program Make;
{$mode objfpc}{$H+}
{$SCOPEDENUMS ON}

uses
  SysUtils, Classes, Generics.Collections, StrUtils, Process, RegExpr,
  Zipper, fphttpclient, openssl, opensslsockets;

type
  TMakeRunner = class;
  TLpkPathProc = procedure(const ALpkPath: string) of object;

  // ---------------------------------------------------------------------------
  // Build backend
  // ---------------------------------------------------------------------------

  // Selected via MAKE_BUILD_BACKEND (defaults to Fpc when unset). Lazbuild
  // drives builds through the IDE tool; Fpc builds packages/projects by
  // invoking the compiler directly (see TPackageGraph).
  TBuildBackend = (
    Lazbuild,
    Fpc
  );

  // Selected via MAKE_PACKAGE_SCOPE (defaults to Required when unset). 'all'
  // compiles every discovered dependency package, so a package that fails to
  // compile on the target is caught even when no built project references it;
  // 'required' compiles only the packages the buildable projects transitively
  // depend on. Honoured by both backends.
  TPackageScope = (
    All,
    Required
  );

  // ---------------------------------------------------------------------------
  // Dependency configuration
  // ---------------------------------------------------------------------------

  TDependencyKind = (OPM, GitHub);

  TDependency = record
    Kind: TDependencyKind;
    Name: string;  // OPM: package name | GitHub: 'owner/repo'
    Ref: string;   // GitHub: branch, tag or commit (ignored for OPM)
  end;

  // ---------------------------------------------------------------------------
  // Lazarus project / package XML
  // ---------------------------------------------------------------------------

  TLazCompilerOptions = record
    CompilerMode: string;
    OptLevel: string;
    UseDwarfSets: Boolean;
    CustomConfigFile: string;
    IncludePaths: string;
    UnitPaths: string;
    UnitOutputDirTemplate: string;
  end;

  // Lightweight extractor for the subset of Lazarus .lpi/.lpk XML we need
  // (block ranges, Value="" attributes, search paths). Not a general XML
  // parser; it relies on the well-formed, tool-generated Lazarus schema.
  TLazXml = class
  public
    class function ReadFile(const AFileName: string): string;
    class function ExtractBlock(const AContent, AOpenTag: string): string;
    class function ExtractAttr(const AContent, ATag: string): string;
    class function ParseCompilerOptions(const AContent: string): TLazCompilerOptions;
    class function ResolveUnitOutputDir(const AOptions: TLazCompilerOptions;
      const AProjDir, ATargetCpu, ATargetOs: string): string;
    class procedure AppendCompilerOptionsToArgv(const AOptions: TLazCompilerOptions;
      const AProjDir, AUnitOutDir, APkgOutDir, ATargetCpu, ATargetOs: string;
      AArgs: TStrings);
    class function ResolvePath(const AValue, AProjDir, AUnitOutDir, APkgOutDir,
      ATargetCpu, ATargetOs: string): string;
    class function CollectFileSourceDirs(const AContent, APkgDir, ATargetCpu,
      ATargetOs: string): TStringList;
    class function ExtractPackageNames(const ABlock: string): TStringList;
    class function ExtractPackageNamesFromContent(const AContent,
      ABlockTag: string): TStringList;
    class function ContentRequiresPackage(const AContent, APackageName,
      ABlockTag: string): Boolean;
    class function ExtractUnitNames(const AContent: string): TStringList;
    class procedure AppendPackageBuildArgs(AArgs: TStrings;
      const AStubFileName, AUnitOutDir: string);
    class procedure AppendProjectBuildArgs(AArgs: TStrings;
      const AMainSource, AUnitOutDir, ATargetBinary: string);
  private
    class function IsAbsolutePath(const S: string): Boolean;
    class function ExpandMacros(const S, AProjDir, AUnitOutDir, APkgOutDir,
      ATargetCpu, ATargetOs: string): string;
    class procedure AppendSearchPathArgs(const APaths, AProjDir, AUnitOutDir,
      APkgOutDir, ATargetCpu, ATargetOs, APrefix: string; AArgs: TStrings);
    class function ArgsHasFuPath(const AArgs: TStrings; const APath: string): Boolean;
    class procedure AppendFuIfMissing(const APath: string; AArgs: TStrings);
  end;

  TProjectFiles = class
  public
    class function FindAll(const ASearchDir, AMask: string): TStringList;
    class procedure RemoveRecursive(const ADir: string);
  private
    class function MatchesMask(const AFileName, AMask: string): Boolean;
    class function IsBackupDir(const ADirName: string): Boolean;
    class function ShouldExcludePath(const AFilePath: string): Boolean;
    class procedure FindRecursive(const ADir, AMask: string; AList: TStrings);
  end;

  TLpiProject = class
  private
    FLpiPath: string;
    FProjDir: string;
    FMainLpr: string;
    FUnitOutDir: string;
    FTargetBinary: string;
    FOptions: TLazCompilerOptions;
    FRequiredPackageNames: TStringList;
  public
    constructor CreateFromFile(const ALpiPath, ATargetCpu, ATargetOs: string);
    destructor Destroy; override;
    function IsValid: Boolean;
    function BuildFpcArgv(const AExtraUnitPaths: TStrings;
      ATargetCpu, ATargetOs: string): TStringList;
    property RequiredPackageNames: TStringList read FRequiredPackageNames;
    property TargetBinary: string read FTargetBinary;
    property UnitOutDir: string read FUnitOutDir;
    property ProjDir: string read FProjDir;
  end;

  TLpkPackage = class
  private
    FLpkPath: string;
    FPkgDir: string;
    FPackageName: string;
    FStubPas: string;
    FUnitOutDir: string;
    FOptions: TLazCompilerOptions;
    FRequiredNames: TStringList;
    FHasLclDependency: Boolean;
    FSourceDirs: TStringList;
  public
    constructor CreateFromFile(const ALpkPath, ATargetCpu, ATargetOs: string);
    destructor Destroy; override;
    function IsValid: Boolean;
    function ResolveUnitOutDir(const ATargetCpu, ATargetOs: string): string;
    property PackageName: string read FPackageName;
    property UnitOutDir: string read FUnitOutDir;
    property PkgDir: string read FPkgDir;
    property Options: TLazCompilerOptions read FOptions;
    property RequiredNames: TStringList read FRequiredNames;
    property SourceDirs: TStringList read FSourceDirs;
    property StubPas: string read FStubPas;
    property HasLclDependency: Boolean read FHasLclDependency;
    class function HasLclDependencyInFile(const ALpkPath: string): Boolean;
  end;

  TDepVisitKind = (BuildOrder, UnitPaths);

  // Dependency graph of discovered .lpk packages. Used by the fpc backend to
  // compute a topological build order and to collect each package's unit
  // output directory (-Fu paths) for dependents. The lazbuild backend does
  // not need this; it registers package links and lets the IDE resolve deps.
  TPackageGraph = class
  private
    FRunner: TMakeRunner;
    FItems: specialize TObjectList<TLpkPackage>;
    FNameToIndex: TStringList;
    function GetPackage(Index: Integer): TLpkPackage;
    function FindIndexByName(const AName: string): Integer;
    function IsBuiltinPackage(const AName: string): Boolean;
    function ResolveDepIndex(const APackageName, AContext: string): Integer;
    procedure VisitPackageDeps(const AIndex: Integer; AVisited: specialize TList<Integer>;
      AKind: TDepVisitKind; AOrder: specialize TList<Integer>; APaths: TStrings);
    procedure CollectBuildOrder(const AIndex: Integer; AOrder: specialize TList<Integer>);
    procedure CollectUnitPaths(const AIndex: Integer; AVisited: specialize TList<Integer>;
      APaths: TStrings);
    function BuildPackageAt(const AIndex: Integer): Boolean;
    function BuildOrder(AOrder: specialize TList<Integer>): Boolean;
  public
    constructor Create(ARunner: TMakeRunner);
    destructor Destroy; override;
    procedure DiscoverUnder(const ARoot: string);
    procedure RegisterLpk(const ALpkPath: string);
    function BuildAll: Boolean;
    function BuildRequired(const ANames: TStrings): Boolean;
    function UnitPathFor(const APackageName: string): string;
    function UnitPathsForRequired(const ANames: TStrings): TStringList;
    function PackageCount: Integer;
    class function ExcludePattern: string;
    class function ShouldExcludeLpkPath(const ALpkPath: string): Boolean;
    class function ShouldSkipLpk(const ALpkPath: string): Boolean;
    // Returns True if the .lpk should be skipped, logging the reason via
    // ARunner when it is skipped solely for an LCL (GUI) dependency.
    class function ShouldSkipLpkLogged(ARunner: TMakeRunner;
      const ALpkPath: string): Boolean;
  end;

  // ---------------------------------------------------------------------------
  // Main orchestrator
  // ---------------------------------------------------------------------------

  TMakeRunner = class
  private
    FBackend: TBuildBackend;
    FBackendResolved: Boolean;
    FPackageScope: TPackageScope;
    FTargetCpu: string;
    FTargetOs: string;
    FErrorCount: Integer;
    FUseColor: Boolean;
    FGraph: TPackageGraph;
    function ParseBackendEnv: TBuildBackend;
    function ParsePackageScopeEnv: TPackageScope;
    procedure InitEnvironment;
    procedure UpdateSubmodules;
    procedure InstallDependencies;
    procedure BuildDiscoveredPackagesFpc;
    function CollectProjectRequiredNames: TStringList;
    procedure BuildAllProjects;
    function BuildProject(const ALpiPath: string): string;
    function BuildProjectWithLazbuild(const APath: string): string;
    function BuildProjectWithFpc(const APath: string): string;
    function ExtractBinaryFromBuildLog(const AOutput, AFallback: string): string;
    function IsGUIProject(const ALpiPath: string): Boolean;
    function IsTestProject(const ALpiPath: string): Boolean;
    procedure RunTestProject(const APath: string);
    procedure RunSampleProject(const APath: string);
    procedure InitSslForDownloads;
    procedure DownloadAndExtract(const AUrl, ADestDir: string);
    function GetDepsBaseDir(const ASubDir: string): string;
    function InstallOPMPackage(const APackageName: string): string;
    function InstallGitHubPackage(const AOwnerRepo, ARef: string): string;
    function ResolveDependency(const ADep: TDependency): string;
    procedure RegisterPackageLazbuild(const APath: string);
    procedure RegisterAllPackagesLazbuild(const ASearchDir: string);
    procedure BuildPackageLazbuild(const APath: string);
    procedure BuildAllPackagesLazbuild(const ASearchDir: string);
    function UsesLazbuild: Boolean;
    function RunCommandEx(const AExecutable: string; const AArgs: TStrings;
      const AWorkingDir: string; AStreamToStderr: Boolean;
      out AOutput: string): Boolean; overload;
    function RunCommandEx(const AExecutable: string;
      const AArgs: array of string; const AWorkingDir: string;
      AStreamToStderr: Boolean; out AOutput: string): Boolean; overload;
    function RepoRoot: string;
    function TargetDirectory: string;
    procedure ForEachLpkInDir(const ARoot: string; ACallback: TLpkPathProc);
    procedure RunBuiltBinary(const ABinaryPath: string;
      const AArgs: array of string; const AFailMessage: string);
    procedure NormalizeFpcTarget(var AValue: string);
    function RunFpcInfoProbeWithRetry(const AInfoFlag: string;
      out AValue: string): Boolean;
    procedure PrepareProjectBuild(Proj: TLpiProject);
  public
    constructor Create;
    destructor Destroy; override;
    function Execute: Integer;
    procedure Log(const AColor, AMessage: string);
    procedure LogInline(const AColor, AMessage: string);
    procedure ReportBuildErrors(const ABuildOutput: string);
    procedure ReportSummary;
    procedure IncError;
    property TargetCpu: string read FTargetCpu;
    property TargetOs: string read FTargetOs;
  end;

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

const
  Target: string = 'HashLib.Tests';

  CSI_Reset  = #27'[0m';
  CSI_Red    = #27'[31m';
  CSI_Green  = #27'[32m';
  CSI_Yellow = #27'[33m';
  CSI_Cyan   = #27'[36m';

  OPMBaseUrl = 'https://packages.lazarus-ide.org/';
  GitHubArchiveBaseUrl = 'https://github.com/';

  Dependencies: array of TDependency = (
    // Examples:
    // (Kind: TDependencyKind.OPM;    Name: 'SimpleBaseLib';                     Ref: ''),
    // (Kind: TDependencyKind.GitHub; Name: 'Xor-el/HashLib4Pascal'; Ref: 'master'),
  );

// ---------------------------------------------------------------------------
// Dependency helpers
// ---------------------------------------------------------------------------

function OPM(const AName: string): TDependency;
begin
  Result.Kind := TDependencyKind.OPM;
  Result.Name := AName;
  Result.Ref := '';
end;

function GitHub(const AOwnerRepo, ARef: string): TDependency;
begin
  Result.Kind := TDependencyKind.GitHub;
  Result.Name := AOwnerRepo;
  Result.Ref := ARef;
end;

// ---------------------------------------------------------------------------
// TLazXml
// ---------------------------------------------------------------------------

{ TLazXml }

class function TLazXml.IsAbsolutePath(const S: string): Boolean;
begin
  {$IFDEF MSWINDOWS}
  Result := (Length(S) >= 2) and (
    ((UpCase(S[1]) >= 'A') and (UpCase(S[1]) <= 'Z') and (S[2] = ':')) or
    (S[1] = '\'));
  {$ELSE}
  Result := (Length(S) > 0) and (S[1] = '/');
  {$ENDIF}
end;

class function TLazXml.ReadFile(const AFileName: string): string;
var
  Stream: TFileStream;
  Size: Int64;
begin
  Result := '';
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyNone);
  try
    Size := Stream.Size;
    if Size <= 0 then
      Exit;
    SetLength(Result, Size);
    Stream.Position := 0;
    Stream.ReadBuffer(Pointer(Result)^, Size);
  finally
    Stream.Free;
  end;
end;

class function TLazXml.ExtractBlock(const AContent, AOpenTag: string): string;
var
  P, Q, TagLen: Integer;
  CloseTag: string;
  NextCh: Char;
begin
  Result := '';
  TagLen := Length(AOpenTag) + 1;
  P := Pos('<' + AOpenTag, AContent);
  while P > 0 do
  begin
    if P + TagLen > Length(AContent) then
      Break;
    NextCh := AContent[P + TagLen];
    if (NextCh = '>') or (NextCh = ' ') or (NextCh = #9) or (NextCh = '/') then
      Break;
    P := PosEx('<' + AOpenTag, AContent, P + 1);
  end;
  if P = 0 then
    Exit;
  CloseTag := '</' + AOpenTag + '>';
  Q := PosEx(CloseTag, AContent, P);
  if Q = 0 then
    Result := Copy(AContent, P, MaxInt)
  else
    Result := Copy(AContent, P, Q - P + Length(CloseTag));
end;

class function TLazXml.ExtractAttr(const AContent, ATag: string): string;
var
  Needle: string;
  P, Q: Integer;
begin
  Result := '';
  Needle := '<' + ATag + ' Value="';
  P := Pos(Needle, AContent);
  if P = 0 then
    Exit;
  Inc(P, Length(Needle));
  Q := PosEx('"', AContent, P);
  if Q = 0 then
    Exit;
  Result := Copy(AContent, P, Q - P);
end;

class function TLazXml.ExpandMacros(const S, AProjDir, AUnitOutDir, APkgOutDir,
  ATargetCpu, ATargetOs: string): string;
begin
  Result := S;
  Result := StringReplace(Result, '$(ProjOutDir)', AUnitOutDir, [rfReplaceAll]);
  Result := StringReplace(Result, '$(PkgOutDir)', APkgOutDir, [rfReplaceAll]);
  Result := StringReplace(Result, '$(TargetCPU)', ATargetCpu, [rfReplaceAll]);
  Result := StringReplace(Result, '$(TargetOS)', ATargetOs, [rfReplaceAll]);
  Result := StringReplace(Result, '\', PathDelim, [rfReplaceAll]);
  if Result = '' then
    Exit;
  if not IsAbsolutePath(Result) then
    Result := ExpandFileName(IncludeTrailingPathDelimiter(AProjDir) + Result);
end;

class function TLazXml.ResolvePath(const AValue, AProjDir, AUnitOutDir,
  APkgOutDir, ATargetCpu, ATargetOs: string): string;
begin
  Result := ExpandMacros(Trim(AValue), AProjDir, AUnitOutDir, APkgOutDir,
    ATargetCpu, ATargetOs);
end;

class procedure TLazXml.AppendSearchPathArgs(const APaths, AProjDir,
  AUnitOutDir, APkgOutDir, ATargetCpu, ATargetOs, APrefix: string;
  AArgs: TStrings);
var
  Parts: TStringArray;
  I: Integer;
  PathItem: string;
begin
  Parts := SplitString(APaths, ';');
  for I := 0 to High(Parts) do
  begin
    PathItem := Trim(Parts[I]);
    if PathItem = '' then
      Continue;
    AArgs.Add(APrefix + ResolvePath(PathItem, AProjDir, AUnitOutDir, APkgOutDir,
      ATargetCpu, ATargetOs));
  end;
end;

class function TLazXml.ArgsHasFuPath(const AArgs: TStrings; const APath: string): Boolean;
var
  I: Integer;
  Norm, ArgPath: string;
begin
  Result := False;
  if APath = '' then
    Exit;
  Norm := LowerCase(ExpandFileName(ExcludeTrailingPathDelimiter(APath)));
  for I := 0 to AArgs.Count - 1 do
  begin
    if not StartsText('-Fu', AArgs[I]) then
      Continue;
    ArgPath := Copy(AArgs[I], 4, MaxInt);
    if SameText(Norm, LowerCase(ExpandFileName(ExcludeTrailingPathDelimiter(ArgPath)))) then
      Exit(True);
  end;
end;

class procedure TLazXml.AppendFuIfMissing(const APath: string; AArgs: TStrings);
begin
  if (APath <> '') and not ArgsHasFuPath(AArgs, APath) then
    AArgs.Add('-Fu' + IncludeTrailingPathDelimiter(APath));
end;

class function TLazXml.CollectFileSourceDirs(const AContent, APkgDir, ATargetCpu,
  ATargetOs: string): TStringList;
var
  Block, FilePath, DirPath, Ext: string;
  Filter: TRegExpr;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.Duplicates := dupIgnore;
  Block := ExtractBlock(AContent, 'Files');
  if Block = '' then
    Exit;
  Filter := TRegExpr.Create('<Filename\s+Value="([^"]+)"\s*/>');
  try
    if Filter.Exec(Block) then
    repeat
      FilePath := Filter.Match[1];
      Ext := LowerCase(ExtractFileExt(FilePath));
      if (Ext = '.pas') or (Ext = '.pp') or (Ext = '.p') then
      begin
        DirPath := ResolvePath(ExtractFilePath(FilePath), APkgDir, '', '',
          ATargetCpu, ATargetOs);
        if DirPath <> '' then
          Result.Add(ExcludeTrailingPathDelimiter(DirPath));
      end;
    until not Filter.ExecNext;
  finally
    Filter.Free;
  end;
end;

class function TLazXml.ParseCompilerOptions(const AContent: string): TLazCompilerOptions;
var
  Block: string;
begin
  Result.CompilerMode := 'delphi';
  Result.OptLevel := '2';
  Result.UseDwarfSets := Pos('dsDwarf3', AContent) > 0;
  Result.CustomConfigFile := '';
  Result.IncludePaths := '';
  Result.UnitPaths := '';
  Result.UnitOutputDirTemplate := 'lib\$(TargetCPU)-$(TargetOS)';

  Block := ExtractBlock(AContent, 'CompilerOptions');
  if Block = '' then
    Exit;

  if ExtractAttr(Block, 'OptimizationLevel') <> '' then
    Result.OptLevel := ExtractAttr(Block, 'OptimizationLevel');
  Result.IncludePaths := ExtractAttr(Block, 'IncludeFiles');
  Result.UnitPaths := ExtractAttr(Block, 'OtherUnitFiles');
  if ExtractAttr(Block, 'UnitOutputDirectory') <> '' then
    Result.UnitOutputDirTemplate := ExtractAttr(Block, 'UnitOutputDirectory');

  if Pos('<CustomConfigFile Value="True"', Block) > 0 then
    Result.CustomConfigFile := ExtractAttr(Block, 'ConfigFilePath');

  if ExtractAttr(Block, 'SyntaxMode') <> '' then
    Result.CompilerMode := LowerCase(ExtractAttr(Block, 'SyntaxMode'))
  else if ExtractAttr(Block, 'CompilerMode') <> '' then
    Result.CompilerMode := LowerCase(ExtractAttr(Block, 'CompilerMode'));
  if Result.CompilerMode = '' then
    Result.CompilerMode := 'delphi';
end;

class function TLazXml.ResolveUnitOutputDir(const AOptions: TLazCompilerOptions;
  const AProjDir, ATargetCpu, ATargetOs: string): string;
begin
  Result := ResolvePath(AOptions.UnitOutputDirTemplate, AProjDir, '', '',
    ATargetCpu, ATargetOs);
  ForceDirectories(Result);
end;

class procedure TLazXml.AppendCompilerOptionsToArgv(const AOptions: TLazCompilerOptions;
  const AProjDir, AUnitOutDir, APkgOutDir, ATargetCpu, ATargetOs: string;
  AArgs: TStrings);
var
  ConfigPath: string;
begin
  if AOptions.CompilerMode <> '' then
    AArgs.Add('-M' + AOptions.CompilerMode)
  else
    AArgs.Add('-Mdelphi');
  AArgs.Add('-O' + AOptions.OptLevel);
  if AOptions.UseDwarfSets then
    AArgs.Add('-godwarfsets');
  AppendSearchPathArgs(AOptions.IncludePaths, AProjDir, AUnitOutDir, APkgOutDir,
    ATargetCpu, ATargetOs, '-Fi', AArgs);
  AppendSearchPathArgs(AOptions.UnitPaths, AProjDir, AUnitOutDir, APkgOutDir,
    ATargetCpu, ATargetOs, '-Fu', AArgs);
  if AOptions.CustomConfigFile <> '' then
  begin
    ConfigPath := ResolvePath(AOptions.CustomConfigFile, AProjDir, AUnitOutDir,
      APkgOutDir, ATargetCpu, ATargetOs);
    if FileExists(ConfigPath) then
      AArgs.Add('@' + ConfigPath);
  end;
end;

class function TLazXml.ExtractPackageNames(const ABlock: string): TStringList;
var
  Filter: TRegExpr;
begin
  Result := TStringList.Create;
  if ABlock = '' then
    Exit;
  Filter := TRegExpr.Create('<PackageName\s+Value="([^"]+)"\s*/>');
  try
    if Filter.Exec(ABlock) then
      repeat
        Result.Add(Filter.Match[1]);
      until not Filter.ExecNext;
  finally
    Filter.Free;
  end;
end;

class function TLazXml.ExtractPackageNamesFromContent(const AContent,
  ABlockTag: string): TStringList;
begin
  Result := ExtractPackageNames(ExtractBlock(AContent, ABlockTag));
end;

class function TLazXml.ContentRequiresPackage(const AContent, APackageName,
  ABlockTag: string): Boolean;
var
  Names: TStringList;
  I: Integer;
begin
  Result := False;
  Names := ExtractPackageNamesFromContent(AContent, ABlockTag);
  try
    for I := 0 to Names.Count - 1 do
      if SameText(Names[I], APackageName) then
        Exit(True);
  finally
    Names.Free;
  end;
end;

class function TLazXml.ExtractUnitNames(const AContent: string): TStringList;
var
  Filter: TRegExpr;
begin
  Result := TStringList.Create;
  Filter := TRegExpr.Create('<UnitName\s+Value="([^"]+)"\s*/>');
  try
    if Filter.Exec(AContent) then
      repeat
        Result.Add(Filter.Match[1]);
      until not Filter.ExecNext;
  finally
    Filter.Free;
  end;
end;

class procedure TLazXml.AppendPackageBuildArgs(AArgs: TStrings;
  const AStubFileName, AUnitOutDir: string);
begin
  AArgs.Add('-FU' + IncludeTrailingPathDelimiter(AUnitOutDir));
  AArgs.Add('-B');
  AArgs.Add(AStubFileName);
end;

class procedure TLazXml.AppendProjectBuildArgs(AArgs: TStrings;
  const AMainSource, AUnitOutDir, ATargetBinary: string);
begin
  AArgs.Add('-FU' + AUnitOutDir);
  AArgs.Add('-FE' + ExtractFilePath(ATargetBinary));
  AArgs.Add('-B');
  AArgs.Add('-o' + ATargetBinary);
  AArgs.Add(AMainSource);
end;

// ---------------------------------------------------------------------------
// TProjectFiles
// ---------------------------------------------------------------------------

{ TProjectFiles }

class function TProjectFiles.MatchesMask(const AFileName, AMask: string): Boolean;
var
  LExt: string;
begin
  LExt := LowerCase(ExtractFileExt(AFileName));
  if AMask = '*.lpk' then
    Exit(LExt = '.lpk');
  if AMask = '*.lpi' then
    Exit(LExt = '.lpi');
  Result := False;
end;

class function TProjectFiles.IsBackupDir(const ADirName: string): Boolean;
begin
  Result := SameText(ADirName, 'backup');
end;

class function TProjectFiles.ShouldExcludePath(const AFilePath: string): Boolean;
var
  Norm: string;
begin
  Norm := LowerCase(ExpandFileName(AFilePath));
  Result := Pos(PathDelim + 'backup' + PathDelim, Norm) > 0;
end;

class procedure TProjectFiles.FindRecursive(const ADir, AMask: string;
  AList: TStrings);
var
  Search: TSearchRec;
  DirPath, EntryPath: string;
begin
  DirPath := IncludeTrailingPathDelimiter(ExpandFileName(ADir));
  if FindFirst(DirPath + '*', faAnyFile, Search) = 0 then
  try
    repeat
      if (Search.Name = '.') or (Search.Name = '..') then
        Continue;
      if (Search.Attr and faDirectory) <> 0 then
      begin
        if IsBackupDir(Search.Name) then
          Continue;
        FindRecursive(DirPath + Search.Name, AMask, AList);
        Continue;
      end;
      EntryPath := DirPath + Search.Name;
      if MatchesMask(Search.Name, AMask) and not ShouldExcludePath(EntryPath) then
        AList.Add(EntryPath);
    until FindNext(Search) <> 0;
  finally
    FindClose(Search);
  end;
end;

class function TProjectFiles.FindAll(const ASearchDir, AMask: string): TStringList;
begin
  Result := TStringList.Create;
  FindRecursive(ASearchDir, AMask, Result);
end;

class procedure TProjectFiles.RemoveRecursive(const ADir: string);
var
  Search: TSearchRec;
  NormDir, DirPath, EntryPath: string;
begin
  if (ADir = '') or not DirectoryExists(ADir) then
    Exit;
  NormDir := ExpandFileName(ADir);
  DirPath := IncludeTrailingPathDelimiter(NormDir);
  if FindFirst(DirPath + '*', faAnyFile, Search) = 0 then
  try
    repeat
      if (Search.Name = '.') or (Search.Name = '..') then
        Continue;
      EntryPath := DirPath + Search.Name;
      if (Search.Attr and faDirectory) <> 0 then
        RemoveRecursive(EntryPath)
      else
        DeleteFile(EntryPath);
    until FindNext(Search) <> 0;
  finally
    FindClose(Search);
  end;
  RemoveDir(NormDir);
end;

// ---------------------------------------------------------------------------
// TLpiProject
// ---------------------------------------------------------------------------

{ TLpiProject }

constructor TLpiProject.CreateFromFile(const ALpiPath, ATargetCpu,
  ATargetOs: string);
var
  Content, Block, Name: string;
  PkgNames: TStringList;
begin
  inherited Create;
  FRequiredPackageNames := TStringList.Create;
  FLpiPath := ALpiPath;
  FProjDir := ExtractFilePath(ALpiPath);

  if not FileExists(ALpiPath) then
    Exit;

  Content := TLazXml.ReadFile(ALpiPath);
  FOptions := TLazXml.ParseCompilerOptions(Content);
  FUnitOutDir := TLazXml.ResolveUnitOutputDir(FOptions, FProjDir, ATargetCpu, ATargetOs);

  Block := TLazXml.ExtractBlock(Content, 'Unit0');
  if Block = '' then
    Block := Content;
  Name := TLazXml.ExtractAttr(Block, 'Filename');
  if Name <> '' then
    FMainLpr := TLazXml.ResolvePath(Name, FProjDir, '', '', ATargetCpu, ATargetOs);

  Block := TLazXml.ExtractBlock(Content, 'Target');
  if Block <> '' then
  begin
    Name := TLazXml.ExtractAttr(Block, 'Filename');
    if Name <> '' then
      FTargetBinary := TLazXml.ResolvePath(Name, FProjDir, FUnitOutDir, '',
        ATargetCpu, ATargetOs);
  end;
  if FTargetBinary = '' then
    FTargetBinary := ChangeFileExt(FMainLpr, '');

  PkgNames := TLazXml.ExtractPackageNamesFromContent(Content, 'RequiredPackages');
  try
    FRequiredPackageNames.Assign(PkgNames);
  finally
    PkgNames.Free;
  end;
end;

destructor TLpiProject.Destroy;
begin
  FRequiredPackageNames.Free;
  inherited Destroy;
end;

function TLpiProject.IsValid: Boolean;
begin
  Result := (FLpiPath <> '') and FileExists(FLpiPath) and (FMainLpr <> '') and
    FileExists(FMainLpr);
end;

function TLpiProject.BuildFpcArgv(const AExtraUnitPaths: TStrings;
  ATargetCpu, ATargetOs: string): TStringList;
var
  I: Integer;
begin
  Result := TStringList.Create;
  TLazXml.AppendCompilerOptionsToArgv(FOptions, FProjDir, FUnitOutDir, FUnitOutDir,
    ATargetCpu, ATargetOs, Result);
  if Assigned(AExtraUnitPaths) then
    for I := 0 to AExtraUnitPaths.Count - 1 do
      TLazXml.AppendFuIfMissing(AExtraUnitPaths[I], Result);
  TLazXml.AppendProjectBuildArgs(Result, FMainLpr, FUnitOutDir, FTargetBinary);
end;

// ---------------------------------------------------------------------------
// TLpkPackage
// ---------------------------------------------------------------------------

{ TLpkPackage }

constructor TLpkPackage.CreateFromFile(const ALpkPath, ATargetCpu,
  ATargetOs: string);
var
  Content, Block: string;
  Units: string;
  UnitNames, PkgNames: TStringList;
  I: Integer;
  SL: TStringList;
begin
  inherited Create;
  FRequiredNames := TStringList.Create;
  FLpkPath := ALpkPath;
  FPkgDir := ExtractFilePath(ALpkPath);

  if not FileExists(ALpkPath) then
  begin
    FSourceDirs := TStringList.Create;
    Exit;
  end;

  Content := TLazXml.ReadFile(ALpkPath);
  FSourceDirs := TLazXml.CollectFileSourceDirs(Content, FPkgDir, ATargetCpu, ATargetOs);
  Block := TLazXml.ExtractBlock(Content, 'Package');
  if Block <> '' then
    FPackageName := TLazXml.ExtractAttr(Block, 'Name')
  else
    FPackageName := TLazXml.ExtractAttr(Content, 'Name');
  FOptions := TLazXml.ParseCompilerOptions(Content);
  FUnitOutDir := TLazXml.ResolveUnitOutputDir(FOptions, FPkgDir, ATargetCpu, ATargetOs);

  PkgNames := TLazXml.ExtractPackageNamesFromContent(Content, 'RequiredPkgs');
  try
    for I := 0 to PkgNames.Count - 1 do
    begin
      if SameText(PkgNames[I], 'LCL') then
        FHasLclDependency := True;
      FRequiredNames.Add(PkgNames[I]);
    end;
  finally
    PkgNames.Free;
  end;

  // fpc compiles a unit, not an .lpk. When the package has no real unit named
  // after it, synthesize a stub unit that `uses` every listed unit so a single
  // `fpc <stub>` builds the whole package. (lazbuild reads the .lpk directly.)
  FStubPas := IncludeTrailingPathDelimiter(FPkgDir) + FPackageName + '.pas';
  if not FileExists(FStubPas) then
  begin
    Units := '';
    UnitNames := TLazXml.ExtractUnitNames(Content);
    try
      for I := 0 to UnitNames.Count - 1 do
      begin
        if Units <> '' then
          Units := Units + ', ';
        Units := Units + UnitNames[I];
      end;
    finally
      UnitNames.Free;
    end;

    SL := TStringList.Create;
    try
      SL.Add('{ Auto-generated by Make for package compile }');
      SL.Add('');
      SL.Add('unit ' + FPackageName + ';');
      SL.Add('');
      SL.Add('{$warn 5023 off : no warning about unused units}');
      SL.Add('interface');
      SL.Add('');
      SL.Add('uses');
      SL.Add('  ' + Units + ';');
      SL.Add('');
      SL.Add('implementation');
      SL.Add('');
      SL.Add('end.');
      SL.SaveToFile(FStubPas);
    finally
      SL.Free;
    end;
  end;
end;

destructor TLpkPackage.Destroy;
begin
  FSourceDirs.Free;
  FRequiredNames.Free;
  inherited Destroy;
end;

function TLpkPackage.ResolveUnitOutDir(const ATargetCpu, ATargetOs: string): string;
begin
  FUnitOutDir := TLazXml.ResolveUnitOutputDir(FOptions, FPkgDir, ATargetCpu, ATargetOs);
  Result := FUnitOutDir;
end;

function TLpkPackage.IsValid: Boolean;
begin
  Result := (FLpkPath <> '') and FileExists(FLpkPath) and (FPackageName <> '') and
    (FStubPas <> '') and FileExists(FStubPas);
end;

class function TLpkPackage.HasLclDependencyInFile(const ALpkPath: string): Boolean;
var
  Content: string;
begin
  Result := False;
  if not FileExists(ALpkPath) then
    Exit;
  Content := TLazXml.ReadFile(ALpkPath);
  Result := TLazXml.ContentRequiresPackage(Content, 'LCL', 'RequiredPkgs');
end;

// ---------------------------------------------------------------------------
// TPackageGraph
// ---------------------------------------------------------------------------

{ TPackageGraph }

class function TPackageGraph.ExcludePattern: string;
begin
  {$IF DEFINED(MSWINDOWS)}
  Result := '(cocoa|x11|_template)';
  {$ELSEIF DEFINED(DARWIN)}
  Result := '(gdi|x11|_template)';
  {$ELSE}
  Result := '(cocoa|gdi|_template)';
  {$IFEND}
end;

class function TPackageGraph.ShouldExcludeLpkPath(const ALpkPath: string): Boolean;
var
  Filter: TRegExpr;
begin
  Filter := TRegExpr.Create(ExcludePattern);
  try
    Result := Filter.Exec(ALpkPath);
  finally
    Filter.Free;
  end;
end;

class function TPackageGraph.ShouldSkipLpk(const ALpkPath: string): Boolean;
begin
  Result := ShouldExcludeLpkPath(ALpkPath) or
    TLpkPackage.HasLclDependencyInFile(ALpkPath);
end;

class function TPackageGraph.ShouldSkipLpkLogged(ARunner: TMakeRunner;
  const ALpkPath: string): Boolean;
begin
  Result := ShouldSkipLpk(ALpkPath);
  // Platform/template packages are excluded silently; only the LCL skip is
  // worth a note since it is the reason a console-only CI drops a package.
  if Result and not ShouldExcludeLpkPath(ALpkPath) then
    ARunner.Log(CSI_Yellow, 'skip LCL-dependent package ' + ALpkPath);
end;

constructor TPackageGraph.Create(ARunner: TMakeRunner);
begin
  inherited Create;
  FRunner := ARunner;
  FItems := specialize TObjectList<TLpkPackage>.Create(True);
  FNameToIndex := TStringList.Create;
  FNameToIndex.Sorted := True;
  FNameToIndex.Duplicates := dupError;
end;

destructor TPackageGraph.Destroy;
begin
  FNameToIndex.Free;
  FItems.Free;
  inherited Destroy;
end;

function TPackageGraph.GetPackage(Index: Integer): TLpkPackage;
begin
  Result := FItems[Index];
end;

function TPackageGraph.PackageCount: Integer;
begin
  Result := FItems.Count;
end;

function TPackageGraph.IsBuiltinPackage(const AName: string): Boolean;
begin
  Result := SameText(AName, 'FCL') or SameText(AName, 'RTL') or
    SameText(AName, 'FCLBase');
end;

function TPackageGraph.FindIndexByName(const AName: string): Integer;
var
  Idx: Integer;
begin
  Result := -1;
  Idx := FNameToIndex.IndexOf(AName);
  if Idx >= 0 then
    Result := Integer(PtrInt(FNameToIndex.Objects[Idx]));
end;

procedure TPackageGraph.RegisterLpk(const ALpkPath: string);
var
  Pkg: TLpkPackage;
begin
  if ShouldSkipLpkLogged(FRunner, ALpkPath) then
    Exit;

  Pkg := TLpkPackage.CreateFromFile(ALpkPath, FRunner.TargetCpu, FRunner.TargetOs);
  if not Pkg.IsValid then
  begin
    FRunner.Log(CSI_Red, 'failed to load package: ' + ALpkPath);
    FRunner.IncError;
    Pkg.Free;
    Exit;
  end;

  if FindIndexByName(Pkg.PackageName) >= 0 then
  begin
    Pkg.Free;
    Exit;
  end;

  FNameToIndex.AddObject(Pkg.PackageName, TObject(PtrInt(FItems.Count)));
  FItems.Add(Pkg);
end;

procedure TPackageGraph.DiscoverUnder(const ARoot: string);
var
  List: TStringList;
  Each: string;
begin
  if not DirectoryExists(ARoot) then
    Exit;
  List := TProjectFiles.FindAll(ARoot, '*.lpk');
  try
    for Each in List do
      RegisterLpk(Each);
  finally
    List.Free;
  end;
end;

function TPackageGraph.ResolveDepIndex(const APackageName,
  AContext: string): Integer;
begin
  Result := FindIndexByName(APackageName);
  if Result < 0 then
  begin
    FRunner.Log(CSI_Red, Format('%s requires unknown package "%s"',
      [AContext, APackageName]));
    FRunner.IncError;
  end;
end;

procedure TPackageGraph.VisitPackageDeps(const AIndex: Integer;
  AVisited: specialize TList<Integer>; AKind: TDepVisitKind; AOrder: specialize TList<Integer>;
  APaths: TStrings);
var
  Pkg: TLpkPackage;
  Path: string;
  I, DepIdx: Integer;
  DepName: string;
begin
  if (AIndex < 0) or (AIndex >= FItems.Count) then
    Exit;

  case AKind of
    TDepVisitKind.BuildOrder:
      if AOrder.IndexOf(AIndex) >= 0 then
        Exit;
    TDepVisitKind.UnitPaths:
      begin
        if AVisited.IndexOf(AIndex) >= 0 then
          Exit;
        AVisited.Add(AIndex);
      end;
  end;

  Pkg := GetPackage(AIndex);
  for I := 0 to Pkg.RequiredNames.Count - 1 do
  begin
    DepName := Pkg.RequiredNames[I];
    if IsBuiltinPackage(DepName) then
      Continue;
    DepIdx := ResolveDepIndex(DepName, 'package "' + Pkg.PackageName + '"');
    if DepIdx < 0 then
      Continue;
    VisitPackageDeps(DepIdx, AVisited, AKind, AOrder, APaths);
  end;

  case AKind of
    TDepVisitKind.BuildOrder:
      AOrder.Add(AIndex);
    TDepVisitKind.UnitPaths:
      begin
        Path := Pkg.ResolveUnitOutDir(FRunner.TargetCpu, FRunner.TargetOs);
        if (Path <> '') and (APaths.IndexOf(Path) < 0) then
          APaths.Add(Path);
      end;
  end;
end;

procedure TPackageGraph.CollectBuildOrder(const AIndex: Integer;
  AOrder: specialize TList<Integer>);
begin
  VisitPackageDeps(AIndex, nil, TDepVisitKind.BuildOrder, AOrder, nil);
end;

procedure TPackageGraph.CollectUnitPaths(const AIndex: Integer;
  AVisited: specialize TList<Integer>; APaths: TStrings);
begin
  VisitPackageDeps(AIndex, AVisited, TDepVisitKind.UnitPaths, nil, APaths);
end;

// Compile a single discovered package by graph index. Wipes and recreates its
// unit output dir, then invokes fpc with the package's options plus the unit
// paths of its dependencies. Returns False (and records an error) on failure.
function TPackageGraph.BuildPackageAt(const AIndex: Integer): Boolean;
var
  Pkg: TLpkPackage;
  Args: TStringList;
  BuildOutput, OutDir, DepPath: string;
  J: Integer;
begin
  Result := True;
  Pkg := GetPackage(AIndex);
  OutDir := Pkg.ResolveUnitOutDir(FRunner.TargetCpu, FRunner.TargetOs);

  FRunner.LogInline(CSI_Yellow, 'build package ' + Pkg.PackageName);
  TProjectFiles.RemoveRecursive(OutDir);
  ForceDirectories(OutDir);

  Args := TStringList.Create;
  try
    TLazXml.AppendCompilerOptionsToArgv(Pkg.Options, Pkg.PkgDir, OutDir,
      OutDir, FRunner.TargetCpu, FRunner.TargetOs, Args);
    for J := 0 to Pkg.SourceDirs.Count - 1 do
      TLazXml.AppendFuIfMissing(Pkg.SourceDirs[J], Args);
    TLazXml.AppendFuIfMissing(Pkg.PkgDir, Args);
    for J := 0 to Pkg.RequiredNames.Count - 1 do
    begin
      if IsBuiltinPackage(Pkg.RequiredNames[J]) then
        Continue;
      DepPath := UnitPathFor(Pkg.RequiredNames[J]);
      TLazXml.AppendFuIfMissing(DepPath, Args);
    end;
    TLazXml.AppendPackageBuildArgs(Args, ExtractFileName(Pkg.StubPas), OutDir);

    if FRunner.RunCommandEx('fpc', Args, Pkg.PkgDir, True, BuildOutput) then
      FRunner.Log(CSI_Green, ' -> ' + OutDir)
    else
    begin
      FRunner.IncError;
      FRunner.ReportBuildErrors(BuildOutput);
      Result := False;
    end;
  finally
    Args.Free;
  end;
end;

// Compile the packages in AOrder (already topologically sorted, dependencies
// first). Builds every entry even when one fails, accumulating errors, and
// returns False if any package failed.
function TPackageGraph.BuildOrder(AOrder: specialize TList<Integer>): Boolean;
var
  I: Integer;
begin
  Result := True;
  for I := 0 to AOrder.Count - 1 do
    if not BuildPackageAt(AOrder[I]) then
      Result := False;
end;

// MAKE_PACKAGE_SCOPE=all: compile every discovered package, in build order.
function TPackageGraph.BuildAll: Boolean;
var
  Order: specialize TList<Integer>;
  I: Integer;
begin
  if FItems.Count = 0 then
    Exit(True);

  Order := specialize TList<Integer>.Create;
  try
    for I := 0 to FItems.Count - 1 do
      CollectBuildOrder(I, Order);
    Result := BuildOrder(Order);
  finally
    Order.Free;
  end;
end;

// MAKE_PACKAGE_SCOPE=required: compile only the dependency closure of ANames,
// in build order. Unknown names are ignored here; the project build reports
// them via UnitPathsForRequired.
function TPackageGraph.BuildRequired(const ANames: TStrings): Boolean;
var
  Order: specialize TList<Integer>;
  I, Idx: Integer;
begin
  if (ANames = nil) or (ANames.Count = 0) or (FItems.Count = 0) then
    Exit(True);

  Order := specialize TList<Integer>.Create;
  try
    for I := 0 to ANames.Count - 1 do
    begin
      if IsBuiltinPackage(ANames[I]) then
        Continue;
      Idx := FindIndexByName(ANames[I]);
      if Idx >= 0 then
        CollectBuildOrder(Idx, Order);
    end;
    Result := BuildOrder(Order);
  finally
    Order.Free;
  end;
end;

function TPackageGraph.UnitPathFor(const APackageName: string): string;
var
  Idx: Integer;
begin
  Result := '';
  Idx := FindIndexByName(APackageName);
  if (Idx < 0) or (Idx >= FItems.Count) then
    Exit;
  Result := GetPackage(Idx).ResolveUnitOutDir(FRunner.TargetCpu, FRunner.TargetOs);
end;

function TPackageGraph.UnitPathsForRequired(const ANames: TStrings): TStringList;
var
  I, Idx: Integer;
  Visited: specialize TList<Integer>;
begin
  Result := TStringList.Create;
  if not Assigned(ANames) then
    Exit;

  Visited := specialize TList<Integer>.Create;
  try
    for I := 0 to ANames.Count - 1 do
    begin
      if IsBuiltinPackage(ANames[I]) then
        Continue;
      Idx := FindIndexByName(ANames[I]);
      if Idx < 0 then
      begin
        FRunner.Log(CSI_Red, Format('project requires unknown package "%s"',
          [ANames[I]]));
        FRunner.IncError;
        Continue;
      end;
      CollectUnitPaths(Idx, Visited, Result);
    end;
  finally
    Visited.Free;
  end;
end;

// ---------------------------------------------------------------------------
// TMakeRunner
// ---------------------------------------------------------------------------

{ TMakeRunner }

constructor TMakeRunner.Create;
begin
  inherited Create;
  FBackend := TBuildBackend.Fpc;
  FBackendResolved := False;
  FPackageScope := TPackageScope.Required;
  FErrorCount := 0;
  // Honor the NO_COLOR convention (https://no-color.org): any value disables
  // ANSI colors. GitHub Actions renders ANSI in its log viewer, so default on.
  FUseColor := GetEnvironmentVariable('NO_COLOR') = '';
  FGraph := TPackageGraph.Create(Self);
end;

destructor TMakeRunner.Destroy;
begin
  FGraph.Free;
  inherited Destroy;
end;

procedure TMakeRunner.Log(const AColor, AMessage: string);
begin
  if FUseColor then
    WriteLn(stderr, AColor, AMessage, CSI_Reset)
  else
    WriteLn(stderr, AMessage);
end;

procedure TMakeRunner.LogInline(const AColor, AMessage: string);
begin
  if FUseColor then
    Write(stderr, AColor, AMessage, CSI_Reset)
  else
    Write(stderr, AMessage);
end;

procedure TMakeRunner.IncError;
begin
  Inc(FErrorCount);
end;

procedure TMakeRunner.ReportBuildErrors(const ABuildOutput: string);
var
  Line: string;
  ErrorFilter: TRegExpr;
begin
  ErrorFilter := TRegExpr.Create('(Fatal|Error):');
  try
    for Line in SplitString(ABuildOutput, LineEnding) do
      if ErrorFilter.Exec(Line) then
        Log(CSI_Red, Line);
  finally
    ErrorFilter.Free;
  end;
end;

procedure TMakeRunner.ReportSummary;
begin
  WriteLn(stderr);
  if FErrorCount > 0 then
    Log(CSI_Red, 'Errors: ' + IntToStr(FErrorCount))
  else
    Log(CSI_Green, 'Errors: 0');
end;

function TMakeRunner.ParseBackendEnv: TBuildBackend;
var
  Env: string;
begin
  Env := LowerCase(Trim(GetEnvironmentVariable('MAKE_BUILD_BACKEND')));
  if Env = '' then
    Exit(TBuildBackend.Fpc);
  if Env = 'lazbuild' then
    Exit(TBuildBackend.Lazbuild);
  if Env = 'fpc' then
    Exit(TBuildBackend.Fpc);
  raise Exception.CreateFmt('unknown MAKE_BUILD_BACKEND: "%s"', [Env]);
end;

function TMakeRunner.ParsePackageScopeEnv: TPackageScope;
var
  Env: string;
begin
  Env := LowerCase(Trim(GetEnvironmentVariable('MAKE_PACKAGE_SCOPE')));
  if Env = '' then
    Exit(TPackageScope.Required);
  if Env = 'all' then
    Exit(TPackageScope.All);
  if Env = 'required' then
    Exit(TPackageScope.Required);
  raise Exception.CreateFmt('unknown MAKE_PACKAGE_SCOPE: "%s"', [Env]);
end;

function TMakeRunner.UsesLazbuild: Boolean;
begin
  if not FBackendResolved then
    InitEnvironment;
  Result := FBackend = TBuildBackend.Lazbuild;
end;

function TMakeRunner.RunCommandEx(const AExecutable: string; const AArgs: TStrings;
  const AWorkingDir: string; AStreamToStderr: Boolean;
  out AOutput: string): Boolean; overload;
var
  Proc: TProcess;
  OutStream: TStringStream;
  Count: LongInt;
  Buffer: array[0..8191] of Byte;
  Chunk: string;

  procedure DrainOutput;
  begin
    while Proc.Output.NumBytesAvailable > 0 do
    begin
      Count := Proc.Output.Read(Buffer, SizeOf(Buffer));
      if Count <= 0 then
        Break;
      OutStream.WriteBuffer(Buffer, Count);
      if AStreamToStderr then
      begin
        SetLength(Chunk, Count);
        Move(Buffer[0], Chunk[1], Count);
        Write(stderr, Chunk);
      end;
    end;
  end;

begin
  AOutput := '';
  Proc := TProcess.Create(nil);
  OutStream := TStringStream.Create('');
  try
    Proc.Executable := AExecutable;
    Proc.Parameters.Assign(AArgs);
    if AWorkingDir <> '' then
      Proc.CurrentDirectory := AWorkingDir;
    Proc.Options := [poUsePipes, poStderrToOutPut];
    Proc.ShowWindow := swoHide;
    Proc.Execute;
    repeat
      DrainOutput;
      if Proc.Running then
        Sleep(10);
    until not Proc.Running;
    DrainOutput;
    Proc.WaitOnExit;
    AOutput := OutStream.DataString;
    Result := Proc.ExitStatus = 0;
  finally
    OutStream.Free;
    Proc.Free;
  end;
end;

function TMakeRunner.RunCommandEx(const AExecutable: string;
  const AArgs: array of string; const AWorkingDir: string;
  AStreamToStderr: Boolean; out AOutput: string): Boolean; overload;
var
  SL: TStringList;
  I: Integer;
begin
  SL := TStringList.Create;
  try
    for I := 0 to High(AArgs) do
      SL.Add(AArgs[I]);
    Result := RunCommandEx(AExecutable, SL, AWorkingDir, AStreamToStderr, AOutput);
  finally
    SL.Free;
  end;
end;

procedure TMakeRunner.NormalizeFpcTarget(var AValue: string);
begin
  AValue := StringReplace(AValue, #13, '', [rfReplaceAll]);
  AValue := StringReplace(AValue, #10, '', [rfReplaceAll]);
  AValue := Trim(AValue);
end;

function TMakeRunner.RunFpcInfoProbeWithRetry(const AInfoFlag: string;
  out AValue: string): Boolean;
var
  Attempt, MaxAttempts, DelayMs: Integer;
  Env, Output: string;
begin
  MaxAttempts := 3;
  DelayMs := 2000;
  Env := Trim(GetEnvironmentVariable('CI_FPC_PROBE_ATTEMPTS'));
  if Env <> '' then
    MaxAttempts := StrToIntDef(Env, MaxAttempts);
  Env := Trim(GetEnvironmentVariable('CI_FPC_PROBE_DELAY_MS'));
  if Env <> '' then
    DelayMs := StrToIntDef(Env, DelayMs);

  AValue := '';
  for Attempt := 1 to MaxAttempts do
  begin
    if RunCommandEx('fpc', [AInfoFlag], '', False, Output) then
    begin
      NormalizeFpcTarget(Output);
      if Output <> '' then
      begin
        AValue := Output;
        if Attempt > 1 then
          Log(CSI_Yellow, Format('fpc %s succeeded on attempt %d/%d',
            [AInfoFlag, Attempt, MaxAttempts]));
        Exit(True);
      end;
    end;
    if Attempt < MaxAttempts then
    begin
      Log(CSI_Yellow, Format('fpc %s empty or failed (attempt %d/%d), retrying...',
        [AInfoFlag, Attempt, MaxAttempts]));
      Sleep(DelayMs);
    end;
  end;
  Result := False;
end;

function TMakeRunner.RepoRoot: string;
var
  Seeds: array[0..1] of string;
  I: Integer;
  Candidate, Parent, DemoDir: string;
begin
  Seeds[0] := ExpandFileName(ExtractFilePath(ParamStr(0)));
  Seeds[1] := ExpandFileName(GetCurrentDir);
  for I := 0 to High(Seeds) do
  begin
    Candidate := Seeds[I];
    while Candidate <> '' do
    begin
      DemoDir := IncludeTrailingPathDelimiter(ConcatPaths([Candidate, Target]));
      if DirectoryExists(DemoDir) then
        Exit(ExcludeTrailingPathDelimiter(Candidate));
      Parent := ExpandFileName(IncludeTrailingPathDelimiter(Candidate) + '..');
      if SameText(Parent, Candidate) then
        Break;
      Candidate := Parent;
    end;
  end;
  Result := GetCurrentDir;
end;

function TMakeRunner.TargetDirectory: string;
begin
  Result := IncludeTrailingPathDelimiter(ConcatPaths([RepoRoot, Target]));
end;

procedure TMakeRunner.ForEachLpkInDir(const ARoot: string;
  ACallback: TLpkPathProc);
var
  List: TStringList;
  Each: string;
begin
  if not Assigned(ACallback) or not DirectoryExists(ARoot) then
    Exit;
  List := TProjectFiles.FindAll(ARoot, '*.lpk');
  try
    for Each in List do
      ACallback(Each);
  finally
    List.Free;
  end;
end;

procedure TMakeRunner.RunBuiltBinary(const ABinaryPath: string;
  const AArgs: array of string; const AFailMessage: string);
var
  Output: string;
begin
  if RunCommandEx(ABinaryPath, AArgs, '', False, Output) then
    WriteLn(Output)
  else
  begin
    IncError;
    if AFailMessage <> '' then
      Log(CSI_Red, AFailMessage);
    WriteLn(stderr, Output);
  end;
end;

procedure TMakeRunner.InitEnvironment;
var
  Output: string;
begin
  if FBackendResolved then
    Exit;

  if not RunFpcInfoProbeWithRetry('-iTP', FTargetCpu) then
    raise Exception.Create('fpc -iTP returned empty TargetCPU');
  if not RunFpcInfoProbeWithRetry('-iTO', FTargetOs) then
    raise Exception.Create('fpc -iTO returned empty TargetOS');

  FBackend := ParseBackendEnv;
  if (FBackend = TBuildBackend.Lazbuild)
    and not RunCommandEx('lazbuild', ['--version'], '', False, Output) then
    raise Exception.Create('MAKE_BUILD_BACKEND=lazbuild but lazbuild not found');

  FBackendResolved := True;
  case FBackend of
    TBuildBackend.Lazbuild:
      Log(CSI_Yellow, 'build backend: lazbuild');
    TBuildBackend.Fpc:
      Log(CSI_Yellow, 'build backend: fpc');
  end;

  FPackageScope := ParsePackageScopeEnv;
  case FPackageScope of
    TPackageScope.All:
      Log(CSI_Yellow, 'package scope: all');
    TPackageScope.Required:
      Log(CSI_Yellow, 'package scope: required');
  end;
end;

procedure TMakeRunner.UpdateSubmodules;
var
  CommandOutput: string;
begin
  if not FileExists('.gitmodules') then
    Exit;
  if RunCommandEx('git', ['submodule', 'update', '--init', '--recursive',
    '--force', '--remote'], '', False, CommandOutput) then
    Log(CSI_Yellow, Trim(CommandOutput));
end;

// TODO(FPC 3.2.4): drop this Windows override. FPC 3.2.2's openssl unit
// hardcodes the OpenSSL 1.1 DLL names (libssl-1_1*.dll / libeay32.dll), but
// modern Windows CI runners ship only OpenSSL 3.x. Point FPC at the 3.x DLLs
// so HTTPS downloads work. FPC 3.2.4+ already knows the OpenSSL 3 names, so
// this whole procedure can become a plain InitSSLInterface call then.
procedure TMakeRunner.InitSslForDownloads;
begin
  {$IFDEF MSWINDOWS}
    {$IFDEF WIN64}
  DLLSSLName := 'libssl-3-x64.dll';
  DLLUtilName := 'libcrypto-3-x64.dll';
    {$ELSE}
  DLLSSLName := 'libssl-3.dll';
  DLLUtilName := 'libcrypto-3.dll';
    {$ENDIF}
  {$ENDIF}
  InitSSLInterface;
end;

procedure TMakeRunner.DownloadAndExtract(const AUrl, ADestDir: string);
var
  TempFile: string;
  Stream: TFileStream;
  Client: TFPHttpClient;
  Unzipper: TUnZipper;
begin
  TempFile := GetTempFileName;
  Stream := TFileStream.Create(TempFile, fmCreate or fmOpenWrite);
  try
    Client := TFPHttpClient.Create(nil);
    try
      Client.AddHeader('User-Agent', 'Mozilla/5.0 (compatible; fpweb)');
      Client.AllowRedirect := True;
      Client.Get(AUrl, Stream);
      Log(CSI_Cyan, 'downloaded ' + AUrl);
    finally
      Client.Free;
    end;
  finally
    Stream.Free;
  end;

  CreateDir(ADestDir);
  Unzipper := TUnZipper.Create;
  try
    Unzipper.FileName := TempFile;
    Unzipper.OutputPath := ADestDir;
    Unzipper.Examine;
    Unzipper.UnZipAllFiles;
    Log(CSI_Cyan, 'extracted to ' + ADestDir);
  finally
    Unzipper.Free;
    DeleteFile(TempFile);
  end;
end;

function TMakeRunner.GetDepsBaseDir(const ASubDir: string): string;
var
  BaseDir: string;
begin
  {$IFDEF MSWINDOWS}
  BaseDir := GetEnvironmentVariable('APPDATA');
  {$ELSE}
  BaseDir := GetEnvironmentVariable('HOME');
  {$ENDIF}
  Result := IncludeTrailingPathDelimiter(ConcatPaths([BaseDir, '.lazarus', ASubDir]));
end;

function TMakeRunner.InstallOPMPackage(const APackageName: string): string;
begin
  Result := GetDepsBaseDir(ConcatPaths(['onlinepackagemanager', 'packages'])) +
    APackageName;
  if DirectoryExists(Result) then
    Exit;
  DownloadAndExtract(OPMBaseUrl + APackageName + '.zip', Result);
end;

function TMakeRunner.InstallGitHubPackage(const AOwnerRepo, ARef: string): string;
var
  SafeName, EffectiveRef: string;
begin
  SafeName := StringReplace(AOwnerRepo, '/', '--', [rfReplaceAll]);
  EffectiveRef := ARef;
  if EffectiveRef = '' then
    EffectiveRef := 'main';

  Result := GetDepsBaseDir('github-packages') + SafeName;
  if DirectoryExists(Result) then
    Exit;

  DownloadAndExtract(
    GitHubArchiveBaseUrl + AOwnerRepo + '/archive/' + EffectiveRef + '.zip',
    Result);
end;

function TMakeRunner.ResolveDependency(const ADep: TDependency): string;
begin
  case ADep.Kind of
    TDependencyKind.OPM:
      Result := InstallOPMPackage(ADep.Name);
    TDependencyKind.GitHub:
      Result := InstallGitHubPackage(ADep.Name, ADep.Ref);
  else
    raise Exception.CreateFmt('Unknown dependency kind for "%s"', [ADep.Name]);
  end;
end;

procedure TMakeRunner.RegisterPackageLazbuild(const APath: string);
var
  CommandOutput: string;
begin
  if TPackageGraph.ShouldSkipLpkLogged(Self, APath) then
    Exit;
  if RunCommandEx('lazbuild', ['--add-package-link', APath], '', False,
    CommandOutput) then
    Log(CSI_Yellow, 'added ' + APath);
end;

procedure TMakeRunner.RegisterAllPackagesLazbuild(const ASearchDir: string);
begin
  ForEachLpkInDir(ASearchDir, @RegisterPackageLazbuild);
end;

procedure TMakeRunner.BuildPackageLazbuild(const APath: string);
var
  BuildOutput: string;
begin
  // Parity with the fpc backend's TPackageGraph.BuildAll: --add-package-link only
  // registers a package; it never compiles it, so a dependency that fails to
  // compile on this target goes unnoticed unless a built project happens to use
  // it. Compile every registered package explicitly to catch that.
  // Uses the non-logging skip so LCL packages are not re-announced (registration
  // already logged them).
  if TPackageGraph.ShouldSkipLpk(APath) then
    Exit;
  LogInline(CSI_Yellow, 'build package ' + APath);
  if RunCommandEx('lazbuild', ['--build-all', '--recursive', APath], '', True,
    BuildOutput) then
    Log(CSI_Green, ' -> ok')
  else
  begin
    WriteLn(stderr, BuildOutput);
    IncError;
    ReportBuildErrors(BuildOutput);
  end;
end;

procedure TMakeRunner.BuildAllPackagesLazbuild(const ASearchDir: string);
begin
  ForEachLpkInDir(ASearchDir, @BuildPackageLazbuild);
end;

procedure TMakeRunner.InstallDependencies;
var
  Roots: TStringList;
  I: Integer;
begin
  // Search roots = each resolved dependency directory plus the repo itself.
  Roots := TStringList.Create;
  try
    if Length(Dependencies) > 0 then
    begin
      InitSslForDownloads;
      for I := 0 to High(Dependencies) do
        Roots.Add(ResolveDependency(Dependencies[I]));
    end;
    Roots.Add(RepoRoot);

    if UsesLazbuild then
    begin
      // Register every package first so cross-package dependencies resolve.
      for I := 0 to Roots.Count - 1 do
        RegisterAllPackagesLazbuild(Roots[I]);
      // Scope=all: also compile each registered package so a package that fails
      // to build on this target is caught even when no project uses it (parity
      // with the fpc backend — see BuildPackageLazbuild). Scope=required:
      // lazbuild compiles the packages a project needs while building it.
      if FPackageScope = TPackageScope.All then
        for I := 0 to Roots.Count - 1 do
          BuildAllPackagesLazbuild(Roots[I]);
    end
    else
    begin
      for I := 0 to Roots.Count - 1 do
        FGraph.DiscoverUnder(Roots[I]);
      if FGraph.PackageCount > 0 then
        BuildDiscoveredPackagesFpc;
    end;
  finally
    Roots.Free;
  end;
end;

// fpc backend: compile discovered packages according to MAKE_PACKAGE_SCOPE.
procedure TMakeRunner.BuildDiscoveredPackagesFpc;
var
  Names: TStringList;
begin
  if FPackageScope = TPackageScope.All then
    FGraph.BuildAll
  else
  begin
    Names := CollectProjectRequiredNames;
    try
      FGraph.BuildRequired(Names);
    finally
      Names.Free;
    end;
  end;
end;

// Union of RequiredPackages across the buildable (non-GUI) projects under the
// target directory. Drives the fpc backend's 'required' scope so it compiles
// only the dependency closure those projects need.
function TMakeRunner.CollectProjectRequiredNames: TStringList;
var
  List: TStringList;
  Each: string;
  Proj: TLpiProject;
  I: Integer;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.Duplicates := dupIgnore;
  List := TProjectFiles.FindAll(TargetDirectory, '*.lpi');
  try
    for Each in List do
    begin
      if IsGUIProject(Each) then
        Continue;
      Proj := TLpiProject.CreateFromFile(Each, FTargetCpu, FTargetOs);
      try
        if Proj.IsValid then
          for I := 0 to Proj.RequiredPackageNames.Count - 1 do
            Result.Add(Proj.RequiredPackageNames[I]);
      finally
        Proj.Free;
      end;
    end;
  finally
    List.Free;
  end;
end;

function TMakeRunner.ExtractBinaryFromBuildLog(const AOutput,
  AFallback: string): string;
var
  Line: string;
  Parts: TStringArray;
  I: Integer;
begin
  Result := AFallback;
  for Line in SplitString(AOutput, LineEnding) do
    if ContainsStr(Line, 'Linking') then
    begin
      Parts := SplitString(Line, ' ');
      for I := High(Parts) downto 0 do
      begin
        if Trim(Parts[I]) <> '' then
        begin
          Result := Trim(Parts[I]);
          Break;
        end;
      end;
      Exit;
    end;
end;

procedure TMakeRunner.PrepareProjectBuild(Proj: TLpiProject);
begin
  TProjectFiles.RemoveRecursive(Proj.UnitOutDir);
  if FileExists(Proj.TargetBinary) then
    DeleteFile(Proj.TargetBinary);
  ForceDirectories(ExtractFilePath(Proj.TargetBinary));
  ForceDirectories(Proj.UnitOutDir);
end;

function TMakeRunner.BuildProjectWithLazbuild(const APath: string): string;
var
  Proj: TLpiProject;
  BuildOutput: string;
begin
  Result := '';
  Proj := TLpiProject.CreateFromFile(APath, FTargetCpu, FTargetOs);
  try
    if not Proj.IsValid then
    begin
      Log(CSI_Red, 'invalid project: ' + APath);
      IncError;
      Exit;
    end;
    PrepareProjectBuild(Proj);
    if RunCommandEx('lazbuild', ['--build-all', '--recursive',
      '--no-write-project', APath], '', True, BuildOutput) then
    begin
      Result := ExtractBinaryFromBuildLog(BuildOutput, Proj.TargetBinary);
      if Result <> '' then
        Log(CSI_Green, ' -> ' + Result)
      else
        WriteLn(stderr, BuildOutput);
    end
    else
    begin
      WriteLn(stderr, BuildOutput);
      IncError;
      ReportBuildErrors(BuildOutput);
    end;
  finally
    Proj.Free;
  end;
end;

function TMakeRunner.BuildProjectWithFpc(const APath: string): string;
var
  Proj: TLpiProject;
  ExtraPaths, Args: TStringList;
  BuildOutput: string;
begin
  Result := '';
  Proj := TLpiProject.CreateFromFile(APath, FTargetCpu, FTargetOs);
  try
    if not Proj.IsValid then
    begin
      Log(CSI_Red, 'invalid project: ' + APath);
      IncError;
      Exit;
    end;

    PrepareProjectBuild(Proj);
    ExtraPaths := FGraph.UnitPathsForRequired(Proj.RequiredPackageNames);
    try
      Args := Proj.BuildFpcArgv(ExtraPaths, FTargetCpu, FTargetOs);
      try
        if RunCommandEx('fpc', Args, Proj.ProjDir, True, BuildOutput) then
        begin
          Result := ExtractBinaryFromBuildLog(BuildOutput, Proj.TargetBinary);
          if FileExists(Result) then
            Log(CSI_Green, ' -> ' + Result)
          else
          begin
            Log(CSI_Red, 'fpc reported success but binary missing: ' + Proj.TargetBinary);
            IncError;
          end;
        end
        else
        begin
          IncError;
          ReportBuildErrors(BuildOutput);
        end;
      finally
        Args.Free;
      end;
    finally
      ExtraPaths.Free;
    end;
  finally
    Proj.Free;
  end;
end;

function TMakeRunner.BuildProject(const ALpiPath: string): string;
begin
  Result := '';
  LogInline(CSI_Yellow, 'build from ' + ALpiPath);
  try
    if UsesLazbuild then
      Result := BuildProjectWithLazbuild(ALpiPath)
    else
      Result := BuildProjectWithFpc(ALpiPath);
  except
    on E: Exception do
    begin
      WriteLn(stderr);
      IncError;
      Log(CSI_Red, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

function TMakeRunner.IsGUIProject(const ALpiPath: string): Boolean;
var
  Content: string;
begin
  Result := False;
  if not FileExists(ALpiPath) then
    Exit;
  Content := TLazXml.ReadFile(ALpiPath);
  Result := TLazXml.ContentRequiresPackage(Content, 'LCL', 'RequiredPackages');
end;

function TMakeRunner.IsTestProject(const ALpiPath: string): Boolean;
var
  LprPath, Content: string;
begin
  Result := False;
  LprPath := ChangeFileExt(ALpiPath, '.lpr');
  if not FileExists(LprPath) then
    Exit;
  Content := TLazXml.ReadFile(LprPath);
  Result := Pos('consoletestrunner', Content) > 0;
end;

procedure TMakeRunner.RunTestProject(const APath: string);
var
  BinaryPath: string;
begin
  BinaryPath := BuildProject(APath);
  if BinaryPath = '' then
    Exit;
  try
    RunBuiltBinary(BinaryPath, ['--all', '--format=plain', '--progress'], '');
  except
    on E: Exception do
    begin
      IncError;
      Log(CSI_Red, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

procedure TMakeRunner.RunSampleProject(const APath: string);
var
  BinaryPath: string;
begin
  BinaryPath := BuildProject(APath);
  if BinaryPath = '' then
    Exit;
  try
    Log(CSI_Yellow, 'run ' + BinaryPath);
    RunBuiltBinary(BinaryPath, [], 'sample execution failed: ' + BinaryPath);
  except
    on E: Exception do
    begin
      IncError;
      Log(CSI_Red, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

procedure TMakeRunner.BuildAllProjects;
var
  List: TStringList;
  Each: string;
begin
  List := TProjectFiles.FindAll(TargetDirectory, '*.lpi');
  try
    for Each in List do
    begin
      if IsGUIProject(Each) then
      begin
        Log(CSI_Yellow, 'skip GUI project ' + Each);
        Continue;
      end;

      if IsTestProject(Each) then
        RunTestProject(Each)
      else
        RunSampleProject(Each);
    end;
  finally
    List.Free;
  end;
end;

function TMakeRunner.Execute: Integer;
begin
  InitEnvironment;
  Log(CSI_Cyan, 'using target directory: ' + TargetDirectory);
  UpdateSubmodules;
  InstallDependencies;
  BuildAllProjects;
  ReportSummary;
  Result := FErrorCount;
end;

// ---------------------------------------------------------------------------
// Program entry
// ---------------------------------------------------------------------------

var
  Runner: TMakeRunner;
begin
  Runner := TMakeRunner.Create;
  try
    ExitCode := Runner.Execute;
  finally
    Runner.Free;
  end;
end.
