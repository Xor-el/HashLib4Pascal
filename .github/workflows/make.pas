program Make;
{$mode objfpc}{$H+}

uses
  Classes,
  SysUtils,
  StrUtils,
  Zipper,
  fphttpclient,
  RegExpr,
  openssl,
  opensslsockets,
  Process;

const
  Target: string = '.';
  Dependencies: array of string = ();

  // ANSI color codes
  CSI_Reset   = #27'[0m';
  CSI_Red     = #27'[31m';
  CSI_Green   = #27'[32m';
  CSI_Yellow  = #27'[33m';
  CSI_Cyan    = #27'[36m';

  // Package path filter — skip platform-incompatible and template packages
  PackageExcludePattern =
  {$IF DEFINED(MSWINDOWS)}
    '(cocoa|x11|_template)'
  {$ELSEIF DEFINED(DARWIN)}
    '(gdi|x11|_template)'
  {$ELSE}
    '(cocoa|gdi|_template)'
  {$IFEND}
  ;

  OPMBaseUrl = 'https://packages.lazarus-ide.org/';

var
  ErrorCount: Integer = 0;

// ---------------------------------------------------------------------------
// FCL/RTL-only helpers (replace FileUtil usage)
// ---------------------------------------------------------------------------

function ReadFileToString(const AFileName: string): string;
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

function MatchesMaskSimple(const AFileName, AMask: string): Boolean;
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

procedure FindAllFilesRecursive(const ADir, AMask: string; AList: TStrings);
var
  Search: TSearchRec;
  DirPath: string;
  EntryPath: string;
begin
  DirPath := IncludeTrailingPathDelimiter(ExpandFileName(ADir));

  if FindFirst(DirPath + '*', faAnyFile, Search) = 0 then
  try
    repeat
      if (Search.Name = '.') or (Search.Name = '..') then
        Continue;

      EntryPath := DirPath + Search.Name;

      if (Search.Attr and faDirectory) <> 0 then
        FindAllFilesRecursive(EntryPath, AMask, AList)
      else if MatchesMaskSimple(Search.Name, AMask) then
        AList.Add(EntryPath);
    until FindNext(Search) <> 0;
  finally
    FindClose(Search);
  end;
end;

function FindAllFilesList(const ASearchDir, AMask: string): TStringList;
begin
  Result := TStringList.Create;
  FindAllFilesRecursive(ASearchDir, AMask, Result);
end;

// ---------------------------------------------------------------------------
// Logging helpers
// ---------------------------------------------------------------------------

procedure Log(const AColor, AMessage: string);
begin
  WriteLn(stderr, AColor, AMessage, CSI_Reset);
end;

procedure LogInline(const AColor, AMessage: string);
begin
  Write(stderr, AColor, AMessage, CSI_Reset);
end;

// ---------------------------------------------------------------------------
// Git submodules
// ---------------------------------------------------------------------------

procedure UpdateSubmodules;
var
  CommandOutput: ansistring;
begin
  if not FileExists('.gitmodules') then
    Exit;
  if RunCommand('git', ['submodule', 'update', '--init', '--recursive',
    '--force', '--remote'], CommandOutput) then
    Log(CSI_Yellow, Trim(CommandOutput));
end;

// ---------------------------------------------------------------------------
// Package registration
// ---------------------------------------------------------------------------

procedure RegisterPackage(const APath: string);
var
  Filter: TRegExpr;
  CommandOutput: ansistring;
begin
  Filter := TRegExpr.Create(PackageExcludePattern);
  try
    if Filter.Exec(APath) then
      Exit;
    if RunCommand('lazbuild', ['--add-package-link', APath], CommandOutput) then
      Log(CSI_Yellow, 'added ' + APath);
  finally
    Filter.Free;
  end;
end;

// ---------------------------------------------------------------------------
// Extract linked binary path from lazbuild output
// ---------------------------------------------------------------------------

function ExtractLinkedBinary(const ABuildOutput: string): string;
var
  Line: string;
  Parts: TStringArray;
begin
  Result := '';
  for Line in SplitString(ABuildOutput, LineEnding) do
    if ContainsStr(Line, 'Linking') then
    begin
      Parts := SplitString(Line, ' ');
      if Length(Parts) >= 3 then
        Result := Parts[2];
      Exit;
    end;
end;

// ---------------------------------------------------------------------------
// Report build errors from lazbuild output
// ---------------------------------------------------------------------------

procedure ReportBuildErrors(const ABuildOutput: string);
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

// ---------------------------------------------------------------------------
// Build a single .lpi project
// Returns the path to the linked binary on success, empty string on failure
// ---------------------------------------------------------------------------

function BuildProject(const APath: string): string;
var
  BuildOutput: string;
  Success: Boolean;
begin
  Result := '';
  LogInline(CSI_Yellow, 'build from ' + APath);
  try
    Success := RunCommand('lazbuild', ['--build-all', '--recursive',
      '--no-write-project', APath], BuildOutput);
    if Success then
    begin
      Result := ExtractLinkedBinary(BuildOutput);
      if Result <> '' then
        Log(CSI_Green, ' -> ' + Result)
      else
        WriteLn(stderr);
    end
    else
    begin
      WriteLn(stderr);
      Inc(ErrorCount);
      ReportBuildErrors(BuildOutput);
    end;
  except
    on E: Exception do
    begin
      WriteLn(stderr);
      Inc(ErrorCount);
      Log(CSI_Red, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

// ---------------------------------------------------------------------------
// Build and run a test project
// ---------------------------------------------------------------------------

procedure RunTestProject(const APath: string);
var
  BinaryPath, TestOutput: string;
begin
  BinaryPath := BuildProject(APath);
  if BinaryPath = '' then
    Exit;
  try
    if RunCommand(BinaryPath, ['--all', '--format=plain', '--progress'],
      TestOutput) then
      WriteLn(stderr, TestOutput)
    else
    begin
      Inc(ErrorCount);
      WriteLn(stderr, TestOutput);
    end;
  except
    on E: Exception do
    begin
      Inc(ErrorCount);
      Log(CSI_Red, E.ClassName + ': ' + E.Message);
    end;
  end;
end;

// ---------------------------------------------------------------------------
// OPM dependency installation
// ---------------------------------------------------------------------------

function GetOPMPackagesDir: string;
begin
  Result :=
    {$IFDEF MSWINDOWS}
    GetEnvironmentVariable('APPDATA') + '\.lazarus\onlinepackagemanager\packages\'
    {$ELSE}
    GetEnvironmentVariable('HOME') + '/.lazarus/onlinepackagemanager/packages/'
    {$ENDIF}
    ;
end;

procedure DownloadAndExtract(const AUrl, ADestDir: string);
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

function InstallOPMPackage(const APackageName: string): string;
begin
  Result := GetOPMPackagesDir + APackageName;
  if DirectoryExists(Result) then
    Exit;
  DownloadAndExtract(OPMBaseUrl + APackageName + '.zip', Result);
end;

// ---------------------------------------------------------------------------
// Determine whether an .lpi project is a test runner
// ---------------------------------------------------------------------------

function IsTestProject(const ALpiPath: string): Boolean;
var
  LprPath, Content: string;
begin
  Result := False;
  LprPath := ChangeFileExt(ALpiPath, '.lpr');
  if not FileExists(LprPath) then
    Exit;
  Content := ReadFileToString(LprPath);
  Result := ContainsStr(Content, 'consoletestrunner');
end;

// ---------------------------------------------------------------------------
// Register all .lpk packages found under a directory
// ---------------------------------------------------------------------------

procedure RegisterAllPackages(const ASearchDir: string);
var
  List: TStringList;
  Each: string;
begin
  List := FindAllFilesList(ASearchDir, '*.lpk');
  try
    for Each in List do
      RegisterPackage(Each);
  finally
    List.Free;
  end;
end;

// ---------------------------------------------------------------------------
// Build (and optionally test) all .lpi projects found under Target
// ---------------------------------------------------------------------------

procedure BuildAllProjects;
var
  List: TStringList;
  Each: string;
begin
  List := FindAllFilesList(Target, '*.lpi');
  try
    for Each in List do
      if IsTestProject(Each) then
        RunTestProject(Each)
      else
        BuildProject(Each);
  finally
    List.Free;
  end;
end;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

procedure Main;
var
  Each: string;
begin
  UpdateSubmodules;
  InitSSLInterface;

  // Install and register OPM dependencies
  for Each in Dependencies do
    RegisterAllPackages(InstallOPMPackage(Each));

  // Register all local packages
  RegisterAllPackages(GetCurrentDir);

  // Build and test
  BuildAllProjects;

  // Summary
  WriteLn(stderr);
  if ErrorCount > 0 then
    Log(CSI_Red, 'Errors: ' + IntToStr(ErrorCount))
  else
    Log(CSI_Green, 'Errors: 0');

  ExitCode := ErrorCount;
end;

begin
  Main;
end.