unit HashLibTestResourceLoader;

{ USE_EMBEDDED_TEST_DATA: deployed file assets (StartUpCopy / bundle).
  Enabled on Delphi Android, iOS, macOS, and Linux. Not used by FPC. }

{$IFNDEF FPC}
  {$IF DEFINED(ANDROID) OR DEFINED(IOS) OR DEFINED(MACOS) OR DEFINED(LINUX)}
    {$DEFINE USE_EMBEDDED_TEST_DATA}
  {$ENDIF}
{$ENDIF}

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
  SyncObjs;

type
  IHashLibTestDataPathProvider = interface
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
    function GetDataRoot: string;
    property DataRoot: string read GetDataRoot;
  end;

  IHashLibTestResourceLoader = interface
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TFileAssetDataRootProvider = class(TInterfacedObject, IHashLibTestDataPathProvider)
  private
    FDataRoot: string;
    function GetDataRoot: string;
  public
    constructor Create(const ADataRoot: string);
  end;

  TDiscoveringDataRootProvider = class(TInterfacedObject, IHashLibTestDataPathProvider)
  private
    class function IsValidDataDir(const ADataDir: string): Boolean; static;
    class function Discover: string; static;
    function GetDataRoot: string;
  public
  end;

  TBaseHashLibTestResourceLoader = class abstract(TInterfacedObject,
    IHashLibTestResourceLoader)
  protected
    function DoLoadBytes(const ARelativePath: string): TBytes; virtual; abstract;
    function DoesResourceExist(const ARelativePath: string): Boolean; virtual; abstract;
    function LoadString(const ARelativePath: string;
      AEncoding: TEncoding): string;
  public
    function LoadAsString(const ARelativePath: string): string; overload;
    function LoadAsString(const ARelativePath: string;
      AEncoding: TEncoding): string; overload;
    function LoadAsBytes(const ARelativePath: string): TBytes;
    function ResourceExists(const ARelativePath: string): Boolean;
  end;

  TFileSystemTestResourceLoader = class(TBaseHashLibTestResourceLoader)
  private
    FPathProvider: IHashLibTestDataPathProvider;
    function TryFullPath(const ARelativePath: string; out AFullPath: string): Boolean;
    function FullPath(const ARelativePath: string): string;
    function ReadFileBytes(const AFullPath: string): TBytes;
  protected
    function DoLoadBytes(const ARelativePath: string): TBytes; override;
    function DoesResourceExist(const ARelativePath: string): Boolean; override;
  public
    constructor Create(const APathProvider: IHashLibTestDataPathProvider);
  end;

  THashLibTestResourceLoader = class sealed
  private
    type
      TFacadeState = record
        PathProvider: IHashLibTestDataPathProvider;
        Loader: IHashLibTestResourceLoader;
        DataRoot: string;
      end;
    class var FLock: TCriticalSection;
    class var FPathProvider: IHashLibTestDataPathProvider;
    class var FInstance: IHashLibTestResourceLoader;
    class constructor Create;
    class destructor Destroy;
    class procedure ConfigureDefaults; static;
    class function GetFacadeState: TFacadeState; static;
    class procedure ValidateDataRoot(const ADataRoot: string); static;
    class function GetDataRoot: string; static;
    class function GetPathProvider: IHashLibTestDataPathProvider; static;
    class function GetInstance: IHashLibTestResourceLoader; static;
  public
    const
      HashLibTestDataSentinel = 'Crypto/Blake2/blake2-kat.json';

    class function ResolveRelativePath(const ARoot, ARelativePath: string): string; static;
    class procedure SetPathProvider(const AProvider: IHashLibTestDataPathProvider); static;
    class property DataRoot: string read GetDataRoot;
    class property PathProvider: IHashLibTestDataPathProvider read GetPathProvider;
    class property Instance: IHashLibTestResourceLoader read GetInstance;
  end;

implementation

{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
uses
  System.IOUtils;
{$ENDIF}

const
  TestsProjectName = 'HashLib.Tests';
  TestsDataFolderName = 'Data';
  TestsDataSuffix = TestsProjectName + PathDelim + TestsDataFolderName;
  DataRootNotSet =
    'Test data path provider not configured. Call SetPathProvider before using Instance.';
  SentinelMissingFmt =
    'Test data sentinel not found. Expected %s under data root: %s';
  PathProviderNilMsg = 'Test data path provider is nil';
  DataRootEmptyMsg = 'Test data root is empty';

function CombineRelativeToDataRoot(const ARoot, ARelativePath: string): string;
var
  LRelative: string;
begin
  if ARelativePath = '' then
    Exit(IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ARoot)));
  LRelative := StringReplace(ARelativePath, '\', PathDelim, [rfReplaceAll]);
  LRelative := StringReplace(LRelative, '/', PathDelim, [rfReplaceAll]);
  Result := IncludeTrailingPathDelimiter(ExcludeTrailingPathDelimiter(ARoot)) + LRelative;
end;

procedure RequirePathProvider(const AProvider: IHashLibTestDataPathProvider);
begin
  if AProvider = nil then
    raise Exception.Create(PathProviderNilMsg);
end;

{ TFileAssetDataRootProvider }

constructor TFileAssetDataRootProvider.Create(const ADataRoot: string);
begin
  inherited Create;
  FDataRoot := ExcludeTrailingPathDelimiter(ADataRoot);
end;

function TFileAssetDataRootProvider.GetDataRoot: string;
begin
  Result := FDataRoot;
end;

{ TDiscoveringDataRootProvider }

class function TDiscoveringDataRootProvider.IsValidDataDir(const ADataDir: string): Boolean;
var
  LDataDir, LParentDir: string;
begin
  LDataDir := ExcludeTrailingPathDelimiter(ADataDir);
  if (LDataDir = '') or not DirectoryExists(LDataDir) then
    Exit(False);

  if not SameText(ExtractFileName(LDataDir), TestsDataFolderName) then
    Exit(False);

  LParentDir := ExcludeTrailingPathDelimiter(ExtractFilePath(LDataDir));
  if (LParentDir = '') or not SameText(ExtractFileName(LParentDir), TestsProjectName) then
    Exit(False);

  Result := True;
end;

class function TDiscoveringDataRootProvider.Discover: string;
var
  LDir, LCandidate, LParent: string;
  LI: Integer;
begin
  Result := '';
  LDir := ExcludeTrailingPathDelimiter(GetCurrentDir);
  if LDir = '' then
    Exit;

  for LI := 0 to 12 do
  begin
    if LDir = '' then
      Break;

    LCandidate := IncludeTrailingPathDelimiter(LDir) + TestsDataSuffix;
    if IsValidDataDir(LCandidate) then
      Exit(ExcludeTrailingPathDelimiter(LCandidate));

    LParent := ExtractFilePath(LDir);
    LParent := ExcludeTrailingPathDelimiter(LParent);
    if (LParent = '') or SameText(LParent, LDir) then
      Break;
    LDir := LParent;
  end;
end;

function TDiscoveringDataRootProvider.GetDataRoot: string;
begin
  Result := Discover;
end;

{ TBaseHashLibTestResourceLoader }

function TBaseHashLibTestResourceLoader.LoadString(const ARelativePath: string;
  AEncoding: TEncoding): string;
var
  LBytes: TBytes;
  LBOMLength: Integer;
  LEnc: TEncoding;
begin
  Result := '';
  LBytes := DoLoadBytes(ARelativePath);
  if Length(LBytes) = 0 then
    Exit;
  LEnc := AEncoding;
  if LEnc = nil then
    LEnc := TEncoding.UTF8;
  LBOMLength := TEncoding.GetBufferEncoding(LBytes, LEnc);
  Result := LEnc.GetString(LBytes, LBOMLength, Length(LBytes) - LBOMLength);
end;

function TBaseHashLibTestResourceLoader.LoadAsString(
  const ARelativePath: string): string;
begin
  Result := LoadAsString(ARelativePath, TEncoding.UTF8);
end;

function TBaseHashLibTestResourceLoader.LoadAsString(const ARelativePath: string;
  AEncoding: TEncoding): string;
begin
  Result := LoadString(ARelativePath, AEncoding);
end;

function TBaseHashLibTestResourceLoader.LoadAsBytes(
  const ARelativePath: string): TBytes;
begin
  Result := DoLoadBytes(ARelativePath);
end;

function TBaseHashLibTestResourceLoader.ResourceExists(
  const ARelativePath: string): Boolean;
begin
  Result := DoesResourceExist(ARelativePath);
end;

{ TFileSystemTestResourceLoader }

constructor TFileSystemTestResourceLoader.Create(
  const APathProvider: IHashLibTestDataPathProvider);
begin
  inherited Create;
  RequirePathProvider(APathProvider);
  FPathProvider := APathProvider;
end;

function TFileSystemTestResourceLoader.TryFullPath(const ARelativePath: string;
  out AFullPath: string): Boolean;
var
  LRoot: string;
begin
  LRoot := FPathProvider.DataRoot;
  if LRoot = '' then
    Exit(False);
  AFullPath := CombineRelativeToDataRoot(LRoot, ARelativePath);
  Result := True;
end;

function TFileSystemTestResourceLoader.FullPath(const ARelativePath: string): string;
begin
  if not TryFullPath(ARelativePath, Result) then
    raise Exception.Create(DataRootEmptyMsg);
end;

function TFileSystemTestResourceLoader.ReadFileBytes(const AFullPath: string): TBytes;
var
  LStream: TFileStream;
  LSize: Int64;
begin
  if not FileExists(AFullPath) then
    raise Exception.CreateFmt('Test resource not found: %s', [AFullPath]);
  LStream := TFileStream.Create(AFullPath, fmOpenRead or fmShareDenyWrite);
  try
    LSize := LStream.Size;
    SetLength(Result, LSize);
    if LSize > 0 then
      LStream.ReadBuffer(Result[0], LSize);
  finally
    LStream.Free;
  end;
end;

function TFileSystemTestResourceLoader.DoLoadBytes(
  const ARelativePath: string): TBytes;
begin
  Result := ReadFileBytes(FullPath(ARelativePath));
end;

function TFileSystemTestResourceLoader.DoesResourceExist(
  const ARelativePath: string): Boolean;
var
  LFullPath: string;
begin
  if not TryFullPath(ARelativePath, LFullPath) then
    Exit(False);
  Result := FileExists(LFullPath);
end;

{ THashLibTestResourceLoader }

class constructor THashLibTestResourceLoader.Create;
begin
  FLock := TCriticalSection.Create;
  ConfigureDefaults;
end;

class destructor THashLibTestResourceLoader.Destroy;
begin
  FInstance := nil;
  FPathProvider := nil;
  FreeAndNil(FLock);
end;

class function THashLibTestResourceLoader.ResolveRelativePath(const ARoot,
  ARelativePath: string): string;
begin
  Result := CombineRelativeToDataRoot(ARoot, ARelativePath);
end;

class procedure THashLibTestResourceLoader.ConfigureDefaults;
var
  LPathProvider: IHashLibTestDataPathProvider;
begin
{$IF DEFINED(USE_EMBEDDED_TEST_DATA)}
  LPathProvider := TFileAssetDataRootProvider.Create(
    TPath.Combine(TPath.GetDocumentsPath, TestsProjectName, TestsDataFolderName));
{$ELSE}
  LPathProvider := TDiscoveringDataRootProvider.Create;
{$ENDIF}
  SetPathProvider(LPathProvider);
end;

class function THashLibTestResourceLoader.GetFacadeState: TFacadeState;
begin
  FLock.Enter;
  try
    Result.PathProvider := FPathProvider;
    Result.Loader := FInstance;
    if FPathProvider = nil then
      Result.DataRoot := ''
    else
      Result.DataRoot := FPathProvider.DataRoot;
  finally
    FLock.Leave;
  end;
end;

class procedure THashLibTestResourceLoader.ValidateDataRoot(const ADataRoot: string);
var
  LSentinelPath: string;
begin
  if ADataRoot = '' then
    raise Exception.Create(DataRootNotSet);
  LSentinelPath := CombineRelativeToDataRoot(ADataRoot, HashLibTestDataSentinel);
  if not FileExists(LSentinelPath) then
    raise Exception.CreateFmt(SentinelMissingFmt,
      [HashLibTestDataSentinel, ADataRoot]);
end;

class function THashLibTestResourceLoader.GetDataRoot: string;
begin
  Result := GetFacadeState().DataRoot;
end;

class function THashLibTestResourceLoader.GetPathProvider
  : IHashLibTestDataPathProvider;
begin
  Result := GetFacadeState().PathProvider;
end;

class procedure THashLibTestResourceLoader.SetPathProvider(
  const AProvider: IHashLibTestDataPathProvider);
begin
  RequirePathProvider(AProvider);
  FLock.Enter;
  try
    FPathProvider := AProvider;
    FInstance := TFileSystemTestResourceLoader.Create(AProvider);
  finally
    FLock.Leave;
  end;
end;

class function THashLibTestResourceLoader.GetInstance
  : IHashLibTestResourceLoader;
var
  LRoot: string;
begin
  FLock.Enter;
  try
    if FPathProvider = nil then
      LRoot := ''
    else
      LRoot := FPathProvider.DataRoot;
    ValidateDataRoot(LRoot);
    Result := FInstance;
  finally
    FLock.Leave;
  end;
end;

end.
