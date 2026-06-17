unit PBKDF_Argon2Tests;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HlpIHashInfo,
  HlpHashLibTypes,
  HlpHashFactory,
  HlpConverters,
  HlpPBKDF_Argon2NotBuildInAdapter,
  HlpArgon2TypeAndVersion,
  HashLibTestBase,
  Argon2Vectors;

type

  TPBKDF_Argon2TestCase = class abstract(THashLibAlgorithmTestCase)

  strict protected
  const
    DEFAULT_OUTPUTLEN = Int32(32);

  end;

type

  TTestPBKDF_Argon2FromInternetDraft = class(TPBKDF_Argon2TestCase)

  strict private
    procedure HashTestFromRow(const ARow: TArgon2VectorRow);
  published
    procedure TestVectorsFromInternetDraft;

  end;

type

  TTestPBKDF_Argon2Others = class(TPBKDF_Argon2TestCase)

  strict private
    procedure HashTestFromRow(const ARow: TArgon2VectorRow);
  published
    procedure TestOthers;

  end;

implementation

function ParseArgon2Type(const AValue: string): string;
begin
  Result := LowerCase(Trim(AValue));
end;

function CreateArgon2Builder(const AType: string): IArgon2ParametersBuilder;
begin
  if AType = 'd' then
    Exit(TArgon2dParametersBuilder.Builder());
  if AType = 'i' then
    Exit(TArgon2iParametersBuilder.Builder());
  if AType = 'id' then
    Exit(TArgon2idParametersBuilder.Builder());
  raise Exception.Create('Unknown Argon2 type: ' + AType);
end;

function ParseArgon2Version(const AValue: string): TArgon2Version;
begin
  if AValue = '13' then
    Exit(TArgon2Version.Version13);
  if AValue = '10' then
    Exit(TArgon2Version.Version10);
  raise Exception.Create('Unknown Argon2 version: ' + AValue);
end;

{ TTestPBKDF_Argon2FromInternetDraft }

procedure TTestPBKDF_Argon2FromInternetDraft.HashTestFromRow(const ARow: TArgon2VectorRow);
var
  LGenerator: IPBKDF_Argon2;
  LActual: String;
  LAdditional, LSecret, LSalt, LPassword: TBytes;
  LArgon2Parameter: IArgon2Parameters;
  LBuilder: IArgon2ParametersBuilder;
begin
  LAdditional := TConverters.ConvertHexStringToBytes(ARow.Additional);
  LSecret := TConverters.ConvertHexStringToBytes(ARow.Secret);
  LSalt := TConverters.ConvertHexStringToBytes(ARow.Salt);
  LPassword := TConverters.ConvertHexStringToBytes(ARow.Password);

  LBuilder := CreateArgon2Builder(ParseArgon2Type(ARow.Argon2Type));
  LBuilder.WithVersion(ParseArgon2Version(ARow.Version)).WithIterations(ARow.Iterations)
    .WithMemoryAsKB(ARow.Memory).WithParallelism(ARow.Parallelism)
    .WithAdditional(LAdditional).WithSecret(LSecret).WithSalt(LSalt);

  LArgon2Parameter := LBuilder.Build();
  LBuilder.Clear();
  LGenerator := TKDF.TPBKDF_Argon2.CreatePBKDF_Argon2(LPassword, LArgon2Parameter);

  LActual := TConverters.ConvertBytesToHexString
    (LGenerator.GetBytes(ARow.OutputLenBytes), False);

  LArgon2Parameter.Clear();
  LGenerator.Clear();

  CheckEquals(ARow.ExpectedHex, LActual, Format('Expected %s but got %s.',
    [ARow.ExpectedHex, LActual]));
end;

procedure TTestPBKDF_Argon2FromInternetDraft.TestVectorsFromInternetDraft;
var
  LRows: THashLibGenericArray<TArgon2VectorRow>;
  LI: Integer;
begin
  LRows := TArgon2Vectors.GetDraftRows;
  for LI := 0 to High(LRows) do
    HashTestFromRow(LRows[LI]);
end;

{ TTestPBKDF_Argon2Others }

procedure TTestPBKDF_Argon2Others.HashTestFromRow(const ARow: TArgon2VectorRow);
var
  LGenerator: IPBKDF_Argon2;
  LSalt, LPassword: TBytes;
  LActual: String;
  LArgon2Parameter: IArgon2Parameters;
  LBuilder: IArgon2ParametersBuilder;
begin
  LSalt := TConverters.ConvertStringToBytes(ARow.Salt, TEncoding.ASCII);
  LPassword := TConverters.ConvertStringToBytes(ARow.Password, TEncoding.ASCII);

  LBuilder := TArgon2iParametersBuilder.Builder();
  LBuilder.WithVersion(ParseArgon2Version(ARow.Version)).WithIterations(ARow.Iterations)
    .WithMemoryPowOfTwo(ARow.Memory).WithParallelism(ARow.Parallelism).WithSalt(LSalt);

  LArgon2Parameter := LBuilder.Build();
  LBuilder.Clear();
  LGenerator := TKDF.TPBKDF_Argon2.CreatePBKDF_Argon2(LPassword, LArgon2Parameter);

  LActual := TConverters.ConvertBytesToHexString
    (LGenerator.GetBytes(ARow.OutputLenBytes), False);

  LArgon2Parameter.Clear();
  LGenerator.Clear();

  CheckEquals(ARow.ExpectedHex, LActual, Format('Expected %s but got %s.',
    [ARow.ExpectedHex, LActual]));
end;

procedure TTestPBKDF_Argon2Others.TestOthers;
var
  LRows: THashLibGenericArray<TArgon2VectorRow>;
  LI: Integer;
begin
  LRows := TArgon2Vectors.GetOthersRows;
  for LI := 0 to High(LRows) do
    HashTestFromRow(LRows[LI]);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPBKDF_Argon2FromInternetDraft);
RegisterTest(TTestPBKDF_Argon2Others);
{$ELSE}
  RegisterTest(TTestPBKDF_Argon2FromInternetDraft.Suite);
RegisterTest(TTestPBKDF_Argon2Others.Suite);
{$ENDIF FPC}

end.
