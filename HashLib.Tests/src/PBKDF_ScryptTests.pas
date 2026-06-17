unit PBKDF_ScryptTests;

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HlpIHashInfo,
  HlpHashFactory,
  HlpConverters,
  HlpHashLibTypes,
  HashLibTestBase,
  ScryptVectors;

type

  TPBKDF_ScryptTestCase = class abstract(THashLibAlgorithmTestCase)

  end;

type
  TTestPBKDF_Scrypt = class(TPBKDF_ScryptTestCase)

  private

    function DoTestVector(const APassword, ASalt: String;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32): String;

    procedure DoCheckOk(const AMsg: String; const APassword, ASalt: TBytes;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32);

    procedure DoCheckIllegal(const AMsg: String; const APassword, ASalt: TBytes;
      ACost, ABlockSize, AParallelism, AOutputSize: Int32);

  published
    procedure TestVectors;
    procedure TestParameters;

  end;

implementation

function TTestPBKDF_Scrypt.DoTestVector(const APassword, ASalt: String;
  ACost, ABlockSize, AParallelism, AOutputSize: Int32): String;
var
  PBKDF_Scrypt: IPBKDF_Scrypt;
  APasswordBytes, ASaltBytes, OutputBytes: TBytes;
begin
  APasswordBytes := TConverters.ConvertStringToBytes(APassword,
    TEncoding.ASCII);
  ASaltBytes := TConverters.ConvertStringToBytes(ASalt, TEncoding.ASCII);
  PBKDF_Scrypt := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(APasswordBytes,
    ASaltBytes, ACost, ABlockSize, AParallelism);
  OutputBytes := PBKDF_Scrypt.GetBytes(AOutputSize);
  PBKDF_Scrypt.Clear();
  Result := TConverters.ConvertBytesToHexString(OutputBytes, False);
end;

procedure TTestPBKDF_Scrypt.DoCheckIllegal(const AMsg: String;
  const APassword, ASalt: TBytes; ACost, ABlockSize, AParallelism,
  AOutputSize: Int32);
begin
  try
    TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(APassword, ASalt, ACost, ABlockSize,
      AParallelism).GetBytes(AOutputSize);
    Fail(AMsg);
  except
    on e: EArgumentHashLibException do
    begin
    end;
  end;
end;

procedure TTestPBKDF_Scrypt.DoCheckOk(const AMsg: String;
  const APassword, ASalt: TBytes; ACost, ABlockSize, AParallelism,
  AOutputSize: Int32);
var
  PBKDF_Scrypt: IPBKDF_Scrypt;
begin
  try
    try
      PBKDF_Scrypt := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(APassword, ASalt,
        ACost, ABlockSize, AParallelism);
      PBKDF_Scrypt.GetBytes(AOutputSize);
    except
      on e: EArgumentHashLibException do
      begin
        Fail(AMsg);
      end;
    end;
  finally
    PBKDF_Scrypt.Clear();
  end;
end;

procedure TTestPBKDF_Scrypt.TestParameters;
begin
  DoCheckOk('Minimal values', nil, nil, 2, 1, 1, 1);
  DoCheckIllegal('Cost parameter must be > 1', nil, nil, 1, 1, 1, 1);
  DoCheckOk('Cost parameter 32768 OK for r = 1', nil, nil, 32768, 1, 1, 1);
  DoCheckIllegal('Cost parameter must < 65536 for r = 1', nil, nil,
    65536, 1, 1, 1);
  DoCheckIllegal('Block size must be >= 1', nil, nil, 2, 0, 2, 1);
  DoCheckIllegal('Parallelisation parameter must be >= 1', nil, nil, 2,
    1, 0, 1);
  DoCheckIllegal('Parallelisation parameter must be < 65535 for r = 4', nil,
    nil, 2, 32, 65536, 1);

  DoCheckIllegal('Len parameter must be > 1', nil, nil, 2, 1, 1, 0);
end;

procedure TTestPBKDF_Scrypt.TestVectors;
var
  LRows: THashLibGenericArray<TScryptVectorRow>;
  LI: Integer;
  LRow: TScryptVectorRow;
begin
  LRows := TScryptVectors.GetEnabledRows;
  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    ActualString := DoTestVector(LRow.Password, LRow.Salt, LRow.Cost,
      LRow.BlockSize, LRow.Parallelism, LRow.OutputLenBytes);
    ExpectedString := LRow.ExpectedHex;
    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPBKDF_Scrypt);
{$ELSE}
  RegisterTest(TTestPBKDF_Scrypt.Suite);
{$ENDIF FPC}

end.
