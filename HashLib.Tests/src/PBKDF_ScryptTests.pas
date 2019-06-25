unit PBKDF_ScryptTests;

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
  HashLibTestBase;

type

  TPBKDF_ScryptTestCase = class abstract(THashLibAlgorithmTestCase)

  end;

type
  /// <summary>
  /// scrypt test vectors from "Stronger Key Derivation Via Sequential Memory-hard Functions" Appendix B.
  /// (http://www.tarsnap.com/scrypt/scrypt.pdf)
  /// </summary>
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

{ TTestPBKDF_Scrypt }

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
      // pass so we do nothing
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
  DoCheckOk('Minimal values', Nil, Nil, 2, 1, 1, 1);
  DoCheckIllegal('Cost parameter must be > 1', Nil, Nil, 1, 1, 1, 1);
  DoCheckOk('Cost parameter 32768 OK for r = 1', Nil, Nil, 32768, 1, 1, 1);
  DoCheckIllegal('Cost parameter must < 65536 for r = 1', Nil, Nil,
    65536, 1, 1, 1);
  DoCheckIllegal('Block size must be >= 1', Nil, Nil, 2, 0, 2, 1);
  DoCheckIllegal('Parallelisation parameter must be >= 1', Nil, Nil, 2,
    1, 0, 1);
  // disabled test because it's very expensive
  // DoCheckOk('Parallelisation parameter 65535 OK for r = 4', Nil, Nil, 2, 32,
  // 65535, 1);
  DoCheckIllegal('Parallelisation parameter must be < 65535 for r = 4', Nil,
    Nil, 2, 32, 65536, 1);

  DoCheckIllegal('Len parameter must be > 1', Nil, Nil, 2, 1, 1, 0);
end;

procedure TTestPBKDF_Scrypt.TestVectors;
begin

  FActualString := DoTestVector('', '', 16, 1, 1, 64);
  FExpectedString :=
    '77D6576238657B203B19CA42C18A0497F16B4844E3074AE8DFDFFA3FEDE21442FCD0069DED0948F8326A753A0FC81F17E8D3E0FB2E0D3628CF35E20C38D18906';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FActualString := DoTestVector('password', 'NaCl', 1024, 8, 16, 64);
  FExpectedString :=
    'FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FActualString := DoTestVector('pleaseletmein', 'SodiumChloride', 16384,
    8, 1, 64);
  FExpectedString :=
    '7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FActualString := DoTestVector('pleaseletmein', 'SodiumChloride', 1048576,
    8, 1, 64);
  FExpectedString :=
    '2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPBKDF_Scrypt);
{$ELSE}
  RegisterTest(TTestPBKDF_Scrypt.Suite);
{$ENDIF FPC}

end.
