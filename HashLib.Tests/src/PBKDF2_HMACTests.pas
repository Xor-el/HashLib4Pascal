unit PBKDF2_HMACTests;

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
  HlpHashFactory,
  HlpConverters,
  HashLibTestBase,
  Pbkdf2Vectors;

type
  TTestPBKDF2_HMACSHA1 = class(TPBKDF2_HMACTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestPBKDF2_HMACSHA2_256 = class(TPBKDF2_HMACTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

{ TTestPBKDF2_HMACSHA1 }

procedure TTestPBKDF2_HMACSHA1.SetUp;
var
  LRow: TPbkdf2VectorRow;
  LPassword, LSalt: TBytes;
begin
  inherited;
  LRow := TPbkdf2Vectors.GetRowByAlgorithm('SHA1');
  ExpectedString := LRow.ExpectedHex;
  LPassword := TConverters.ConvertHexStringToBytes(LRow.PasswordHex);
  LSalt := TConverters.ConvertHexStringToBytes(LRow.SaltHex);
  ByteCount := LRow.OutputLenBytes;
  PBKDF2_HMACInstance := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC
    (THashFactory.TCrypto.CreateSHA1(), LPassword, LSalt, LRow.Iterations);
end;

procedure TTestPBKDF2_HMACSHA1.TearDown;
begin
  PBKDF2_HMACInstance := nil;
  inherited;
end;

{ TTestPBKDF2_HMACSHA2_256 }

procedure TTestPBKDF2_HMACSHA2_256.SetUp;
var
  LRow: TPbkdf2VectorRow;
  LPassword, LSalt: TBytes;
begin
  inherited;
  LRow := TPbkdf2Vectors.GetRowByAlgorithm('SHA256');
  ExpectedString := LRow.ExpectedHex;
  LPassword := TConverters.ConvertHexStringToBytes(LRow.PasswordHex);
  LSalt := TConverters.ConvertHexStringToBytes(LRow.SaltHex);
  ByteCount := LRow.OutputLenBytes;
  PBKDF2_HMACInstance := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC
    (THashFactory.TCrypto.CreateSHA2_256(), LPassword, LSalt, LRow.Iterations);
end;

procedure TTestPBKDF2_HMACSHA2_256.TearDown;
begin
  PBKDF2_HMACInstance := nil;
  inherited;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPBKDF2_HMACSHA1);
  RegisterTest(TTestPBKDF2_HMACSHA2_256);
{$ELSE}
  RegisterTest(TTestPBKDF2_HMACSHA1.Suite);
  RegisterTest(TTestPBKDF2_HMACSHA2_256.Suite);
{$ENDIF FPC}

end.
