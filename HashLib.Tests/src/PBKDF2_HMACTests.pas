unit PBKDF2_HMACTests;

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
  HashLibTestBase;

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
  Password, Salt: TBytes;
begin
  inherited;
  ExpectedString := 'BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643';
  Password := TBytes.Create($70, $61, $73, $73, $77, $6F, $72, $64);
  Salt := TBytes.Create($78, $57, $8E, $5A, $5D, $63, $CB, $06);
  ByteCount := 24;
  PBKDF2_HMACInstance := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC
    (THashFactory.TCrypto.CreateSHA1(), Password, Salt, 2048);
end;

procedure TTestPBKDF2_HMACSHA1.TearDown;
begin
  PBKDF2_HMACInstance := Nil;
  inherited;
end;

{ TTestPBKDF2_HMACSHA2_256 }

procedure TTestPBKDF2_HMACSHA2_256.SetUp;
var
  Password, Salt: TBytes;
begin
  inherited;
  ExpectedString :=
    '0394A2EDE332C9A13EB82E9B24631604C31DF978B4E2F0FBD2C549944F9D79A5';
  Password := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  Salt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  ByteCount := 32;
  PBKDF2_HMACInstance := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC
    (THashFactory.TCrypto.CreateSHA2_256(), Password, Salt, 100000);
end;

procedure TTestPBKDF2_HMACSHA2_256.TearDown;
begin
  PBKDF2_HMACInstance := Nil;
  inherited;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPBKDF2_HMACSHA1);
RegisterTest(TTestPBKDF2_HMACSHA2_256);
{$ELSE}
  RegisterTest(TTestPBKDF2_HMACSHA1.Suite);
RegisterTest(TTestPBKDF2_HMACSHA2_256.Suite);
{$ENDIF FPC}

end.
