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
  HlpIHash,
  HlpIHashInfo,
  HlpHashFactory,
  HlpConverters,
  HashLibTestBase;

type

  TPBKDF2_HMACTestCase = class abstract(THashLibAlgorithmTestCase)

  end;

type

  TTestPBKDF2_HMACSHA1 = class(TPBKDF2_HMACTestCase)

  published
    procedure TestOne;

  end;

type

  TTestPBKDF2_HMACSHA2_256 = class(TPBKDF2_HMACTestCase)

  published
    procedure TestOne;

  end;

implementation

{ TTestPBKDF2_HMACSHA1 }

procedure TTestPBKDF2_HMACSHA1.TestOne;
var
  Password, Salt, Key: TBytes;
  Hash: IHash;
  PBKDF2: IPBKDF2_HMAC;

begin
  FExpectedString := 'BFDE6BE94DF7E11DD409BCE20A0255EC327CB936FFE93643';
  Password := TBytes.Create($70, $61, $73, $73, $77, $6F, $72, $64);
  Salt := TBytes.Create($78, $57, $8E, $5A, $5D, $63, $CB, $06);
  Hash := THashFactory.TCrypto.CreateSHA1();
  PBKDF2 := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC(Hash, Password, Salt, 2048);
  Key := PBKDF2.GetBytes(24);
  PBKDF2.Clear();

  FActualString := TConverters.ConvertBytesToHexString(Key, False);

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

end;

{ TTestPBKDF2_HMACSHA2_256 }

procedure TTestPBKDF2_HMACSHA2_256.TestOne;
var
  Password, Salt, Key: TBytes;
  Hash: IHash;
  PBKDF2: IPBKDF2_HMAC;

begin
  FExpectedString :=
    '0394A2EDE332C9A13EB82E9B24631604C31DF978B4E2F0FBD2C549944F9D79A5';
  Password := TConverters.ConvertStringToBytes('password', TEncoding.UTF8);
  Salt := TConverters.ConvertStringToBytes('salt', TEncoding.UTF8);
  Hash := THashFactory.TCrypto.CreateSHA2_256();
  PBKDF2 := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC(Hash, Password, Salt, 100000);
  Key := PBKDF2.GetBytes(32);
  PBKDF2.Clear();

  FActualString := TConverters.ConvertBytesToHexString(Key, False);

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

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
