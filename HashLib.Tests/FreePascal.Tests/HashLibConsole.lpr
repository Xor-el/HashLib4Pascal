program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  Blake2BTestVectors,
  Blake2STestVectors,
  HashLibTestBase,
  ChecksumTests,
  NullDigestTests,
  Hash32Tests,
  Hash64Tests,
  Hash128Tests,
  CryptoTests,
  BitConverterTests,
  PBKDF2_HMACTests,
  PBKDF_Argon2Tests,
  PBKDF_ScryptTests,
  CRCTests;

type

  { THashLibConsoleTestRunner }

  THashLibConsoleTestRunner = class(TTestRunner)
  protected
    // override the protected methods of TTestRunner to customize its behaviour
end;

var
Application: THashLibConsoleTestRunner;

begin
  Application := THashLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  Application.Run;
  Application.Free;
end.
                                
