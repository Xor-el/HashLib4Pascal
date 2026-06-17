program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cwstring,{$ENDIF}
  consoletestrunner,
  HashLibTestBase,
  HashLibTestResourceLoader,
  CsvVectorParser,
  JsonVectorParser,
  CsvVectorLoaderBase,
  Blake2KatVectors,
  Blake3Vectors,
  Argon2Vectors,
  ScryptVectors,
  Pbkdf2Vectors,
  ChecksumTests,
  NullDigestTests,
  Hash32Tests,
  Hash64Tests,
  Hash128Tests,
  CryptoTests,
  PBKDF2_HMACTests,
  PBKDF_Argon2Tests,
  PBKDF_ScryptTests,
  CRCTests,
  SimdSelectSlotTests;

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
                                
