program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
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

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

