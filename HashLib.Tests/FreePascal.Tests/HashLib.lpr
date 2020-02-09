program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
  HashLibTestBase,
  TestVectors,
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

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

