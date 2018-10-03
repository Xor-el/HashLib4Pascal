program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
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
  PBKDF2_HMACTests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

