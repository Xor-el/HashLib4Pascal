program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
 // fpcunittestrunner,
  HashLibTests,
  BitConverterTests,
  PBKDF2_HMACTests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

