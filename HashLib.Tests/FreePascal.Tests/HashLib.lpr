program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
 // fpcunittestrunner,
  HashLibTests,
  BitConverterTests,
  PBKDF2_HMACTests, 
  Blake2BTestVectors, 
  Blake2STestVectors;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

