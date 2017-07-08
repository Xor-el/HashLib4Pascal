program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  HashLibTests,
  BitConverterTests,
  PBKDF2_HMACTests;

type

  { THashLibConsoleTestRunner }

  THashLibConsoleTestRunner = class(TTestRunner)
  protected
    // override the protected methods of TTestRunner to customize its behavior
end;

var
Application: THashLibConsoleTestRunner;

begin
  Application := THashLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  Application.Run;
  Application.Free;
end.
                                
