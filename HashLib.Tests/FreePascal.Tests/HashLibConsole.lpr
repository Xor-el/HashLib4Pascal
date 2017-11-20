program HashLib.Tests;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  HashLibTests,
  BitConverterTests,
  PBKDF2_HMACTests,
  Blake2BTestVectors,
  Blake2STestVectors;

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
                                
