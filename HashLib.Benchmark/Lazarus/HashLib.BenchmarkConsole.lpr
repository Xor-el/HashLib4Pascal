program HashLib.BenchmarkConsole;

{$MODE DELPHI}

uses
  SysUtils,
  PerformanceBenchmark;

procedure ConsoleLog(const AMessage: String);
begin
  Writeln(AMessage);
end;

begin
  try
    TPerformanceBenchmark.Run(ConsoleLog);
    // ReadLn; // TODO: restore for interactive IDE runs; disabled for CI
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
