program PerformanceBenchmarkConsole;

{$MODE DELPHI}

uses
  SysUtils,
  uPerformanceBenchmark;

procedure ConsoleLog(const AMessage: String);
begin
  Writeln(AMessage);
end;

begin
  try
    TPerformanceBenchmark.Run(ConsoleLog);
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
