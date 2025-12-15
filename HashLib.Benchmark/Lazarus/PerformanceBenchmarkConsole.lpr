program PerformanceBenchmarkConsole;

uses
  Classes,
  SysUtils,
  uPerformanceBenchmark;

var
  StringList: TStringList;
  Log: String;

begin
  try
    Writeln('Please be patient, this might take some time' + SLineBreak);
    StringList := TStringList.Create;
    try
      TPerformanceBenchmark.DoBenchmark(StringList);

      for Log in StringList do
      begin
        Writeln(Log);
      end;

    finally
      StringList.Free;
    end;
    Writeln(SLineBreak + 'Performance Benchmark Finished');
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

end.
