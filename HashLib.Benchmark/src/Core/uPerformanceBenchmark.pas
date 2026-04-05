unit uPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  uBenchmarkCommon,
  uHashPerformanceBenchmark,
  uKdfPerformanceBenchmark;

type
  TPerformanceBenchmark = class sealed(TObject)
  public
    class procedure Run(ALogProc: TBenchmarkLogProc); overload;
    class procedure Run(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32); overload;
  end;

implementation

uses
  Math;

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ABufferSizes: array of Int32);
var
  LHashWidth, LKdfWidth: Int32;
begin
  LHashWidth := THashPerformanceBenchmark.Run(ALogProc, ABufferSizes);
  ALogProc('');
  LKdfWidth := TKdfPerformanceBenchmark.Run(ALogProc);
  TBenchmarkReport.WriteStandardFooter(ALogProc, Math.Max(LHashWidth, LKdfWidth));
end;

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc);
const
  DEFAULT_SIZES: array [0 .. 4] of Int32 = (256, 1024, 8192, 65536, 1048576);
begin
  Run(ALogProc, DEFAULT_SIZES);
end;

end.
