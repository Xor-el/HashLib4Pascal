unit uBenchmarkCommon;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  SysUtils;

type
  TBenchmarkLogProc = procedure(const AMessage: String);

const
  BENCH_DURATION_MS = UInt32(3000);
  BENCH_ROUNDS = 3;
  BENCH_LABEL_COL_WIDTH = 32;
  BENCH_VALUE_COL_WIDTH = 16;
  BENCH_KDF_VALUE_COL_WIDTH = 22;

type
  TBenchmarkReport = class sealed(TObject)
  public
  class var
    FloatFormat: TFormatSettings;
  strict private
    class constructor Create;
  public
    class function GetPlatformInfo: String;
    class function BuildSeparator(AWidth: Int32): String;
    class function BuildHeaderRow(const AFirstColTitle: String;
      const AColumnLabels: array of String): String; overload;
    class function BuildHeaderRow(const AFirstColTitle: String;
      const AColumnLabels: array of String;
      AValueColumnWidth: Int32): String; overload;
    class function BuildDataRow(const ARowLabel: String;
      const ACells: array of String): String; overload;
    class function BuildDataRow(const ARowLabel: String;
      const ACells: array of String;
      AValueColumnWidth: Int32): String; overload;
    class procedure WriteStandardFooter(ALogProc: TBenchmarkLogProc;
      ATableWidth: Int32);
  end;

implementation

{ TBenchmarkReport }

class constructor TBenchmarkReport.Create;
begin
{$IFDEF FPC}
  FloatFormat := DefaultFormatSettings;
{$ELSE}
  FloatFormat := FormatSettings;
{$ENDIF}
  FloatFormat.ThousandSeparator := ',';
  FloatFormat.DecimalSeparator := '.';
end;

class function TBenchmarkReport.BuildSeparator(AWidth: Int32): String;
begin
  Result := StringOfChar('-', AWidth);
end;

class function TBenchmarkReport.BuildHeaderRow(const AFirstColTitle: String;
  const AColumnLabels: array of String): String;
begin
  Result := BuildHeaderRow(AFirstColTitle, AColumnLabels, BENCH_VALUE_COL_WIDTH);
end;

class function TBenchmarkReport.BuildHeaderRow(const AFirstColTitle: String;
  const AColumnLabels: array of String; AValueColumnWidth: Int32): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := AFirstColTitle;
  while System.Length(Result) < BENCH_LABEL_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(AColumnLabels) to System.High(AColumnLabels) do
  begin
    LCell := AColumnLabels[LIdx];
    while System.Length(LCell) < AValueColumnWidth do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TBenchmarkReport.BuildDataRow(const ARowLabel: String;
  const ACells: array of String): String;
begin
  Result := BuildDataRow(ARowLabel, ACells, BENCH_VALUE_COL_WIDTH);
end;

class function TBenchmarkReport.BuildDataRow(const ARowLabel: String;
  const ACells: array of String; AValueColumnWidth: Int32): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := ARowLabel;
  while System.Length(Result) < BENCH_LABEL_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(ACells) to System.High(ACells) do
  begin
    LCell := ACells[LIdx];
    while System.Length(LCell) < AValueColumnWidth do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TBenchmarkReport.GetPlatformInfo: String;
var
  LOS, LCompiler, LCPU: String;
begin
{$IFDEF FPC}
  {$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
  {$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
  {$ELSEIF DEFINED(DARWIN)}
  LOS := 'macOS';
  {$ELSE}
  LOS := 'Unknown OS';
  {$ENDIF}

  {$IF DEFINED(CPUX86_64)}
  LCPU := 'x86_64';
  {$ELSEIF DEFINED(CPUI386)}
  LCPU := 'i386';
  {$ELSEIF DEFINED(CPUAARCH64)}
  LCPU := 'AArch64';
  {$ELSEIF DEFINED(CPUARM)}
  LCPU := 'ARM';
  {$ELSE}
  LCPU := 'Unknown CPU';
  {$ENDIF}
{$ELSE}
  {$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
  {$ELSEIF DEFINED(ANDROID)}
  LOS := 'Android';
  {$ELSEIF DEFINED(IOS)}
  LOS := 'iOS';
  {$ELSEIF DEFINED(MACOS)}
  LOS := 'macOS';
  {$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
  {$ELSE}
  LOS := 'Unknown OS';
  {$ENDIF}

  {$IF DEFINED(CPUX64)}
  LCPU := 'x86_64';
  {$ELSEIF DEFINED(CPUX86)}
  LCPU := 'i386';
  {$ELSEIF DEFINED(CPUARM64)}
  LCPU := 'AArch64';
  {$ELSEIF DEFINED(CPUARM)}
  LCPU := 'ARM';
  {$ELSE}
  LCPU := 'Unknown CPU';
  {$ENDIF}
{$ENDIF}

{$IFDEF FPC}
  LCompiler := 'FPC ' + {$I %FPCVERSION%};
{$ELSE}
  LCompiler := Format('Delphi (CompilerVersion %.1f)', [CompilerVersion]);
{$ENDIF}

  Result := Format('Platform: %s %s, %s', [LOS, LCPU, LCompiler]);
end;

class procedure TBenchmarkReport.WriteStandardFooter(ALogProc: TBenchmarkLogProc;
  ATableWidth: Int32);
begin
  if ATableWidth < 40 then
    ATableWidth := 40;
  ALogProc(BuildSeparator(ATableWidth));
  ALogProc('Benchmark complete.');
  ALogProc(GetPlatformInfo);
  ALogProc('Date: ' + FormatDateTime('yyyy-mm-dd', Now));
end;

end.
