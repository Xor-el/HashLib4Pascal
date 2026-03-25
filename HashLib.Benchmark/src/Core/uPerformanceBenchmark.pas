unit uPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
  Math,
  HlpCRC,
  HlpIHash,
  HlpHashFactory;

type
  TBenchmarkLogProc = procedure(const AMessage: String);

  TPerformanceBenchmark = class sealed(TObject)
  strict private
  const
    BENCH_DURATION_MS = UInt32(3000);
    BENCH_ROUNDS = Int32(3);
    NAME_COL_WIDTH = Int32(32);
    RATE_COL_WIDTH = Int32(16);

  class var
    FFormatSettings: TFormatSettings;

    class function MeasureThroughput(const AHashInstance: IHash;
      ASize: Int32): Double;
    class function FormatSize(ASize: Int32): String;
    class function FormatRate(ARate: Double): String;
    class function BuildTableRow(const AName: String;
      const ARates: array of Double): String;
    class function BuildHeaderRow(
      const ABufferSizes: array of Int32): String;
    class function BuildSeparator(AWidth: Int32): String;
    class function GetPlatformInfo: String;
    class procedure RunBenchmarks(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32);

    class constructor CreateBenchmark;

  public
    class procedure Run(ALogProc: TBenchmarkLogProc); overload;
    class procedure Run(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32); overload;
  end;

implementation

{ TPerformanceBenchmark }

class constructor TPerformanceBenchmark.CreateBenchmark;
begin
  Randomize;
{$IFDEF FPC}
  FFormatSettings := DefaultFormatSettings;
{$ELSE}
  FFormatSettings := FormatSettings;
{$ENDIF}
  FFormatSettings.ThousandSeparator := ',';
  FFormatSettings.DecimalSeparator := '.';
end;

class function TPerformanceBenchmark.MeasureThroughput(
  const AHashInstance: IHash; ASize: Int32): Double;
var
  LData: TBytes;
  LRound: Int32;
  LTotal: Int64;
  LTickStart, LTickEnd, LElapsed: UInt32;
begin
  System.SetLength(LData, ASize);
  for LRound := System.Low(LData) to System.High(LData) do
    LData[LRound] := Byte(Random(256));

  Result := 0.0;
  for LRound := 1 to BENCH_ROUNDS do
  begin
    LTotal := 0;
    LElapsed := 0;
    while LElapsed <= BENCH_DURATION_MS do
    begin
      LTickStart := TThread.GetTickCount;
      AHashInstance.ComputeBytes(LData);
      LTickEnd := TThread.GetTickCount;
      LTotal := LTotal + System.Length(LData);
      LElapsed := LElapsed + (LTickEnd - LTickStart);
    end;
    if LElapsed > 0 then
      Result := Math.Max(LTotal / (LElapsed / 1000.0) / 1024.0 / 1024.0,
        Result);
  end;
end;

class function TPerformanceBenchmark.FormatSize(ASize: Int32): String;
begin
  if ASize >= 1024 * 1024 then
    Result := Format('%d MB', [ASize div (1024 * 1024)])
  else if ASize >= 1024 then
    Result := Format('%d KB', [ASize div 1024])
  else
    Result := Format('%d B', [ASize]);
end;

class function TPerformanceBenchmark.FormatRate(ARate: Double): String;
begin
  Result := FormatFloat('#,##0.00', ARate, FFormatSettings) + ' MB/s';
end;

class function TPerformanceBenchmark.BuildTableRow(const AName: String;
  const ARates: array of Double): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := AName;
  while System.Length(Result) < NAME_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(ARates) to System.High(ARates) do
  begin
    LCell := FormatRate(ARates[LIdx]);
    while System.Length(LCell) < RATE_COL_WIDTH do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TPerformanceBenchmark.BuildHeaderRow(
  const ABufferSizes: array of Int32): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := 'Hash Name';
  while System.Length(Result) < NAME_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(ABufferSizes) to System.High(ABufferSizes) do
  begin
    LCell := FormatSize(ABufferSizes[LIdx]);
    while System.Length(LCell) < RATE_COL_WIDTH do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TPerformanceBenchmark.BuildSeparator(AWidth: Int32): String;
begin
  Result := StringOfChar('-', AWidth);
end;

class function TPerformanceBenchmark.GetPlatformInfo: String;
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
  LCPU := 'x86';
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
  LCPU := 'x86';
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

class procedure TPerformanceBenchmark.RunBenchmarks(
  ALogProc: TBenchmarkLogProc; const ABufferSizes: array of Int32);
var
  LHeaderRow: String;
  LTotalWidth: Int32;
  LRates: array of Double;

  procedure Bench(const AHashInstance: IHash; const AName: String);
  var
    LIdx: Int32;
  begin
    for LIdx := 0 to System.High(ABufferSizes) do
      LRates[LIdx] := MeasureThroughput(AHashInstance, ABufferSizes[LIdx]);
    ALogProc(BuildTableRow(AName, LRates));
  end;

begin
  System.SetLength(LRates, System.Length(ABufferSizes));

  ALogProc('HashLib4Pascal Performance Benchmark');
  ALogProc('=====================================');
  ALogProc('');

  LHeaderRow := BuildHeaderRow(ABufferSizes);
  LTotalWidth := System.Length(LHeaderRow);
  ALogProc(LHeaderRow);
  ALogProc(BuildSeparator(LTotalWidth));

  // Checksums
  Bench(THashFactory.TChecksum.CreateAdler32, 'Adler32');
  Bench(THashFactory.TChecksum.TCRC.CreateCRC(TCRCStandard.CRC32),
    'CRC32 (PKZIP, Generic)');
  Bench(THashFactory.TChecksum.TCRC.CreateCRC32_PKZIP,
    'CRC32 (PKZIP, Fast)');
  Bench(THashFactory.TChecksum.TCRC.CreateCRC(TCRCStandard.CRC32C),
    'CRC32C (Castagnoli, Generic)');
  Bench(THashFactory.TChecksum.TCRC.CreateCRC32_CASTAGNOLI,
    'CRC32C (Castagnoli, Fast)');
  Bench(THashFactory.TChecksum.TCRC.CreateCRC64_ECMA_182,
    'CRC64 (ECMA-182)');

  // Non-cryptographic
  Bench(THashFactory.THash32.CreateMurmurHash3_x86_32,
    'MurmurHash3-x86-32');
  Bench(THashFactory.THash32.CreateXXHash32, 'XXHash32');
  Bench(THashFactory.THash64.CreateSipHash2_4, 'SipHash-2-4');
  Bench(THashFactory.THash64.CreateXXHash64, 'XXHash64');
  Bench(THashFactory.THash64.CreateXXHash3, 'XXHash3');
  Bench(THashFactory.THash128.CreateMurmurHash3_x86_128,
    'MurmurHash3-x86-128');
  Bench(THashFactory.THash128.CreateMurmurHash3_x64_128,
    'MurmurHash3-x64-128');
  Bench(THashFactory.THash128.CreateSipHash128_2_4, 'SipHash128-2-4');
  Bench(THashFactory.THash128.CreateXXHash128, 'XXHash128');

  // Cryptographic
  Bench(THashFactory.TCrypto.CreateMD5, 'MD5');
  Bench(THashFactory.TCrypto.CreateSHA1, 'SHA-1');
  Bench(THashFactory.TCrypto.CreateSHA2_256, 'SHA2-256');
  Bench(THashFactory.TCrypto.CreateSHA2_512, 'SHA2-512');
  Bench(THashFactory.TCrypto.CreateSHA3_256, 'SHA3-256');
  Bench(THashFactory.TCrypto.CreateSHA3_512, 'SHA3-512');
  Bench(THashFactory.TCrypto.CreateBlake2B_256, 'Blake2B-256');
  Bench(THashFactory.TCrypto.CreateBlake2B_512, 'Blake2B-512');
  Bench(THashFactory.TCrypto.CreateBlake2S_128, 'Blake2S-128');
  Bench(THashFactory.TCrypto.CreateBlake2S_256, 'Blake2S-256');
  Bench(THashFactory.TCrypto.CreateBlake2BP(64, nil), 'Blake2BP');
  Bench(THashFactory.TCrypto.CreateBlake2SP(32, nil), 'Blake2SP');
  Bench(THashFactory.TCrypto.CreateBlake3_256(nil), 'Blake3-256');

  // Footer
  ALogProc(BuildSeparator(LTotalWidth));
  ALogProc('Benchmark complete.');
  ALogProc(GetPlatformInfo);
  ALogProc(Format('Date: %s', [FormatDateTime('yyyy-mm-dd', Now)]));
end;

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc);
const
  DEFAULT_SIZES: array [0 .. 4] of Int32 = (256, 1024, 8192, 65536, 1048576);
begin
  Run(ALogProc, DEFAULT_SIZES);
end;

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ABufferSizes: array of Int32);
begin
  RunBenchmarks(ALogProc, ABufferSizes);
end;

end.
