unit uHashPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  Classes,
  SysUtils,
  HlpIHash,
  HlpHashFactory,
  HlpCRC,
  uBenchmarkCommon;

type
  THashPerformanceBenchmark = class sealed(TObject)
  strict private
    class function MeasureThroughput(const AHashInstance: IHash;
      ASize: Int32): Double;
    class function FormatSize(ASize: Int32): String;
    class function FormatRate(ARate: Double): String;
    class function BuildHashTableRow(const AName: String;
      const ARates: array of Double): String;
    class function BuildHashHeaderRow(
      const ABufferSizes: array of Int32): String;
    class procedure RunHashList(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32; overload;
    class function Run(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32): Int32; overload;
  end;

implementation

uses
  Math;

{ THashPerformanceBenchmark }

class function THashPerformanceBenchmark.FormatSize(ASize: Int32): String;
begin
  if ASize >= 1024 * 1024 then
    Result := Format('%d MB', [ASize div (1024 * 1024)])
  else if ASize >= 1024 then
    Result := Format('%d KB', [ASize div 1024])
  else
    Result := Format('%d B', [ASize]);
end;

class function THashPerformanceBenchmark.FormatRate(ARate: Double): String;
begin
  Result := FormatFloat('#,##0.00', ARate, TBenchmarkReport.FloatFormat) +
    ' MB/s';
end;

class function THashPerformanceBenchmark.BuildHashTableRow(const AName: String;
  const ARates: array of Double): String;
var
  LIdx: Int32;
  LParts: array of String;
begin
  System.SetLength(LParts, System.Length(ARates));
  for LIdx := System.Low(ARates) to System.High(ARates) do
    LParts[LIdx] := FormatRate(ARates[LIdx]);
  Result := TBenchmarkReport.BuildDataRow(AName, LParts);
end;

class function THashPerformanceBenchmark.BuildHashHeaderRow(
  const ABufferSizes: array of Int32): String;
var
  LIdx: Int32;
  LLabels: array of String;
begin
  System.SetLength(LLabels, System.Length(ABufferSizes));
  for LIdx := System.Low(ABufferSizes) to System.High(ABufferSizes) do
    LLabels[LIdx] := FormatSize(ABufferSizes[LIdx]);
  Result := TBenchmarkReport.BuildHeaderRow('Hash Name', LLabels);
end;

class function THashPerformanceBenchmark.MeasureThroughput(
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

class procedure THashPerformanceBenchmark.RunHashList(
  ALogProc: TBenchmarkLogProc; const ABufferSizes: array of Int32);
var
  LRates: array of Double;

  procedure Bench(const AHashInstance: IHash; const AName: String);
  var
    LIdx: Int32;
  begin
    for LIdx := 0 to System.High(ABufferSizes) do
      LRates[LIdx] := MeasureThroughput(AHashInstance, ABufferSizes[LIdx]);
    ALogProc(BuildHashTableRow(AName, LRates));
  end;

begin
  System.SetLength(LRates, System.Length(ABufferSizes));

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
end;

class function THashPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ABufferSizes: array of Int32): Int32;
var
  LHeaderRow: String;
begin
  Randomize;
  ALogProc('HashLib4Pascal Performance Benchmark');
  ALogProc('=====================================');
  ALogProc('');

  LHeaderRow := BuildHashHeaderRow(ABufferSizes);
  Result := System.Length(LHeaderRow);
  ALogProc(LHeaderRow);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  RunHashList(ALogProc, ABufferSizes);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

class function THashPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
const
  DEFAULT_SIZES: array [0 .. 4] of Int32 = (256, 1024, 8192, 65536, 1048576);
begin
  Result := Run(ALogProc, DEFAULT_SIZES);
end;

end.
