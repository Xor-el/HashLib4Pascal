unit uKdfPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  uBenchmarkCommon,
  HlpIKDF;

type
  TKdfBenchFactory = function: IKDF;

  TKdfPerformanceBenchmark = class sealed(TObject)
  strict private
    class function MeasureMeanMillisecondsPerDerivation(
      AFactory: TKdfBenchFactory; AOutputBytes: Int32): Double;
    class function FormatMillisecondsPerDerivation(AMeanMs: Double): String;
    class procedure InitializeBenchSecrets;
    class function WriteKdfSubTableHeader(ALogProc: TBenchmarkLogProc;
      const AHeadingLines: array of String; const AFirstColTitle: String;
      const AColumnLabels: array of String; AValueColumnWidth: Int32): Int32;
    class procedure WriteKdfMatrixRow(ALogProc: TBenchmarkLogProc;
      const ARowLabel: String; AFactory1, AFactory2, AFactory3: TKdfBenchFactory;
      AOutputBytes, AValueColumnWidth: Int32);
    class procedure WriteKdfSingleValueRow(ALogProc: TBenchmarkLogProc;
      const ARowLabel: String; AFactory: TKdfBenchFactory;
      AOutputBytes, AValueColumnWidth: Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32;
  end;

implementation

uses
  Classes,
  SysUtils,
  Math,
  HlpIHash,
  HlpIHashInfo,
  HlpHashFactory,
  HlpHashLibTypes,
  HlpArgon2TypeAndVersion,
  HlpPBKDF_Argon2NotBuildInAdapter;

const
  BENCH_KDF_OUTPUT_BYTES = Int32(32);
  BENCH_SECRET_LEN = Int32(24);

var
  GBenchPassword: THashLibByteArray;
  GBenchSalt: THashLibByteArray;

function CreatePbkdf2HmacInstance(const AHash: IHash;
  AIterations: UInt32): IKDF;
begin
  Result := TKDF.TPBKDF2_HMAC.CreatePBKDF2_HMAC(AHash, GBenchPassword,
    GBenchSalt, AIterations);
end;

function CreateArgon2KdfFromBuilder(const ABuilder: IArgon2ParametersBuilder;
  AMemoryKiB, ATimeCost, AParallelism: Int32): IKDF;
var
  LParams: IArgon2Parameters;
begin
  ABuilder.WithVersion(TArgon2Version.Version13);
  ABuilder.WithSalt(GBenchSalt);
  ABuilder.WithIterations(ATimeCost);
  ABuilder.WithMemoryAsKB(AMemoryKiB);
  ABuilder.WithParallelism(AParallelism);
  LParams := ABuilder.Build();
  ABuilder.Clear();
  Result := TKDF.TPBKDF_Argon2.CreatePBKDF_Argon2(GBenchPassword, LParams);
  LParams.Clear();
end;

function FactoryPbkdf2HmacSha256Iterations10000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_256, 10000);
end;

function FactoryPbkdf2HmacSha256Iterations100000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_256, 100000);
end;

function FactoryPbkdf2HmacSha256Iterations600000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_256, 600000);
end;

function FactoryPbkdf2HmacSha512Iterations10000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_512, 10000);
end;

function FactoryPbkdf2HmacSha512Iterations100000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_512, 100000);
end;

function FactoryPbkdf2HmacSha512Iterations600000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA2_512, 600000);
end;

function FactoryPbkdf2HmacSha1Iterations10000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA1, 10000);
end;

function FactoryPbkdf2HmacSha1Iterations100000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA1, 100000);
end;

function FactoryPbkdf2HmacSha1Iterations600000: IKDF;
begin
  Result := CreatePbkdf2HmacInstance(THashFactory.TCrypto.CreateSHA1, 600000);
end;

function FactoryArgon2IdMemory8KiBTime1Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2idParametersBuilder.Builder(),
    8, 1, 1);
end;

function FactoryArgon2IdMemory32KiBTime2Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2idParametersBuilder.Builder(),
    32, 2, 1);
end;

function FactoryArgon2IdMemory64KiBTime3Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2idParametersBuilder.Builder(),
    64, 3, 1);
end;

function FactoryArgon2IMemory8KiBTime1Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2iParametersBuilder.Builder(),
    8, 1, 1);
end;

function FactoryArgon2IMemory32KiBTime2Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2iParametersBuilder.Builder(),
    32, 2, 1);
end;

function FactoryArgon2IMemory64KiBTime3Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2iParametersBuilder.Builder(),
    64, 3, 1);
end;

function FactoryArgon2DMemory8KiBTime1Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2dParametersBuilder.Builder(),
    8, 1, 1);
end;

function FactoryArgon2DMemory32KiBTime2Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2dParametersBuilder.Builder(),
    32, 2, 1);
end;

function FactoryArgon2DMemory64KiBTime3Parallelism1: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2dParametersBuilder.Builder(),
    64, 3, 1);
end;

function FactoryScryptCost1024BlockSize8Parallelism1: IKDF;
begin
  Result := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(GBenchPassword, GBenchSalt,
    1024, 8, 1);
end;

function FactoryScryptCost4096BlockSize8Parallelism1: IKDF;
begin
  Result := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(GBenchPassword, GBenchSalt,
    4096, 8, 1);
end;

function FactoryScryptCost16384BlockSize8Parallelism1: IKDF;
begin
  Result := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(GBenchPassword, GBenchSalt,
    16384, 8, 1);
end;

{ OWASP-style reference rows (Password Storage Cheat Sheet, illustrative) }

function FactoryArgon2IdMemory19456KiBTime2Parallelism1Owasp: IKDF;
begin
  Result := CreateArgon2KdfFromBuilder(TArgon2idParametersBuilder.Builder(),
    19456, 2, 1);
end;

function FactoryScryptCost131072BlockSize8Parallelism1Owasp: IKDF;
begin
  Result := TKDF.TPBKDF_Scrypt.CreatePBKDF_Scrypt(GBenchPassword, GBenchSalt,
    131072, 8, 1);
end;

{ TKdfPerformanceBenchmark }

class procedure TKdfPerformanceBenchmark.InitializeBenchSecrets;
var
  LIdx: Int32;
begin
  System.SetLength(GBenchPassword, BENCH_SECRET_LEN);
  System.SetLength(GBenchSalt, BENCH_SECRET_LEN);
  for LIdx := 0 to BENCH_SECRET_LEN - 1 do
  begin
    GBenchPassword[LIdx] := Byte(Random(256));
    GBenchSalt[LIdx] := Byte(Random(256));
  end;
end;

class function TKdfPerformanceBenchmark.FormatMillisecondsPerDerivation(
  AMeanMs: Double): String;
begin
  if not (AMeanMs > 0.0) then
    Result := '0.00 ms'
  else
    Result := FormatFloat('#,##0.00', AMeanMs, TBenchmarkReport.FloatFormat) +
      ' ms';
end;

class function TKdfPerformanceBenchmark.MeasureMeanMillisecondsPerDerivation(
  AFactory: TKdfBenchFactory; AOutputBytes: Int32): Double;
var
  LRound: Int32;
  LCount: Int64;
  LTickStart, LTickEnd, LElapsed: UInt32;
  LKdf: IKDF;
  LDummy: THashLibByteArray;
  LMeanMs: Double;
  LHaveAny: Boolean;
begin
  LHaveAny := False;
  Result := 0.0;
  for LRound := 1 to BENCH_ROUNDS do
  begin
    LCount := 0;
    LElapsed := 0;
    while LElapsed <= BENCH_DURATION_MS do
    begin
      LTickStart := TThread.GetTickCount;
      LKdf := AFactory();
      LDummy := LKdf.GetBytes(AOutputBytes);
      LKdf := nil;
      LTickEnd := TThread.GetTickCount;
      System.Inc(LCount);
      LElapsed := LElapsed + (LTickEnd - LTickStart);
    end;
    if LCount > 0 then
    begin
      LMeanMs := LElapsed / LCount;
      if not LHaveAny or (LMeanMs < Result) then
      begin
        Result := LMeanMs;
        LHaveAny := True;
      end;
    end;
  end;
  if not LHaveAny then
    Result := 0.0;
end;

class function TKdfPerformanceBenchmark.WriteKdfSubTableHeader(
  ALogProc: TBenchmarkLogProc; const AHeadingLines: array of String;
  const AFirstColTitle: String; const AColumnLabels: array of String;
  AValueColumnWidth: Int32): Int32;
var
  LIdx: Int32;
  LHeader: String;
begin
  for LIdx := System.Low(AHeadingLines) to System.High(AHeadingLines) do
    ALogProc(AHeadingLines[LIdx]);
  LHeader := TBenchmarkReport.BuildHeaderRow(AFirstColTitle, AColumnLabels,
    AValueColumnWidth);
  Result := System.Length(LHeader);
  ALogProc(LHeader);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

class procedure TKdfPerformanceBenchmark.WriteKdfMatrixRow(
  ALogProc: TBenchmarkLogProc; const ARowLabel: String;
  AFactory1, AFactory2, AFactory3: TKdfBenchFactory; AOutputBytes,
  AValueColumnWidth: Int32);
var
  LIdx: Int32;
  LMeans: array [0 .. 2] of Double;
  LCells: array [0 .. 2] of String;
begin
  LMeans[0] := MeasureMeanMillisecondsPerDerivation(AFactory1, AOutputBytes);
  LMeans[1] := MeasureMeanMillisecondsPerDerivation(AFactory2, AOutputBytes);
  LMeans[2] := MeasureMeanMillisecondsPerDerivation(AFactory3, AOutputBytes);
  for LIdx := 0 to 2 do
    LCells[LIdx] := FormatMillisecondsPerDerivation(LMeans[LIdx]);
  ALogProc(TBenchmarkReport.BuildDataRow(ARowLabel, LCells, AValueColumnWidth));
end;

class procedure TKdfPerformanceBenchmark.WriteKdfSingleValueRow(
  ALogProc: TBenchmarkLogProc; const ARowLabel: String;
  AFactory: TKdfBenchFactory; AOutputBytes, AValueColumnWidth: Int32);
var
  LCells: array [0 .. 0] of String;
begin
  LCells[0] := FormatMillisecondsPerDerivation(
    MeasureMeanMillisecondsPerDerivation(AFactory, AOutputBytes));
  ALogProc(TBenchmarkReport.BuildDataRow(ARowLabel, LCells, AValueColumnWidth));
end;

class function TKdfPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LCol: array [0 .. 2] of String;
  LHeader: String;
  LPartW: Int32;
  LValueW: Int32;
begin
  Randomize;
  InitializeBenchSecrets;
  Result := 0;
  LValueW := BENCH_KDF_VALUE_COL_WIDTH;

  ALogProc('Key derivation benchmarks');
  ALogProc('-------------------------');
  ALogProc('Each cell: mean milliseconds for one full derivation — new IKDF,');
  ALogProc('then a single GetBytes(' + IntToStr(BENCH_KDF_OUTPUT_BYTES) +
    ') call. Timed like the hash bench: sum per-operation tick deltas until ' +
    'the running total exceeds ' + IntToStr(BENCH_DURATION_MS) +
    ' ms, repeated for ' + IntToStr(BENCH_ROUNDS) +
    ' rounds; the reported value uses the round with the lowest mean time per');
  ALogProc('derivation (same as the previous “best of rounds” derivations/s).');
  ALogProc('');
  ALogProc('Do not compare numbers across PBKDF2 vs Argon2 vs scrypt; work factors differ.');
  ALogProc('Approximate trial rate at the same parameters: derivations/s ~ 1000 / (mean ms).');
  ALogProc('');

  LCol[0] := '10k iter';
  LCol[1] := '100k iter';
  LCol[2] := '600k iter';
  LPartW := WriteKdfSubTableHeader(ALogProc, ['PBKDF2-HMAC'], 'PRF', LCol,
    LValueW);
  Result := Math.Max(Result, LPartW);
  WriteKdfMatrixRow(ALogProc, 'SHA-256',
    @FactoryPbkdf2HmacSha256Iterations10000,
    @FactoryPbkdf2HmacSha256Iterations100000,
    @FactoryPbkdf2HmacSha256Iterations600000, BENCH_KDF_OUTPUT_BYTES, LValueW);
  WriteKdfMatrixRow(ALogProc, 'SHA-512',
    @FactoryPbkdf2HmacSha512Iterations10000,
    @FactoryPbkdf2HmacSha512Iterations100000,
    @FactoryPbkdf2HmacSha512Iterations600000, BENCH_KDF_OUTPUT_BYTES, LValueW);
  WriteKdfMatrixRow(ALogProc, 'SHA-1', @FactoryPbkdf2HmacSha1Iterations10000,
    @FactoryPbkdf2HmacSha1Iterations100000,
    @FactoryPbkdf2HmacSha1Iterations600000, BENCH_KDF_OUTPUT_BYTES, LValueW);
  LHeader := TBenchmarkReport.BuildHeaderRow('PRF', LCol, LValueW);
  ALogProc(TBenchmarkReport.BuildSeparator(System.Length(LHeader)));
  ALogProc('');

  LCol[0] := 'm=8KiB t=1 p=1';
  LCol[1] := 'm=32KiB t=2 p=1';
  LCol[2] := 'm=64KiB t=3 p=1';
  LPartW := WriteKdfSubTableHeader(ALogProc,
    ['Argon2 (memory = KiB, t = time cost)'], 'Type', LCol, LValueW);
  Result := Math.Max(Result, LPartW);
  WriteKdfMatrixRow(ALogProc, 'Argon2id',
    @FactoryArgon2IdMemory8KiBTime1Parallelism1,
    @FactoryArgon2IdMemory32KiBTime2Parallelism1,
    @FactoryArgon2IdMemory64KiBTime3Parallelism1, BENCH_KDF_OUTPUT_BYTES,
    LValueW);
  WriteKdfMatrixRow(ALogProc, 'Argon2i',
    @FactoryArgon2IMemory8KiBTime1Parallelism1,
    @FactoryArgon2IMemory32KiBTime2Parallelism1,
    @FactoryArgon2IMemory64KiBTime3Parallelism1, BENCH_KDF_OUTPUT_BYTES,
    LValueW);
  WriteKdfMatrixRow(ALogProc, 'Argon2d',
    @FactoryArgon2DMemory8KiBTime1Parallelism1,
    @FactoryArgon2DMemory32KiBTime2Parallelism1,
    @FactoryArgon2DMemory64KiBTime3Parallelism1, BENCH_KDF_OUTPUT_BYTES,
    LValueW);
  LHeader := TBenchmarkReport.BuildHeaderRow('Type', LCol, LValueW);
  ALogProc(TBenchmarkReport.BuildSeparator(System.Length(LHeader)));
  ALogProc('');

  LCol[0] := 'N=1024';
  LCol[1] := 'N=4096';
  LCol[2] := 'N=16384';
  LPartW := WriteKdfSubTableHeader(ALogProc, ['scrypt (r=8, p=1)'], 'KDF', LCol,
    LValueW);
  Result := Math.Max(Result, LPartW);
  WriteKdfMatrixRow(ALogProc, 'scrypt',
    @FactoryScryptCost1024BlockSize8Parallelism1,
    @FactoryScryptCost4096BlockSize8Parallelism1,
    @FactoryScryptCost16384BlockSize8Parallelism1, BENCH_KDF_OUTPUT_BYTES,
    LValueW);
  LHeader := TBenchmarkReport.BuildHeaderRow('KDF', LCol, LValueW);
  ALogProc(TBenchmarkReport.BuildSeparator(System.Length(LHeader)));
  ALogProc('');

  LPartW := WriteKdfSubTableHeader(ALogProc,
    ['Reference profiles (OWASP cheat sheet style, same 32-byte derive)'],
    'Profile', ['Mean ms'], LValueW);
  Result := Math.Max(Result, LPartW);
  WriteKdfSingleValueRow(ALogProc, 'PBKDF2-HMAC-SHA-256 600k iter',
    @FactoryPbkdf2HmacSha256Iterations600000, BENCH_KDF_OUTPUT_BYTES, LValueW);
  WriteKdfSingleValueRow(ALogProc, 'Argon2id m=19456 t=2 p=1',
    @FactoryArgon2IdMemory19456KiBTime2Parallelism1Owasp,
    BENCH_KDF_OUTPUT_BYTES, LValueW);
  WriteKdfSingleValueRow(ALogProc, 'scrypt N=131072 r=8 p=1',
    @FactoryScryptCost131072BlockSize8Parallelism1Owasp,
    BENCH_KDF_OUTPUT_BYTES, LValueW);
  LHeader := TBenchmarkReport.BuildHeaderRow('Profile', ['Mean ms'], LValueW);
  ALogProc(TBenchmarkReport.BuildSeparator(System.Length(LHeader)));
end;

end.
