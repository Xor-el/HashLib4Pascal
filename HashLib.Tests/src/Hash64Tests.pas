unit Hash64Tests;

interface

{$IFDEF FPC}
{$WARNINGS OFF}
{$NOTES OFF}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HashLibTestBase,
  HlpHashFactory,
  HlpIHash,
  HlpIHashInfo,
  HlpConverters;

// Hash64

type

  TTestFNV64 = class(THashLibAlgorithmTestCase)

  private

    FFNV64: IHash;

  const
    FExpectedHashOfEmptyData: String = '0000000000000000';
    FExpectedHashOfDefaultData: String = '061A6856F5925B83';
    FExpectedHashOfOnetoNine: String = 'B8FB573C21FE68F1';
    FExpectedHashOfabcde: String = '77018B280326F529';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type

  TTestFNV1a64 = class(THashLibAlgorithmTestCase)

  private

    FFNV1a64: IHash;

  const
    FExpectedHashOfEmptyData: String = 'CBF29CE484222325';
    FExpectedHashOfDefaultData: String = '5997E22BF92B0598';
    FExpectedHashOfOnetoNine: String = '06D5573923C6CDFC';
    FExpectedHashOfabcde: String = '6348C52D762364A8';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type

  TTestMurmur2_64 = class(THashLibAlgorithmTestCase)

  private

    FMurmur2_64: IHash;

  const
    FExpectedHashOfEmptyData: String = '0000000000000000';
    FExpectedHashOfDefaultData: String = 'F78F3AF068158F5A';
    FExpectedHashOfOnetoNine: String = 'F22BE622518FAF39';
    FExpectedHashOfabcde: String = 'AF7BA284707E90C2';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = '49F2E215E924B552';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKey;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type
  TTestSipHash2_4 = class(THashLibAlgorithmTestCase)

  private

    FSipHash2_4: IHash;

  const
    FExpectedHashOfEmptyData: String = '726FDB47DD0E0E31';
    FExpectedHashOfDefaultData: String = 'AA43C4288619D24E';
    FExpectedHashOfShortMessage: String = 'AE43DFAED1AB1C00';
    FExpectedHashOfOnetoNine: String = 'CA60FC96020EFEFD';
    FExpectedHashOfabcde: String = 'A74563E1EA79B873';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestShortMessage;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestIndexChunkedDataIncrementalHash;
    procedure TestWithOutsideKey;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type

  TTestXXHash64 = class(THashLibAlgorithmTestCase)

  private

    FXXHash64: IHash;

  const
    FExpectedHashOfEmptyData: String = 'EF46DB3751D8E999';
    FExpectedHashOfDefaultData: String = '0F1FADEDD0B77861';
    FExpectedHashOfRandomString: String = 'C9C17BCD07584404';
    FExpectedHashOfZerotoFour: String = '34CB4C2EE6166F65';
    FExpectedHashOfEmptyDataWithOneAsKey: String = 'D5AFBA1336A3BE4B';
    FExpectedHashOfDefaultDataWithMaxUInt64AsKey: String = '68DCC1056096A94F';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt64DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

implementation

// Hash64

{ TTestFNV64 }

procedure TTestFNV64.SetUp;
begin
  inherited;
  FFNV64 := THashFactory.THash64.CreateFNV();
end;

procedure TTestFNV64.TearDown;
begin
  FFNV64 := Nil;
  inherited;
end;

procedure TTestFNV64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FFNV64;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FFNV64;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestFNV64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV64.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateFNV;

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV64.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV1a64 }

procedure TTestFNV1a64.SetUp;
begin
  inherited;
  FFNV1a64 := THashFactory.THash64.CreateFNV1a();
end;

procedure TTestFNV1a64.TearDown;
begin
  FFNV1a64 := Nil;
  inherited;
end;

procedure TTestFNV1a64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV1a64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FFNV1a64;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FFNV1a64;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestFNV1a64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV1a64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV1a64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV1a64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV1a64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateFNV1a();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV1a64.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmur2_64 }

procedure TTestMurmur2_64.SetUp;
begin
  inherited;
  FMurmur2_64 := THashFactory.THash64.CreateMurmur2();
end;

procedure TTestMurmur2_64.TearDown;
begin
  FMurmur2_64 := Nil;
  inherited;
end;

procedure TTestMurmur2_64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMurmur2_64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMurmur2_64;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMurmur2_64;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMurmur2_64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmur2_64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmur2_64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmur2_64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmur2_64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateMurmur2();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMurmur2_64.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestWithDifferentKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmur2_64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSipHash2_4 }

procedure TTestSipHash2_4.SetUp;
begin
  inherited;
  FSipHash2_4 := THashFactory.THash64.CreateSipHash2_4();
end;

procedure TTestSipHash2_4.TearDown;
begin
  FSipHash2_4 := Nil;
  inherited;
end;

procedure TTestSipHash2_4.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FSipHash2_4.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FSipHash2_4.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FSipHash2_4.TransformString(temp, TEncoding.UTF8);

    FActualString := FSipHash2_4.TransformFinal().ToString();
    FExpectedString := THashFactory.THash64.CreateSipHash2_4.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s',
      [FExpectedString, FActualString]));
  end;

end;

procedure TTestSipHash2_4.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSipHash2_4.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSipHash2_4;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSipHash2_4;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSipHash2_4.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSipHash2_4.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSipHash2_4.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSipHash2_4.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSipHash2_4.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateSipHash2_4();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestIndexChunkedDataIncrementalHash;
var
  Count, i: Int32;
  ChunkedDataBytes, temp: TBytes;

begin
  ChunkedDataBytes := TConverters.ConvertStringToBytes(FChunkedData,
    TEncoding.UTF8);
  for i := System.Low(ChunkedDataBytes) to System.High(ChunkedDataBytes) do
  begin
    Count := System.Length(ChunkedDataBytes) - i;
    temp := System.Copy(ChunkedDataBytes, i, Count);
    FSipHash2_4.Initialize();

    FSipHash2_4.TransformBytes(ChunkedDataBytes, i, Count);

    FActualString := FSipHash2_4.TransformFinal().ToString();
    FExpectedString := THashFactory.THash64.CreateSipHash2_4()
      .ComputeBytes(temp).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestSipHash2_4.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSipHash2_4.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestShortMessage;
begin
  FExpectedString := FExpectedHashOfShortMessage;
  FActualString := FSipHash2_4.ComputeString(FShortMessage, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestWithOutsideKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  LIHashWithKey := (FSipHash2_4 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ConvertHexStringToBytes(FHexStringAsKey);
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestXXHash64 }

procedure TTestXXHash64.SetUp;
begin
  inherited;
  FXXHash64 := THashFactory.THash64.CreateXXHash64();

end;

procedure TTestXXHash64.TearDown;
begin
  FXXHash64 := Nil;
  inherited;
end;

procedure TTestXXHash64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FXXHash64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestXXHash64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FXXHash64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FXXHash64.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FXXHash64.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FXXHash64.TransformString(temp, TEncoding.UTF8);

    FActualString := FXXHash64.TransformFinal().ToString();
    FExpectedString := THashFactory.THash64.CreateXXHash64.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestXXHash64.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FXXHash64;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FXXHash64;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestXXHash64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FXXHash64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateXXHash64();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FXXHash64.ComputeString(FRandomStringTobacco, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestWithDifferentKeyMaxUInt64DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt64AsKey;
  LIHashWithKey := (FXXHash64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt64AsBytesLE(System.High(UInt64));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FXXHash64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt64AsBytesLE(UInt64(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FXXHash64.ComputeString(FZerotoFour, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Hash64
RegisterTest(TTestFNV64);
RegisterTest(TTestFNV1a64);
RegisterTest(TTestMurmur2_64);
RegisterTest(TTestSipHash2_4);
RegisterTest(TTestXXHash64);
{$ELSE}
// Hash64
RegisterTest(TTestFNV64.Suite);
RegisterTest(TTestFNV1a64.Suite);
RegisterTest(TTestMurmur2_64.Suite);
RegisterTest(TTestSipHash2_4.Suite);
RegisterTest(TTestXXHash64.Suite);
{$ENDIF FPC}

end.
