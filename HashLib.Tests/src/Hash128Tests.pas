unit Hash128Tests;

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

// Hash128

type

  TTestMurmurHash3_x86_128 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x86_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000000000000000000000000000';
    FExpectedHashOfDefaultData: String = 'B35E1058738E067BF637B17075F14B8B';
    FExpectedHashOfRandomString: String = '9B5B7BA2EF3F7866889ADEAF00F3F98E';
    FExpectedHashOfZerotoFour: String = '35C5B3EE7B3B211600AE108800AE1088';
    FExpectedHashOfEmptyDataWithOneAsKey
      : String = '88C4ADEC54D201B954D201B954D201B9';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey
      : String = '55315FA9E8129C7390C080B8FDB1C972';

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
    procedure TestIndexChunkedDataIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type

  TTestMurmurHash3_x64_128 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x64_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000000000000000000000000000';
    FExpectedHashOfDefaultData: String = '705BD3C954B94BE056F06B68662E6364';
    FExpectedHashOfRandomString: String = 'D30654ABBD8227E367D73523F0079673';
    FExpectedHashOfZerotoFour: String = '0F04E459497F3FC1ECCC6223A28DD613';
    FExpectedHashOfEmptyDataWithOneAsKey
      : String = '4610ABE56EFF5CB551622DAA78F83583';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey
      : String = 'ADFD14988FB1F8582A1B67C1BBACC218';

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
    procedure TestIndexChunkedDataIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

implementation

// Hash128

{ TTestMurmurHash3_x86_128 }

procedure TTestMurmurHash3_x86_128.SetUp;
begin
  inherited;
  FMurmurHash3_x86_128 := THashFactory.THash128.CreateMurmurHash3_x86_128();

end;

procedure TTestMurmurHash3_x86_128.TearDown;
begin
  FMurmurHash3_x86_128 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x86_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x86_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x86_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x86_128.ComputeString(FEmptyData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x86_128.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x86_128.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x86_128.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x86_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x86_128.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s',
      [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x86_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMurmurHash3_x86_128;
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

procedure TTestMurmurHash3_x86_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMurmurHash3_x86_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMurmurHash3_x86_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x86_128.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash128.CreateMurmurHash3_x86_128();

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

procedure TTestMurmurHash3_x86_128.TestIndexChunkedDataIncrementalHash;
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
    FMurmurHash3_x86_128.Initialize();

    FMurmurHash3_x86_128.TransformBytes(ChunkedDataBytes, i, Count);

    FActualString := FMurmurHash3_x86_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x86_128.
      ComputeBytes(temp).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x86_128.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x86_128.ComputeString(FRandomStringTobacco,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x86_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x86_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x86_128.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmurHash3_x64_128 }

procedure TTestMurmurHash3_x64_128.SetUp;
begin
  inherited;
  FMurmurHash3_x64_128 := THashFactory.THash128.CreateMurmurHash3_x64_128();

end;

procedure TTestMurmurHash3_x64_128.TearDown;
begin
  FMurmurHash3_x64_128 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x64_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x64_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x64_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x64_128.ComputeString(FEmptyData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x64_128.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x64_128.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x64_128.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x64_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x64_128.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x64_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMurmurHash3_x64_128;
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

procedure TTestMurmurHash3_x64_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMurmurHash3_x64_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMurmurHash3_x64_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x64_128.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash128.CreateMurmurHash3_x64_128();

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

procedure TTestMurmurHash3_x64_128.TestIndexChunkedDataIncrementalHash;
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
    FMurmurHash3_x64_128.Initialize();

    FMurmurHash3_x64_128.TransformBytes(ChunkedDataBytes, i, Count);

    FActualString := FMurmurHash3_x64_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x64_128.
      ComputeBytes(temp).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x64_128.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x64_128.ComputeString(FRandomStringTobacco,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x64_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x64_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x64_128.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Hash128
RegisterTest(TTestMurmurHash3_x86_128);
RegisterTest(TTestMurmurHash3_x64_128);
{$ELSE}
// Hash128
RegisterTest(TTestMurmurHash3_x86_128.Suite);
RegisterTest(TTestMurmurHash3_x64_128.Suite);
{$ENDIF FPC}

end.
