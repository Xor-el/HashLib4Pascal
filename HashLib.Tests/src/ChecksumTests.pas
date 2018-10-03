unit ChecksumTests;

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
  HlpCRC,
  HlpICRC,
  HlpHashFactory,
  HlpIHash,
  HlpConverters;

// Checksum

type

  TTestCRCModel = class(THashLibAlgorithmTestCase)
  private

    FCRC: IHash;

  protected
    procedure TearDown; override;
  published
    procedure TestCheckValue;
    procedure TestCheckValueWithIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

type

  TTestAlder32 = class(THashLibAlgorithmTestCase)

  private

    FAdler32: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000001';
    FExpectedHashOfDefaultData: String = '25D40524';
    FExpectedHashOfOnetoNine: String = '091E01DE';
    FExpectedHashOfabcde: String = '05C801F0';

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

implementation

// Checksum

{ TTestCRCModel }

procedure TTestCRCModel.TearDown;
begin
  FCRC := Nil;
  inherited;

end;

procedure TTestCRCModel.TestAnotherChunkedDataIncrementalHash;
var
  Idx: TCRCStandard;
  temp: String;
  x, size, i: Int32;
begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
    begin
      FCRC := THashFactory.TChecksum.CreateCRC(Idx);
      FCRC.Initialize;

      i := size;
      while i < System.Length(FChunkedData) do
      begin
        temp := System.Copy(FChunkedData, (i - size) + 1, size);
        FCRC.TransformString(temp, TEncoding.UTF8);

        System.Inc(i, size);
      end;
      temp := System.Copy(FChunkedData, (i - size) + 1,
        System.Length(FChunkedData) - ((i - size)));
      FCRC.TransformString(temp, TEncoding.UTF8);

      FActualString := FCRC.TransformFinal().ToString();

      FExpectedString := THashFactory.TChecksum.CreateCRC(Idx)
        .ComputeString(FChunkedData, TEncoding.UTF8).ToString();

      CheckEquals(FExpectedString, FActualString,
        Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
        FCRC.Name]));

    end;
  end;

end;

procedure TTestCRCModel.TestCheckValue;
var
  Idx: TCRCStandard;
  tmp: String;
begin
  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.CreateCRC(Idx);

    FExpectedString := IntToHex(((FCRC as ICRC).CheckValue), 16);

    tmp := FCRC.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
      FCRC.Name]));

  end;

end;

procedure TTestCRCModel.TestCheckValueWithIncrementalHash;
var
  Idx: TCRCStandard;
  tmp: String;
begin
  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.CreateCRC(Idx);

    FCRC.Initialize();

    FExpectedString := IntToHex(((FCRC as ICRC).CheckValue), 16);

    FCRC.TransformString(System.Copy(FOnetoNine, 1, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(FOnetoNine, 4, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(FOnetoNine, 7, 3), TEncoding.UTF8);

    FHashResult := FCRC.TransformFinal();

    tmp := FHashResult.ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
      FCRC.Name]));

  end;

end;

procedure TTestCRCModel.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
  Idx: TCRCStandard;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);

  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    Original := THashFactory.TChecksum.CreateCRC(Idx);
    Original.Initialize;

    Original.TransformBytes(ChunkOne);
    // Make Copy Of Current State
    Copy := Original.Clone();
    Original.TransformBytes(ChunkTwo);
    FExpectedString := Original.TransformFinal().ToString();
    Copy.TransformBytes(ChunkTwo);
    FActualString := Copy.TransformFinal().ToString();

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
      Original.Name]));
  end;
end;

procedure TTestCRCModel.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
  Idx: TCRCStandard;
begin
  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    Original := THashFactory.TChecksum.CreateCRC(Idx);
    Original.Initialize;
    Original.BufferSize := (64 * 1024); // 64Kb
    // Make Copy Of Current State
    Copy := Original.Clone();
    Copy.BufferSize := (128 * 1024); // 128Kb

    CheckNotEquals(Original.BufferSize, Copy.BufferSize,
      Format('Expected %d but got %d. %s', [Original.BufferSize,
      Copy.BufferSize, Original.Name]));
  end;
end;

{ TTestAlder32 }

procedure TTestAlder32.SetUp;
begin
  inherited;
  FAdler32 := THashFactory.TChecksum.CreateAdler32();
end;

procedure TTestAlder32.TearDown;
begin
  FAdler32 := Nil;
  inherited;
end;

procedure TTestAlder32.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FAdler32.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FAdler32;
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

procedure TTestAlder32.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FAdler32;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestAlder32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FAdler32.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FAdler32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestAlder32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FAdler32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TChecksum.CreateAdler32();

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

procedure TTestAlder32.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FAdler32.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Checksum
RegisterTest(TTestCRCModel);
RegisterTest(TTestAlder32);
{$ELSE}
// Checksum
RegisterTest(TTestCRCModel.Suite);
RegisterTest(TTestAlder32.Suite);
{$ENDIF FPC}

end.
