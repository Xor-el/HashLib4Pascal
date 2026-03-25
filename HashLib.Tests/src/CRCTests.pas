unit CRCTests;

interface

uses
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

  TTestCRC32FastModel = class(THashLibAlgorithmTestCase)
  private

    FCRC32Fast: IHash;

  const
    CRC32_PKZIP_Check_Value = UInt32($CBF43926);
    CRC32_CASTAGNOLI_Check_Value = UInt32($E3069283);
    LOW_INDEX = Int32(0);
    HIGH_INDEX = Int32(1);

    function GetWorkingValue(AIndex: Int32): UInt32;

  protected
    procedure TearDown; override;
  published
    procedure TestCheckValue;
    procedure TestCheckValueWithIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

implementation

{ TTestCRCModel }

procedure TTestCRCModel.TearDown;
begin
  FCRC := nil;
  inherited;
end;

procedure TTestCRCModel.TestAnotherChunkedDataIncrementalHash;
var
  LIdx: TCRCStandard;
  LTemp: String;
  LX, LSize, LI: Int32;
begin

  for LX := 0 to System.Pred(System.SizeOf(ChunkSizes)
    div System.SizeOf(Int32)) do
  begin
    LSize := ChunkSizes[LX];
    for LIdx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
    begin
      FCRC := THashFactory.TChecksum.TCRC.CreateCRC(LIdx);
      FCRC.Initialize;

      LI := LSize;
      while LI < System.Length(ChunkedData) do
      begin
        LTemp := System.Copy(ChunkedData, (LI - LSize) + 1, LSize);
        FCRC.TransformString(LTemp, TEncoding.UTF8);

        System.Inc(LI, LSize);
      end;
      LTemp := System.Copy(ChunkedData, (LI - LSize) + 1,
        System.Length(ChunkedData) - ((LI - LSize)));
      FCRC.TransformString(LTemp, TEncoding.UTF8);

      ActualString := FCRC.TransformFinal().ToString();

      ExpectedString := THashFactory.TChecksum.TCRC.CreateCRC(LIdx)
        .ComputeString(ChunkedData, TEncoding.UTF8).ToString();

      CheckEquals(ExpectedString, ActualString,
        Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
        FCRC.Name]));

    end;
  end;

end;

procedure TTestCRCModel.TestCheckValue;
var
  LIdx: TCRCStandard;
  LTmp: String;
  LCRC: ICRC;
begin
  for LIdx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.TCRC.CreateCRC(LIdx);

    CheckTrue(Supports(FCRC, ICRC, LCRC), Format('Expected ICRC from %s',
      [FCRC.Name]));
    ExpectedString := IntToHex(LCRC.CheckValue, 16);

    LTmp := FCRC.ComputeString(OneToNine, TEncoding.UTF8).ToString();

    ActualString := System.StringOfChar('0', 16 - System.Length(LTmp)) + LTmp;

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      FCRC.Name]));

  end;

end;

procedure TTestCRCModel.TestCheckValueWithIncrementalHash;
var
  LIdx: TCRCStandard;
  LTmp: String;
  LCRC: ICRC;
begin
  for LIdx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.TCRC.CreateCRC(LIdx);

    FCRC.Initialize();

    CheckTrue(Supports(FCRC, ICRC, LCRC), Format('Expected ICRC from %s',
      [FCRC.Name]));
    ExpectedString := IntToHex(LCRC.CheckValue, 16);

    FCRC.TransformString(System.Copy(OneToNine, 1, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(OneToNine, 4, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(OneToNine, 7, 3), TEncoding.UTF8);

    LTmp := FCRC.TransformFinal().ToString();

    ActualString := System.StringOfChar('0', 16 - System.Length(LTmp)) + LTmp;

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      FCRC.Name]));

  end;

end;

procedure TTestCRCModel.TestHashCloneIsCorrect;
var
  LOriginal, LCopy: IHash;
  LMainData, LChunkOne, LChunkTwo: TBytes;
  LCount: Int32;
  LIdx: TCRCStandard;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  LCount := System.Length(LMainData) - 3;
  LChunkOne := System.Copy(LMainData, 0, LCount);
  LChunkTwo := System.Copy(LMainData, LCount, System.Length(LMainData) - LCount);

  for LIdx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    LOriginal := THashFactory.TChecksum.TCRC.CreateCRC(LIdx);
    LOriginal.Initialize;

    LOriginal.TransformBytes(LChunkOne);
    // Make Copy Of Current State
    LCopy := LOriginal.Clone();
    LOriginal.TransformBytes(LChunkTwo);
    ExpectedString := LOriginal.TransformFinal().ToString();
    LCopy.TransformBytes(LChunkTwo);
    ActualString := LCopy.TransformFinal().ToString();

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      LOriginal.Name]));
  end;
end;

procedure TTestCRCModel.TestHashCloneIsUnique;
var
  LOriginal, LCopy: IHash;
  LIdx: TCRCStandard;
begin
  for LIdx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    LOriginal := THashFactory.TChecksum.TCRC.CreateCRC(LIdx);
    LOriginal.Initialize;
    LOriginal.BufferSize := (64 * 1024); // 64Kb
    // Make Copy Of Current State
    LCopy := LOriginal.Clone();
    LCopy.BufferSize := (128 * 1024); // 128Kb

    CheckNotEquals(LOriginal.BufferSize, LCopy.BufferSize,
      Format('Expected %d but got %d. %s', [LOriginal.BufferSize,
      LCopy.BufferSize, LOriginal.Name]));
  end;
end;

{ TTestCRC32FastModel }

function TTestCRC32FastModel.GetWorkingValue(AIndex: Int32): UInt32;
begin
  case AIndex of
    0:
      begin
        FCRC32Fast := THashFactory.TChecksum.TCRC.CreateCRC32_PKZIP();
        Result := CRC32_PKZIP_Check_Value;
      end;
    1:
      begin
        FCRC32Fast := THashFactory.TChecksum.TCRC.CreateCRC32_CASTAGNOLI();
        Result := CRC32_CASTAGNOLI_Check_Value;
      end
  else
    begin
      raise Exception.CreateFmt('Invalid Index, "%d"', [AIndex]);
    end;
  end;
end;

procedure TTestCRC32FastModel.TearDown;
begin
  FCRC32Fast := nil;
  inherited;
end;

procedure TTestCRC32FastModel.TestAnotherChunkedDataIncrementalHash;
var
  LTemp: String;
  LX, LSize, LI, LIdx: Int32;
begin

  for LX := 0 to System.Pred(System.SizeOf(ChunkSizes)
    div System.SizeOf(Int32)) do
  begin
    LSize := ChunkSizes[LX];

    for LIdx := LOW_INDEX to HIGH_INDEX do
    begin

      GetWorkingValue(LIdx);

      FCRC32Fast.Initialize;

      LI := LSize;
      while LI < System.Length(ChunkedData) do
      begin
        LTemp := System.Copy(ChunkedData, (LI - LSize) + 1, LSize);
        FCRC32Fast.TransformString(LTemp, TEncoding.UTF8);

        System.Inc(LI, LSize);
      end;
      LTemp := System.Copy(ChunkedData, (LI - LSize) + 1,
        System.Length(ChunkedData) - ((LI - LSize)));
      FCRC32Fast.TransformString(LTemp, TEncoding.UTF8);

      ActualString := FCRC32Fast.TransformFinal().ToString();

      ExpectedString := FCRC32Fast.ComputeString(ChunkedData, TEncoding.UTF8)
        .ToString();

      CheckEquals(ExpectedString, ActualString,
        Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
        FCRC32Fast.Name]));

    end;

  end;

end;

procedure TTestCRC32FastModel.TestCheckValue;
var
  LIdx: Int32;
  LCheckValue: UInt32;
  LTmp: String;
begin

  for LIdx := LOW_INDEX to HIGH_INDEX do
  begin

    LCheckValue := GetWorkingValue(LIdx);

    ExpectedString := IntToHex(LCheckValue, 16);

    LTmp := FCRC32Fast.ComputeString(OneToNine, TEncoding.UTF8).ToString();

    ActualString := System.StringOfChar('0', 16 - System.Length(LTmp)) + LTmp;

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      FCRC32Fast.Name]));

  end;

end;

procedure TTestCRC32FastModel.TestCheckValueWithIncrementalHash;
var
  LIdx: Int32;
  LCheckValue: UInt32;
  LTmp: String;
begin

  for LIdx := LOW_INDEX to HIGH_INDEX do
  begin

    LCheckValue := GetWorkingValue(LIdx);

    FCRC32Fast.Initialize();

    ExpectedString := IntToHex(LCheckValue, 16);

    FCRC32Fast.TransformString(System.Copy(OneToNine, 1, 3), TEncoding.UTF8);
    FCRC32Fast.TransformString(System.Copy(OneToNine, 4, 3), TEncoding.UTF8);
    FCRC32Fast.TransformString(System.Copy(OneToNine, 7, 3), TEncoding.UTF8);

    LTmp := FCRC32Fast.TransformFinal().ToString();

    ActualString := System.StringOfChar('0', 16 - System.Length(LTmp)) + LTmp;

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      FCRC32Fast.Name]));

  end;

end;

procedure TTestCRC32FastModel.TestHashCloneIsCorrect;
var
  LOriginal, LCopy: IHash;
  LMainData, LChunkOne, LChunkTwo: TBytes;
  LCount, LIdx: Int32;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  LCount := System.Length(LMainData) - 3;
  LChunkOne := System.Copy(LMainData, 0, LCount);
  LChunkTwo := System.Copy(LMainData, LCount, System.Length(LMainData) - LCount);

  for LIdx := LOW_INDEX to HIGH_INDEX do
  begin
    GetWorkingValue(LIdx);
    LOriginal := FCRC32Fast;
    LOriginal.Initialize;

    LOriginal.TransformBytes(LChunkOne);
    // Make Copy Of Current State
    LCopy := LOriginal.Clone();
    LOriginal.TransformBytes(LChunkTwo);
    ExpectedString := LOriginal.TransformFinal().ToString();
    LCopy.TransformBytes(LChunkTwo);
    ActualString := LCopy.TransformFinal().ToString();

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s. %s', [ExpectedString, ActualString,
      LOriginal.Name]));
  end;
end;

procedure TTestCRC32FastModel.TestHashCloneIsUnique;
var
  LOriginal, LCopy: IHash;
  LIdx: Int32;
begin
  for LIdx := LOW_INDEX to HIGH_INDEX do
  begin
    GetWorkingValue(LIdx);
    LOriginal := FCRC32Fast;
    LOriginal.Initialize;
    LOriginal.BufferSize := (64 * 1024); // 64Kb
    // Make Copy Of Current State
    LCopy := LOriginal.Clone();
    LCopy.BufferSize := (128 * 1024); // 128Kb

    CheckNotEquals(LOriginal.BufferSize, LCopy.BufferSize,
      Format('Expected %d but got %d. %s', [LOriginal.BufferSize,
      LCopy.BufferSize, LOriginal.Name]));
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestCRCModel);
RegisterTest(TTestCRC32FastModel);
{$ELSE}
  RegisterTest(TTestCRCModel.Suite);
RegisterTest(TTestCRC32FastModel.Suite);
{$ENDIF FPC}

end.
