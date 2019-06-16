unit CRCTests;

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
      FCRC := THashFactory.TCRC.CreateCRC(Idx);
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

      FExpectedString := THashFactory.TCRC.CreateCRC(Idx)
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
    FCRC := THashFactory.TCRC.CreateCRC(Idx);

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
    FCRC := THashFactory.TCRC.CreateCRC(Idx);

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
    Original := THashFactory.TCRC.CreateCRC(Idx);
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
    Original := THashFactory.TCRC.CreateCRC(Idx);
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

{ TTestCRC32FastModel }

function TTestCRC32FastModel.GetWorkingValue(AIndex: Int32): UInt32;
begin
  case AIndex of
    0:
      begin
        FCRC32Fast := THashFactory.TCRC.CreateCRC32_PKZIP();
        Result := CRC32_PKZIP_Check_Value;
      end;
    1:
      begin
        FCRC32Fast := THashFactory.TCRC.CreateCRC32_CASTAGNOLI();
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
  FCRC32Fast := Nil;
  inherited;
end;

procedure TTestCRC32FastModel.TestAnotherChunkedDataIncrementalHash;
var
  temp: String;
  x, size, i, Idx: Int32;
begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];

    for Idx := LOW_INDEX to HIGH_INDEX do
    begin

      GetWorkingValue(Idx);

      FCRC32Fast.Initialize;

      i := size;
      while i < System.Length(FChunkedData) do
      begin
        temp := System.Copy(FChunkedData, (i - size) + 1, size);
        FCRC32Fast.TransformString(temp, TEncoding.UTF8);

        System.Inc(i, size);
      end;
      temp := System.Copy(FChunkedData, (i - size) + 1,
        System.Length(FChunkedData) - ((i - size)));
      FCRC32Fast.TransformString(temp, TEncoding.UTF8);

      FActualString := FCRC32Fast.TransformFinal().ToString();

      FExpectedString := FCRC32Fast.ComputeString(FChunkedData, TEncoding.UTF8)
        .ToString();

      CheckEquals(FExpectedString, FActualString,
        Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
        FCRC32Fast.Name]));

    end;

  end;

end;

procedure TTestCRC32FastModel.TestCheckValue;
var
  Idx: Int32;
  Check_Value: UInt32;
  tmp: String;
begin

  for Idx := LOW_INDEX to HIGH_INDEX do
  begin

    Check_Value := GetWorkingValue(Idx);

    FExpectedString := IntToHex(Check_Value, 16);

    tmp := FCRC32Fast.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
      FCRC32Fast.Name]));

  end;

end;

procedure TTestCRC32FastModel.TestCheckValueWithIncrementalHash;
var
  Idx: Int32;
  Check_Value: UInt32;
  tmp: String;
begin

  for Idx := LOW_INDEX to HIGH_INDEX do
  begin

    Check_Value := GetWorkingValue(Idx);

    FCRC32Fast.Initialize();

    FExpectedString := IntToHex(Check_Value, 16);

    FCRC32Fast.TransformString(System.Copy(FOnetoNine, 1, 3), TEncoding.UTF8);
    FCRC32Fast.TransformString(System.Copy(FOnetoNine, 4, 3), TEncoding.UTF8);
    FCRC32Fast.TransformString(System.Copy(FOnetoNine, 7, 3), TEncoding.UTF8);

    FHashResult := FCRC32Fast.TransformFinal();

    tmp := FHashResult.ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s. %s', [FExpectedString, FActualString,
      FCRC32Fast.Name]));

  end;

end;

procedure TTestCRC32FastModel.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count, Idx: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);

  for Idx := LOW_INDEX to HIGH_INDEX do
  begin
    GetWorkingValue(Idx);
    Original := FCRC32Fast;
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

procedure TTestCRC32FastModel.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
  Idx: Int32;
begin
  for Idx := LOW_INDEX to HIGH_INDEX do
  begin
    GetWorkingValue(Idx);
    Original := FCRC32Fast;
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
