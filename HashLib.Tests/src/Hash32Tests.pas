unit Hash32Tests;

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

// Hash32

type

  TTestAP = class(THashLibAlgorithmTestCase)

  private

    FAP: IHash;

  const
    FExpectedHashOfEmptyData: String = 'AAAAAAAA';
    FExpectedHashOfDefaultData: String = '7F14EFED';
    FExpectedHashOfOnetoNine: String = 'C0E86BE5';
    FExpectedHashOfabcde: String = '7F6A697A';

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

  TTestBernstein = class(THashLibAlgorithmTestCase)

  private

    FBernstein: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = 'C4635F48';
    FExpectedHashOfOnetoNine: String = '35CDBB82';
    FExpectedHashOfabcde: String = '0F11B894';

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

  TTestBernstein1 = class(THashLibAlgorithmTestCase)

  private

    FBernstein1: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = '2D122E48';
    FExpectedHashOfOnetoNine: String = '3BABEA14';
    FExpectedHashOfabcde: String = '0A1DEB04';

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

  TTestBKDR = class(THashLibAlgorithmTestCase)

  private

    FBKDR: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '29E11B15';
    FExpectedHashOfOnetoNine: String = 'DE43D6D5';
    FExpectedHashOfabcde: String = 'B3EDEA13';

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

  TTestDEK = class(THashLibAlgorithmTestCase)

  private

    FDEK: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '8E01E947';
    FExpectedHashOfOnetoNine: String = 'AB4ACBA5';
    FExpectedHashOfabcde: String = '0C2080E5';

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

  TTestDJB = class(THashLibAlgorithmTestCase)

  private

    FDJB: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = 'C4635F48';
    FExpectedHashOfOnetoNine: String = '35CDBB82';
    FExpectedHashOfabcde: String = '0F11B894';

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

  TTestELF = class(THashLibAlgorithmTestCase)

  private

    FELF: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '01F5B2CC';
    FExpectedHashOfOnetoNine: String = '0678AEE9';
    FExpectedHashOfabcde: String = '006789A5';

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

  TTestFNV = class(THashLibAlgorithmTestCase)

  private

    FFNV: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'BE611EA3';
    FExpectedHashOfOnetoNine: String = 'D8D70BF1';
    FExpectedHashOfabcde: String = 'B2B39969';

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

  TTestFNV1a = class(THashLibAlgorithmTestCase)

  private

    FFNV1a: IHash;

  const
    FExpectedHashOfEmptyData: String = '811C9DC5';
    FExpectedHashOfDefaultData: String = '1892F1F8';
    FExpectedHashOfOnetoNine: String = 'BB86B11C';
    FExpectedHashOfabcde: String = '749BCF08';

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

  TTestJenkins3 = class(THashLibAlgorithmTestCase)

  private

    FJenkins3: IHash;

  const
    FExpectedHashOfEmptyData: String = 'DEADBEEF';
    FExpectedHashOfDefaultData: String = 'F0F69CEF';
    FExpectedHashOfOnetoNine: String = '845D9A96';
    FExpectedHashOfabcde: String = '026D72DE';

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

  TTestJS = class(THashLibAlgorithmTestCase)

  private

    FJS: IHash;

  const
    FExpectedHashOfEmptyData: String = '4E67C6A7';
    FExpectedHashOfDefaultData: String = '683AFCFE';
    FExpectedHashOfOnetoNine: String = '90A4224B';
    FExpectedHashOfabcde: String = '62E8C8B5';

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

  TTestMurmur2 = class(THashLibAlgorithmTestCase)

  private

    FMurmur2: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '30512DE6';
    FExpectedHashOfOnetoNine: String = 'DCCB0167';
    FExpectedHashOfabcde: String = '5F09A8DE';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = 'B15D52F0';

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

  TTestMurmurHash3_x86_32 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x86_32: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '3D97B9EB';
    FExpectedHashOfRandomString: String = 'A8D02B9A';
    FExpectedHashOfZerotoFour: String = '19D02170';
    FExpectedHashOfEmptyDataWithOneAsKey: String = '514E28B7';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = 'B05606FE';

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

  TTestOneAtTime = class(THashLibAlgorithmTestCase)

  private

    FOneAtTime: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '4E379A4F';
    FExpectedHashOfOnetoNine: String = 'C66B58C5';
    FExpectedHashOfabcde: String = 'B98559FC';

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

  TTestPJW = class(THashLibAlgorithmTestCase)

  private

    FPJW: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '01F5B2CC';
    FExpectedHashOfOnetoNine: String = '0678AEE9';
    FExpectedHashOfabcde: String = '006789A5';

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

  TTestRotating = class(THashLibAlgorithmTestCase)

  private

    FRotating: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '158009D3';
    FExpectedHashOfOnetoNine: String = '1076548B';
    FExpectedHashOfabcde: String = '00674525';

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

  TTestRS = class(THashLibAlgorithmTestCase)

  private

    FRS: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '9EF98E63';
    FExpectedHashOfOnetoNine: String = '704952E9';
    FExpectedHashOfabcde: String = 'A4A13F5D';

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

  TTestSDBM = class(THashLibAlgorithmTestCase)

  private

    FSDBM: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '3001A5C9';
    FExpectedHashOfOnetoNine: String = '68A07035';
    FExpectedHashOfabcde: String = 'BD500063';

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

  TTestShiftAndXor = class(THashLibAlgorithmTestCase)

  private

    FShiftAndXor: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'BD0A7DA4';
    FExpectedHashOfOnetoNine: String = 'E164F745';
    FExpectedHashOfabcde: String = '0731B823';

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

  TTestSuperFast = class(THashLibAlgorithmTestCase)

  private

    FSuperFast: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'F00EB3C0';
    FExpectedHashOfOnetoNine: String = '9575A2E9';
    FExpectedHashOfabcde: String = '51ED072E';

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

  TTestXXHash32 = class(THashLibAlgorithmTestCase)

  private

    FXXHash32: IHash;

  const
    FExpectedHashOfEmptyData: String = '02CC5D05';
    FExpectedHashOfDefaultData: String = '6A1C7A99';
    FExpectedHashOfRandomString: String = 'CE8CF448';
    FExpectedHashOfZerotoFour: String = '8AA3B71C';
    FExpectedHashOfEmptyDataWithOneAsKey: String = '0B2CB792';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = '728C6772';

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
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

implementation

// Hash32

{ TTestAP }

procedure TTestAP.SetUp;
begin
  inherited;
  FAP := THashFactory.THash32.CreateAP();
end;

procedure TTestAP.TearDown;
begin
  FAP := Nil;
  inherited;
end;

procedure TTestAP.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FAP.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FAP;
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

procedure TTestAP.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FAP;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestAP.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FAP.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FAP.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestAP.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FAP.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateAP();

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

procedure TTestAP.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FAP.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBernstein }

procedure TTestBernstein.SetUp;
begin
  inherited;
  FBernstein := THashFactory.THash32.CreateBernstein();
end;

procedure TTestBernstein.TearDown;
begin
  FBernstein := Nil;
  inherited;
end;

procedure TTestBernstein.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBernstein.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FBernstein;
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

procedure TTestBernstein.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FBernstein;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestBernstein.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBernstein.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBernstein.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBernstein.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBernstein.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBernstein();

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

procedure TTestBernstein.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBernstein.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBernstein1 }

procedure TTestBernstein1.SetUp;
begin
  inherited;
  FBernstein1 := THashFactory.THash32.CreateBernstein1();
end;

procedure TTestBernstein1.TearDown;
begin
  FBernstein1 := Nil;
  inherited;
end;

procedure TTestBernstein1.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBernstein1.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FBernstein1;
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

procedure TTestBernstein1.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FBernstein1;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestBernstein1.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBernstein1.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBernstein1.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBernstein1.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBernstein1.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBernstein1();

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

procedure TTestBernstein1.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBernstein1.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBKDR }

procedure TTestBKDR.SetUp;
begin
  inherited;
  FBKDR := THashFactory.THash32.CreateBKDR();
end;

procedure TTestBKDR.TearDown;
begin
  FBKDR := Nil;
  inherited;
end;

procedure TTestBKDR.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBKDR.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FBKDR;
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

procedure TTestBKDR.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FBKDR;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestBKDR.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBKDR.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBKDR.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBKDR.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBKDR.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBKDR();

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

procedure TTestBKDR.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBKDR.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestDEK }

procedure TTestDEK.SetUp;
begin
  inherited;
  FDEK := THashFactory.THash32.CreateDEK();
end;

procedure TTestDEK.TearDown;
begin
  FDEK := Nil;
  inherited;
end;

procedure TTestDEK.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FDEK.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FDEK;
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

procedure TTestDEK.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FDEK;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestDEK.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FDEK.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FDEK.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestDEK.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FDEK.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateDEK();

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

procedure TTestDEK.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FDEK.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestDJB }

procedure TTestDJB.SetUp;
begin
  inherited;
  FDJB := THashFactory.THash32.CreateDJB();
end;

procedure TTestDJB.TearDown;
begin
  FDJB := Nil;
  inherited;
end;

procedure TTestDJB.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FDJB.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FDJB;
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

procedure TTestDJB.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FDJB;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestDJB.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FDJB.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FDJB.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestDJB.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FDJB.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateDJB();

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

procedure TTestDJB.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FDJB.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestELF }

procedure TTestELF.SetUp;
begin
  inherited;
  FELF := THashFactory.THash32.CreateELF();
end;

procedure TTestELF.TearDown;
begin
  FELF := Nil;
  inherited;
end;

procedure TTestELF.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FELF.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FELF;
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

procedure TTestELF.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FELF;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestELF.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FELF.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FELF.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestELF.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FELF.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateELF();

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

procedure TTestELF.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FELF.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV }

procedure TTestFNV.SetUp;
begin
  inherited;
  FFNV := THashFactory.THash32.CreateFNV();
end;

procedure TTestFNV.TearDown;
begin
  FFNV := Nil;
  inherited;
end;

procedure TTestFNV.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FFNV;
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

procedure TTestFNV.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FFNV;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestFNV.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateFNV();

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

procedure TTestFNV.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV1a }

procedure TTestFNV1a.SetUp;
begin
  inherited;
  FFNV1a := THashFactory.THash32.CreateFNV1a();
end;

procedure TTestFNV1a.TearDown;
begin
  FFNV1a := Nil;
  inherited;
end;

procedure TTestFNV1a.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV1a.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FFNV1a;
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

procedure TTestFNV1a.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FFNV1a;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestFNV1a.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV1a.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV1a.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV1a.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV1a.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateFNV1a();

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

procedure TTestFNV1a.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV1a.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestJenkins3 }

procedure TTestJenkins3.SetUp;
begin
  inherited;
  FJenkins3 := THashFactory.THash32.CreateJenkins3();
end;

procedure TTestJenkins3.TearDown;
begin
  FJenkins3 := Nil;
  inherited;
end;

procedure TTestJenkins3.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FJenkins3.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FJenkins3;
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

procedure TTestJenkins3.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FJenkins3;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestJenkins3.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FJenkins3.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FJenkins3.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestJenkins3.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FJenkins3.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateJenkins3();

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

procedure TTestJenkins3.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FJenkins3.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestJS }

procedure TTestJS.SetUp;
begin
  inherited;
  FJS := THashFactory.THash32.CreateJS();
end;

procedure TTestJS.TearDown;
begin
  FJS := Nil;
  inherited;
end;

procedure TTestJS.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FJS.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FJS;
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

procedure TTestJS.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FJS;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestJS.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FJS.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FJS.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestJS.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FJS.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateJS();

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

procedure TTestJS.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FJS.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmur2 }

procedure TTestMurmur2.SetUp;
begin
  inherited;
  FMurmur2 := THashFactory.THash32.CreateMurmur2();
end;

procedure TTestMurmur2.TearDown;
begin
  FMurmur2 := Nil;
  inherited;
end;

procedure TTestMurmur2.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMurmur2.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMurmur2;
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

procedure TTestMurmur2.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMurmur2;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMurmur2.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmur2.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmur2.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmur2.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmur2.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateMurmur2();

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

procedure TTestMurmur2.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMurmur2.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestWithDifferentKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmur2 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmurHash3_x86_32 }

procedure TTestMurmurHash3_x86_32.SetUp;
begin
  inherited;
  FMurmurHash3_x86_32 := THashFactory.THash32.CreateMurmurHash3_x86_32();

end;

procedure TTestMurmurHash3_x86_32.TearDown;
begin
  FMurmurHash3_x86_32 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x86_32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x86_32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x86_32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x86_32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x86_32.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x86_32.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x86_32.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x86_32.TransformFinal().ToString();
    FExpectedString := THashFactory.THash32.CreateMurmurHash3_x86_32.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x86_32.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMurmurHash3_x86_32;
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

procedure TTestMurmurHash3_x86_32.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMurmurHash3_x86_32;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMurmurHash3_x86_32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x86_32.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateMurmurHash3_x86_32();

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

procedure TTestMurmurHash3_x86_32.TestIndexChunkedDataIncrementalHash;
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
    FMurmurHash3_x86_32.Initialize();

    FMurmurHash3_x86_32.TransformBytes(ChunkedDataBytes, i, Count);

    FActualString := FMurmurHash3_x86_32.TransformFinal().ToString();
    FExpectedString := THashFactory.THash32.CreateMurmurHash3_x86_32.
      ComputeBytes(temp).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestMurmurHash3_x86_32.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x86_32.ComputeString(FRandomStringRecord,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x86_32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x86_32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x86_32.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestOneAtTime }

procedure TTestOneAtTime.SetUp;
begin
  inherited;
  FOneAtTime := THashFactory.THash32.CreateOneAtTime();
end;

procedure TTestOneAtTime.TearDown;
begin
  FOneAtTime := Nil;
  inherited;
end;

procedure TTestOneAtTime.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FOneAtTime.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FOneAtTime;
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

procedure TTestOneAtTime.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FOneAtTime;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestOneAtTime.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FOneAtTime.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FOneAtTime.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestOneAtTime.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FOneAtTime.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateOneAtTime();

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

procedure TTestOneAtTime.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FOneAtTime.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestPJW }

procedure TTestPJW.SetUp;
begin
  inherited;
  FPJW := THashFactory.THash32.CreatePJW();
end;

procedure TTestPJW.TearDown;
begin
  FPJW := Nil;
  inherited;
end;

procedure TTestPJW.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FPJW.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FPJW;
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

procedure TTestPJW.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FPJW;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestPJW.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FPJW.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FPJW.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestPJW.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FPJW.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreatePJW();

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

procedure TTestPJW.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FPJW.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRotating }

procedure TTestRotating.SetUp;
begin
  inherited;
  FRotating := THashFactory.THash32.CreateRotating();
end;

procedure TTestRotating.TearDown;
begin
  FRotating := Nil;
  inherited;
end;

procedure TTestRotating.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRotating.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRotating;
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

procedure TTestRotating.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRotating;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRotating.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRotating.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRotating.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRotating.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRotating.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateRotating();

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

procedure TTestRotating.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRotating.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRS }

procedure TTestRS.SetUp;
begin
  inherited;
  FRS := THashFactory.THash32.CreateRS();
end;

procedure TTestRS.TearDown;
begin
  FRS := Nil;
  inherited;
end;

procedure TTestRS.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRS.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRS;
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

procedure TTestRS.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRS;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRS.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRS.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRS.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRS.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRS.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateRS();

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

procedure TTestRS.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRS.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSDBM }

procedure TTestSDBM.SetUp;
begin
  inherited;
  FSDBM := THashFactory.THash32.CreateSDBM();
end;

procedure TTestSDBM.TearDown;
begin
  FSDBM := Nil;
  inherited;
end;

procedure TTestSDBM.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSDBM.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSDBM;
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

procedure TTestSDBM.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSDBM;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSDBM.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSDBM.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSDBM.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSDBM.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSDBM.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateSDBM();

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

procedure TTestSDBM.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSDBM.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestShiftAndXor }

procedure TTestShiftAndXor.SetUp;
begin
  inherited;
  FShiftAndXor := THashFactory.THash32.CreateShiftAndXor();
end;

procedure TTestShiftAndXor.TearDown;
begin
  FShiftAndXor := Nil;
  inherited;
end;

procedure TTestShiftAndXor.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FShiftAndXor.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FShiftAndXor;
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

procedure TTestShiftAndXor.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FShiftAndXor;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestShiftAndXor.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FShiftAndXor.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FShiftAndXor.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestShiftAndXor.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FShiftAndXor.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateShiftAndXor();

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

procedure TTestShiftAndXor.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FShiftAndXor.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSuperFast }

procedure TTestSuperFast.SetUp;
begin
  inherited;
  FSuperFast := THashFactory.THash32.CreateSuperFast();
end;

procedure TTestSuperFast.TearDown;
begin
  FSuperFast := Nil;
  inherited;
end;

procedure TTestSuperFast.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSuperFast.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSuperFast;
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

procedure TTestSuperFast.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSuperFast;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSuperFast.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSuperFast.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSuperFast.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSuperFast.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSuperFast.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateSuperFast();

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

procedure TTestSuperFast.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSuperFast.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestXXHash32 }

procedure TTestXXHash32.SetUp;
begin
  inherited;
  FXXHash32 := THashFactory.THash32.CreateXXHash32();

end;

procedure TTestXXHash32.TearDown;
begin
  FXXHash32 := Nil;
  inherited;
end;

procedure TTestXXHash32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FXXHash32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestXXHash32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FXXHash32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FXXHash32.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FXXHash32.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FXXHash32.TransformString(temp, TEncoding.UTF8);

    FActualString := FXXHash32.TransformFinal().ToString();
    FExpectedString := THashFactory.THash32.CreateXXHash32.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestXXHash32.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FXXHash32;
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

procedure TTestXXHash32.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FXXHash32;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestXXHash32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FXXHash32.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateXXHash32();

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

procedure TTestXXHash32.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FXXHash32.ComputeString(FRandomStringTobacco, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FXXHash32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FXXHash32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FXXHash32.ComputeString(FZerotoFour, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Hash32
RegisterTest(TTestAP);
RegisterTest(TTestBernstein);
RegisterTest(TTestBernstein1);
RegisterTest(TTestBKDR);
RegisterTest(TTestDEK);
RegisterTest(TTestDJB);
RegisterTest(TTestELF);
RegisterTest(TTestFNV);
RegisterTest(TTestFNV1a);
RegisterTest(TTestJenkins3);
RegisterTest(TTestJS);
RegisterTest(TTestMurmur2);
RegisterTest(TTestMurmurHash3_x86_32);
RegisterTest(TTestOneAtTime);
RegisterTest(TTestPJW);
RegisterTest(TTestRotating);
RegisterTest(TTestRS);
RegisterTest(TTestSDBM);
RegisterTest(TTestShiftAndXor);
RegisterTest(TTestSuperFast);
RegisterTest(TTestXXHash32);
{$ELSE}
// Hash32
RegisterTest(TTestAP.Suite);
RegisterTest(TTestBernstein.Suite);
RegisterTest(TTestBernstein1.Suite);
RegisterTest(TTestBKDR.Suite);
RegisterTest(TTestDEK.Suite);
RegisterTest(TTestDJB.Suite);
RegisterTest(TTestELF.Suite);
RegisterTest(TTestFNV.Suite);
RegisterTest(TTestFNV1a.Suite);
RegisterTest(TTestJenkins3.Suite);
RegisterTest(TTestJS.Suite);
RegisterTest(TTestMurmur2.Suite);
RegisterTest(TTestMurmurHash3_x86_32.Suite);
RegisterTest(TTestOneAtTime.Suite);
RegisterTest(TTestPJW.Suite);
RegisterTest(TTestRotating.Suite);
RegisterTest(TTestRS.Suite);
RegisterTest(TTestSDBM.Suite);
RegisterTest(TTestShiftAndXor.Suite);
RegisterTest(TTestSuperFast.Suite);
RegisterTest(TTestXXHash32.Suite);
{$ENDIF FPC}

end.
