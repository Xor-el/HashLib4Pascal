unit Hash64Tests;

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
  HlpIHashInfo,
  HlpHashFactory;

// Hash64

type
  TTestFNV64 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestFNV1a64 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestMurmur2_64 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSipHash2_4 = class(THashWithExternalKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestXXHash64 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestXXHash3 = class(THashWithUInt64AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    // Known-answer tests for the long-input paths (values cross-checked
    // against the official xxHash implementation): the self-consistency
    // chunked tests alone cannot catch a wrong SIMD kernel because both
    // sides run the same code.
    procedure TestChunkedDataKnownAnswer;          // 299 bytes: accumulate512
    procedure TestTwoKiBDataKnownAnswer;           // 2048 bytes: scrambleAcc
    procedure TestChunkedDataWithMaxUInt64AsKeyKnownAnswer; // seeded: initSecret
    // An asymmetric key (lo32 <> hi32) - a symmetric one like MaxUInt64
    // cannot catch seed dword swaps or wrong hi/lo pickup in the kernels.
    procedure TestChunkedDataWithAsymmetricKeyKnownAnswer;

  end;

implementation

// Hash64

{ TTestFNV64 }

procedure TTestFNV64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFNV();
  HashOfEmptyData := '0000000000000000';
  HashOfDefaultData := '061A6856F5925B83';
  HashOfOnetoNine := 'B8FB573C21FE68F1';
  HashOfABCDE := '77018B280326F529';
end;

procedure TTestFNV64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestFNV1a64 }

procedure TTestFNV1a64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateFNV1a();
  HashOfEmptyData := 'CBF29CE484222325';
  HashOfDefaultData := '5997E22BF92B0598';
  HashOfOnetoNine := '06D5573923C6CDFC';
  HashOfABCDE := '6348C52D762364A8';
end;

procedure TTestFNV1a64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestMurmur2_64 }

procedure TTestMurmur2_64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateMurmur2();
  HashOfEmptyData := '0000000000000000';
  HashOfDefaultData := '831EFD69DC9E99F9';
  HashOfOnetoNine := '4977490251674330';
  HashOfABCDE := '1182974836D6DBB7';
  HashOfDefaultDataWithMaxUInt64AsKey := 'FF0A342F0AF9ADC6';
end;

procedure TTestMurmur2_64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestSipHash2_4 }

procedure TTestSipHash2_4.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateSipHash2_4();
  HashOfEmptyData := '310E0EDD47DB6F72';
  HashOfDefaultData := '4ED2198628C443AA';
  HashOfOnetoNine := 'FDFE0E0296FC60CA';
  HashOfABCDE := '73B879EAE16345A7';
  HashOfDefaultDataWithExternalKey := '4ED2198628C443AA';
end;

procedure TTestSipHash2_4.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestXXHash64 }

procedure TTestXXHash64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateXXHash64();
  HashOfEmptyData := 'EF46DB3751D8E999';
  HashOfDefaultData := '0F1FADEDD0B77861';
  HashOfOnetoNine := '8CB841DB40E6AE83';
  HashOfABCDE := '07E3670C0C8DC7EB';
  HashOfDefaultDataWithMaxUInt64AsKey := '68DCC1056096A94F';
end;

procedure TTestXXHash64.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

{ TTestXXHash3 }

procedure TTestXXHash3.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash64.CreateXXHash3();
  HashOfEmptyData := '2D06800538D394C2';
  HashOfDefaultData := '73B9276A6BAC2B49';
  HashOfOnetoNine := '72DCB18B67A17DFF';
  HashOfABCDE := '55C65158EE9E652D';
  HashOfDefaultDataWithMaxUInt64AsKey := '153E26503A9470AF';
end;

procedure TTestXXHash3.TearDown;
begin
  HashInstance := nil;
  inherited;
end;

procedure TTestXXHash3.TestChunkedDataKnownAnswer;
begin
  ExpectedString := '3D3D7245B763ACE8';
  ActualString := HashInstance.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestTwoKiBDataKnownAnswer;
var
  LData: TBytes;
  LIdx: Int32;
begin
  System.SetLength(LData, 2048);
  for LIdx := 0 to 2047 do
  begin
    LData[LIdx] := Byte(LIdx and $FF);
  end;
  ExpectedString := 'DD420471FF96BD00';
  ActualString := HashInstance.ComputeBytes(LData).ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestChunkedDataWithAsymmetricKeyKnownAnswer;
var
  LIHashWithKey: IHashWithKey;
  LKey: TBytes;
begin
  // key = $0123456789ABCDEF (little-endian bytes below)
  ExpectedString := 'FBF9CD92890CC82A';
  CheckTrue(Supports(HashInstance, IHashWithKey, LIHashWithKey),
    'HashInstance must support IHashWithKey');
  LKey := TBytes.Create($EF, $CD, $AB, $89, $67, $45, $23, $01);
  LIHashWithKey.Key := LKey;
  ActualString := LIHashWithKey.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestXXHash3.TestChunkedDataWithMaxUInt64AsKeyKnownAnswer;
var
  LIHashWithKey: IHashWithKey;
  LKey: TBytes;
  LIdx: Int32;
begin
  ExpectedString := '7DEFEE70FC854900';
  CheckTrue(Supports(HashInstance, IHashWithKey, LIHashWithKey),
    'HashInstance must support IHashWithKey');
  System.SetLength(LKey, System.SizeOf(UInt64));
  for LIdx := 0 to System.High(LKey) do
  begin
    LKey[LIdx] := $FF;
  end;
  LIHashWithKey.Key := LKey;
  ActualString := LIHashWithKey.ComputeString(ChunkedData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
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
RegisterTest(TTestXXHash3);
{$ELSE}
// Hash64
RegisterTest(TTestFNV64.Suite);
RegisterTest(TTestFNV1a64.Suite);
RegisterTest(TTestMurmur2_64.Suite);
RegisterTest(TTestSipHash2_4.Suite);
RegisterTest(TTestXXHash64.Suite);
RegisterTest(TTestXXHash3.Suite);
{$ENDIF FPC}

end.
