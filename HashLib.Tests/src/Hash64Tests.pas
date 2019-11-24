unit Hash64Tests;

interface

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HashLibTestBase,
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
  HashInstance := Nil;
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
  HashInstance := Nil;
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
  HashInstance := Nil;
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
  HashInstance := Nil;
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
  HashInstance := Nil;
  inherited;
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
