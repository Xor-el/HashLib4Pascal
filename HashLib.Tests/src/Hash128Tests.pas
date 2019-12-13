unit Hash128Tests;

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

// Hash128

type
  TTestMurmurHash3_x86_128 = class(THashWithUInt32AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMurmurHash3_x64_128 = class(THashWithUInt32AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSipHash128_2_4 = class(THashWithExternalKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

// Hash128

{ TTestMurmurHash3_x86_128 }

procedure TTestMurmurHash3_x86_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash128.CreateMurmurHash3_x86_128();
  HashOfEmptyData := '00000000000000000000000000000000';
  HashOfDefaultData := 'B35E1058738E067BF637B17075F14B8B';
  HashOfOnetoNine := 'C65876BB119A1552C5E3E5D7A9168CA4';
  HashOfABCDE := 'C5402EFB5D24C5BC5A7201775A720177';
  HashOfDefaultDataWithMaxUInt32AsKey := '55315FA9E8129C7390C080B8FDB1C972';
end;

procedure TTestMurmurHash3_x86_128.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestMurmurHash3_x64_128 }

procedure TTestMurmurHash3_x64_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash128.CreateMurmurHash3_x64_128();
  HashOfEmptyData := '00000000000000000000000000000000';
  HashOfDefaultData := '705BD3C954B94BE056F06B68662E6364';
  HashOfOnetoNine := '3C84645EDB66CCA499F8FAC73A1EA105';
  HashOfABCDE := '2036D091F496BBB8C5C7EEA04BCFEC8C';
  HashOfDefaultDataWithMaxUInt32AsKey := 'ADFD14988FB1F8582A1B67C1BBACC218';
end;

procedure TTestMurmurHash3_x64_128.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestSipHash128_2_4 }

procedure TTestSipHash128_2_4.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash128.CreateSipHash128_2_4();
  HashOfEmptyData := 'A3817F04BA25A8E66DF67214C7550293';
  HashOfDefaultData := '312C82F65D5A567B333CD772F045E36C';
  HashOfOnetoNine := 'CE94828373303D1AB5FC781744AD71CE';
  HashOfABCDE := 'EB8662A95F0D718811E7CEDBDF03541C';
  HashOfDefaultDataWithExternalKey := '312C82F65D5A567B333CD772F045E36C';
end;

procedure TTestSipHash128_2_4.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Hash128
RegisterTest(TTestMurmurHash3_x86_128);
RegisterTest(TTestMurmurHash3_x64_128);
RegisterTest(TTestSipHash128_2_4);
{$ELSE}
// Hash128
RegisterTest(TTestMurmurHash3_x86_128.Suite);
RegisterTest(TTestMurmurHash3_x64_128.Suite);
RegisterTest(TTestSipHash128_2_4.Suite);
{$ENDIF FPC}

end.
