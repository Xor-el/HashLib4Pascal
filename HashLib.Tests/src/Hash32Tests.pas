unit Hash32Tests;

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

// Hash32
type
  TTestAP = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBernstein = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBernstein1 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBKDR = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestDEK = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestDJB = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestELF = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestFNV = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestFNV1a = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestJenkins3 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestJS = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMurmur2 = class(THashWithUInt32AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMurmurHash3_x86_32 = class(THashWithUInt32AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestOneAtTime = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestPJW = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRotating = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRS = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSDBM = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestShiftAndXor = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSuperFast = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestXXHash32 = class(THashWithUInt32AsKeyAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

// Hash32

{ TTestAP }

procedure TTestAP.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateAP();
  HashOfEmptyData := 'AAAAAAAA';
  HashOfDefaultData := '7F14EFED';
  HashOfOnetoNine := 'C0E86BE5';
  HashOfABCDE := '7F6A697A';
end;

procedure TTestAP.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestBernstein }

procedure TTestBernstein.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateBernstein();
  HashOfEmptyData := '00001505';
  HashOfDefaultData := 'C4635F48';
  HashOfOnetoNine := '35CDBB82';
  HashOfABCDE := '0F11B894';
end;

procedure TTestBernstein.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestBernstein1 }

procedure TTestBernstein1.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateBernstein1();
  HashOfEmptyData := '00001505';
  HashOfDefaultData := '2D122E48';
  HashOfOnetoNine := '3BABEA14';
  HashOfABCDE := '0A1DEB04';
end;

procedure TTestBernstein1.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestBKDR }

procedure TTestBKDR.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateBKDR();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '29E11B15';
  HashOfOnetoNine := 'DE43D6D5';
  HashOfABCDE := 'B3EDEA13';
end;

procedure TTestBKDR.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestDEK }

procedure TTestDEK.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateDEK();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '8E01E947';
  HashOfOnetoNine := 'AB4ACBA5';
  HashOfABCDE := '0C2080E5';
end;

procedure TTestDEK.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestDJB }

procedure TTestDJB.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateDJB();
  HashOfEmptyData := '00001505';
  HashOfDefaultData := 'C4635F48';
  HashOfOnetoNine := '35CDBB82';
  HashOfABCDE := '0F11B894';
end;

procedure TTestDJB.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestELF }

procedure TTestELF.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateELF();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '01F5B2CC';
  HashOfOnetoNine := '0678AEE9';
  HashOfABCDE := '006789A5';
end;

procedure TTestELF.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestFNV }

procedure TTestFNV.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateFNV();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := 'BE611EA3';
  HashOfOnetoNine := 'D8D70BF1';
  HashOfABCDE := 'B2B39969';
end;

procedure TTestFNV.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestFNV1a }

procedure TTestFNV1a.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateFNV1a();
  HashOfEmptyData := '811C9DC5';
  HashOfDefaultData := '1892F1F8';
  HashOfOnetoNine := 'BB86B11C';
  HashOfABCDE := '749BCF08';
end;

procedure TTestFNV1a.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestJenkins3 }

procedure TTestJenkins3.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateJenkins3();
  HashOfEmptyData := 'DEADBEEF';
  HashOfDefaultData := 'F0F69CEF';
  HashOfOnetoNine := '845D9A96';
  HashOfABCDE := '026D72DE';
end;

procedure TTestJenkins3.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestJS }

procedure TTestJS.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateJS();
  HashOfEmptyData := '4E67C6A7';
  HashOfDefaultData := '683AFCFE';
  HashOfOnetoNine := '90A4224B';
  HashOfABCDE := '62E8C8B5';
end;

procedure TTestJS.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestMurmur2 }

procedure TTestMurmur2.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateMurmur2();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '30512DE6';
  HashOfOnetoNine := 'DCCB0167';
  HashOfABCDE := '5F09A8DE';
  HashOfDefaultDataWithMaxUInt32AsKey := 'B15D52F0';
end;

procedure TTestMurmur2.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestMurmurHash3_x86_32 }

procedure TTestMurmurHash3_x86_32.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateMurmurHash3_x86_32();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '3D97B9EB';
  HashOfOnetoNine := 'B4FEF382';
  HashOfABCDE := 'E89B9AF6';
  HashOfDefaultDataWithMaxUInt32AsKey := 'B05606FE';
end;

procedure TTestMurmurHash3_x86_32.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestOneAtTime }

procedure TTestOneAtTime.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateOneAtTime();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '4E379A4F';
  HashOfOnetoNine := 'C66B58C5';
  HashOfABCDE := 'B98559FC';
end;

procedure TTestOneAtTime.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestPJW }

procedure TTestPJW.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreatePJW();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '01F5B2CC';
  HashOfOnetoNine := '0678AEE9';
  HashOfABCDE := '006789A5';
end;

procedure TTestPJW.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestRotating }

procedure TTestRotating.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateRotating();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '158009D3';
  HashOfOnetoNine := '1076548B';
  HashOfABCDE := '00674525';
end;

procedure TTestRotating.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestRS }

procedure TTestRS.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateRS();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '9EF98E63';
  HashOfOnetoNine := '704952E9';
  HashOfABCDE := 'A4A13F5D';
end;

procedure TTestRS.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestSDBM }

procedure TTestSDBM.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateSDBM();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := '3001A5C9';
  HashOfOnetoNine := '68A07035';
  HashOfABCDE := 'BD500063';
end;

procedure TTestSDBM.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestShiftAndXor }

procedure TTestShiftAndXor.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateShiftAndXor();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := 'BD0A7DA4';
  HashOfOnetoNine := 'E164F745';
  HashOfABCDE := '0731B823';
end;

procedure TTestShiftAndXor.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestSuperFast }

procedure TTestSuperFast.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateSuperFast();
  HashOfEmptyData := '00000000';
  HashOfDefaultData := 'F00EB3C0';
  HashOfOnetoNine := '9575A2E9';
  HashOfABCDE := '51ED072E';
end;

procedure TTestSuperFast.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

{ TTestXXHash32 }

procedure TTestXXHash32.SetUp;
begin
  inherited;
  HashInstance := THashFactory.THash32.CreateXXHash32();
  HashOfEmptyData := '02CC5D05';
  HashOfDefaultData := '6A1C7A99';
  HashOfOnetoNine := '937BAD67';
  HashOfABCDE := '9738F19B';
  HashOfDefaultDataWithMaxUInt32AsKey := '728C6772';
end;

procedure TTestXXHash32.TearDown;
begin
  HashInstance := Nil;
  inherited;
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
