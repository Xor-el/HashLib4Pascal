unit ChecksumTests;

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

type
  TTestAlder32 = class(THashAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

{ TTestAlder32 }

procedure TTestAlder32.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TChecksum.CreateAdler32();
  HashOfEmptyData := '00000001';
  HashOfDefaultData := '25D40524';
  HashOfOnetoNine := '091E01DE';
  HashOfABCDE := '05C801F0';
end;

procedure TTestAlder32.TearDown;
begin
  HashInstance := Nil;
  inherited;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAlder32);
{$ELSE}
  RegisterTest(TTestAlder32.Suite);
{$ENDIF FPC}

end.
