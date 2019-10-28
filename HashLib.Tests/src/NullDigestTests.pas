unit NullDigestTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HashLibTestBase,
  HlpHashFactory;

// NullDigest
type
  TTestNullDigest = class(TNullDigestAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

{ TTestNullDigest }

procedure TTestNullDigest.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TNullDigestFactory.CreateNullDigest();
  FBlockSizeMethod := CallGetBlockSize;
  FHashSizeMethod := CallGetHashSize;
end;

procedure TTestNullDigest.TearDown;
begin
  inherited;
  HashInstance := Nil;
  FBlockSizeMethod := Nil;
  FHashSizeMethod := Nil;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// NullDigest
RegisterTest(TTestNullDigest);
{$ELSE}
// NullDigest
RegisterTest(TTestNullDigest.Suite);
{$ENDIF FPC}

end.
