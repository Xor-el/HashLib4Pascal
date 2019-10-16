unit NullDigestTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$NOTES OFF}
{$ENDIF FPC}

uses
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
  HlpConverters,
  HlpHashLibTypes;

// NullDigest

type
  TTestNullDigest = class(THashLibAlgorithmTestCase)

  private
    FNullDigest: IHash;
    FBlockSizeMethod, FHashSizeMethod: TTestMethod;

    procedure CallGetBlockSize();
    procedure CallGetHashSize();

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyBytes;
    procedure TestBytesabcde;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;

  end;

implementation

{ TTestNullDigest }

procedure TTestNullDigest.CallGetBlockSize;
begin
  FNullDigest.BlockSize;
end;

procedure TTestNullDigest.CallGetHashSize;
begin
  FNullDigest.HashSize;
end;

procedure TTestNullDigest.SetUp;
begin
  inherited;
  FNullDigest := THashFactory.TNullDigestFactory.CreateNullDigest();
  FBlockSizeMethod := CallGetBlockSize;
  FHashSizeMethod := CallGetHashSize;
end;

procedure TTestNullDigest.TearDown;
begin
  inherited;
  FNullDigest := Nil;
  FBlockSizeMethod := Nil;
  FHashSizeMethod := Nil;
end;

procedure TTestNullDigest.TestBytesabcde;
var
  BytesABCDE, Result: TBytes;
begin
  BytesABCDE := TEncoding.UTF8.GetBytes('abcde');

  FNullDigest.Initialize;

  FNullDigest.TransformBytes(BytesABCDE);

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckTrue(AreEqual(BytesABCDE, Result));
  CheckException(FBlockSizeMethod, ENotImplementedHashLibException);
  CheckException(FHashSizeMethod, ENotImplementedHashLibException);
end;

procedure TTestNullDigest.TestEmptyBytes;
var
  BytesEmpty, Result: TBytes;
begin
  BytesEmpty := TEncoding.UTF8.GetBytes('');

  FNullDigest.Initialize;

  FNullDigest.TransformBytes(BytesEmpty);

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckTrue(AreEqual(BytesEmpty, Result));
  CheckException(FBlockSizeMethod, ENotImplementedHashLibException);
  CheckException(FHashSizeMethod, ENotImplementedHashLibException);
end;

procedure TTestNullDigest.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FNullDigest;
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

procedure TTestNullDigest.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FNullDigest;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestNullDigest.TestIncrementalHash;
var
  BytesZeroToNine, Result: TBytes;
begin
  BytesZeroToNine := TEncoding.UTF8.GetBytes('0123456789');

  FNullDigest.Initialize;

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 0, 4));

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 4, 6));

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckTrue(AreEqual(BytesZeroToNine, Result));
  CheckException(FBlockSizeMethod, ENotImplementedHashLibException);
  CheckException(FHashSizeMethod, ENotImplementedHashLibException);
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
