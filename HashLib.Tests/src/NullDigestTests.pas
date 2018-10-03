unit NullDigestTests;

interface

{$IFDEF FPC}
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
  HlpConverters;

// NullDigest

type
  TTestNullDigest = class(THashLibAlgorithmTestCase)

  private
    FNullDigest: IHash;

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

procedure TTestNullDigest.SetUp;
begin
  inherited;
  FNullDigest := THashFactory.TNullDigestFactory.CreateNullDigest();
end;

procedure TTestNullDigest.TearDown;
begin
  inherited;
  FNullDigest := Nil;
end;

procedure TTestNullDigest.TestBytesabcde;
var
  BytesABCDE, Result: TBytes;
begin
  BytesABCDE := TEncoding.UTF8.GetBytes('abcde');
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(BytesABCDE);

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(System.Length(BytesABCDE), FNullDigest.HashSize);

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(AreEqual(BytesABCDE, Result));

end;

procedure TTestNullDigest.TestEmptyBytes;
var
  BytesEmpty, Result: TBytes;
begin
  BytesEmpty := TEncoding.UTF8.GetBytes('');
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(BytesEmpty);

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(System.Length(BytesEmpty), FNullDigest.HashSize);

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(AreEqual(BytesEmpty, Result));
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
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 0, 4));

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(4, FNullDigest.HashSize);

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 4, 6));

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(10, FNullDigest.HashSize);

  Result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(AreEqual(BytesZeroToNine, Result));

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
