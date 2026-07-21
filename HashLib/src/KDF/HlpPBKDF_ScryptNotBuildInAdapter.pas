unit HlpPBKDF_ScryptNotBuildInAdapter;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
{$IFDEF HASHLIB_USE_PPL}
  System.Threading,
{$ENDIF HASHLIB_USE_PPL}
  HlpIHash,
  HlpKDF,
  HlpSHA2_256,
  HlpIHashInfo,
  HlpBinaryPrimitives,
  HlpPBKDF2_HMACNotBuildInAdapter,
  HlpArrayUtils,
  HlpHashLibExceptions,
  HlpHashLibTypes;

type
  TScryptSalsaXorProc = procedure(AState, AInput: Pointer);

var
  Scrypt_SalsaXor: TScryptSalsaXorProc;

procedure Scrypt_Permute(ABlock: PCardinal; AChunkCount: Int32);
procedure Scrypt_Unpermute(ABlock: PCardinal; AChunkCount: Int32);

resourcestring
  SInvalidByteCount =
    '"(AByteCount)" Argument must be a value greater than zero.';
  SInvalidCost = 'Cost parameter must be > 1 and a power of 2.';
  SBlockSizeAndCostIncompatible = 'Cost parameter must be > 1 and < 65536.';
  SBlockSizeTooSmall = 'Block size must be >= 1.';
  SInvalidParallelism =
    'Parallelism parameter must be >= 1 and <= %d (based on block size of %d)';

type
  /// <summary>Implementation of the scrypt a password-based key derivation function.</summary>
  /// <remarks>
  /// Scrypt was created by Colin Percival and is specified in
  /// <a href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kd</a>.
  /// </remarks>
  TPBKDF_ScryptNotBuildInAdapter = class sealed(TKDF, IPBKDF_Scrypt,
    IPBKDF_ScryptNotBuildIn)

  strict private
  var
    FPasswordBytes, FSaltBytes: THashLibByteArray;
    FCost, FBlockSize, FParallelism: Int32;

    class function IsPowerOf2(AValue: Int32): Boolean; static; inline;

    class function SingleIterationPBKDF2(const APasswordBytes,
      ASaltBytes: THashLibByteArray; AOutputLength: Int32)
      : THashLibByteArray; static;

    class procedure SMixLane(AIdx: Int32; APtrB: PCardinal;
      ACost, ABlockSize: Int32); static;

    class procedure BlockMix(const ASourceBlock: THashLibUInt32Array;
      AScratchState: PCardinal; const AMixedOut: THashLibUInt32Array;
      ABlockSize: Int32); static;

    class procedure DoParallelSMix(APtrB: PCardinal; AParallelism, ACost,
      ABlockSize: Int32); static;

    class function MFCrypt(const APasswordBytes, ASaltBytes: THashLibByteArray;
      ACost, ABlockSize, AParallelism, AOutputLength: Int32)
      : THashLibByteArray; static;

    /// <summary>
    /// Validates Scrypt input parameters.
    /// </summary>
    /// <param name="ACost">CPU/Memory cost parameter N.</param>
    /// <param name="ABlockSize">Block size parameter r.</param>
    /// <param name="AParallelism">Parallelization parameter p.</param>
    /// <param name="ARelaxCostRestriction">
    /// When <c>True</c>, skips the <c>N &lt; 2^(128*r/8)</c> constraint
    /// from RFC 7914 (which rejects <c>r=1</c> when <c>N &gt;= 65536</c>).
    /// Colin Percival (Scrypt creator and RFC co-author) confirmed this
    /// constraint was an accidental error; the intended bound was
    /// <c>N &lt; 2^(128*r*8)</c>, which is trivially satisfied.
    /// The Scrypt reference implementation (Tarsnap) does not enforce it,
    /// and the Ethereum Web3 Secret Storage standard depends on
    /// <c>N=262144, r=1, p=8</c> which violates this erroneous constraint.
    /// <list type="bullet">
    ///   <item>RFC errata:          https://www.rfc-editor.org/errata/rfc7914 (5971, 5972, 5973)</item>
    ///   <item>Author confirmation: https://github.com/golang/go/issues/33703#issuecomment-568198927</item>
    ///   <item>OpenSSL:             https://github.com/openssl/openssl/issues/24650</item>
    ///   <item>Go:                  https://github.com/golang/go/issues/33703</item>
    ///   <item>geth:                https://github.com/ethereum/go-ethereum/issues/19977</item>
    ///   <item>eth-account:         https://github.com/ethereum/eth-account/issues/181</item>
    ///   <item>noble-hashes:        https://github.com/paulmillr/noble-hashes/issues/61</item>
    ///   <item>RustCrypto:          https://github.com/RustCrypto/password-hashes/issues/546</item>
    ///   <item>Rustic:              https://github.com/rustic-rs/rustic/issues/1394</item>
    ///   <item>Node.js:             https://github.com/nodejs/node/pull/28799</item>
    /// </list>
    /// </param>
    class procedure ValidatePBKDF_ScryptInputs(ACost, ABlockSize,
      AParallelism: Int32; ARelaxCostRestriction: Boolean = False); static;

  public

    constructor Create(const APasswordBytes, ASaltBytes: THashLibByteArray;
      ACost, ABlockSize, AParallelism: Int32;
      ARelaxCostRestriction: Boolean = False);

    destructor Destroy; override;

    procedure Clear(); override;

    /// <summary>
    /// Returns the pseudo-random bytes for this object.
    /// </summary>
    /// <param name="AByteCount">The number of pseudo-random key bytes to generate.</param>
    /// <returns>A byte array filled with pseudo-random key bytes.</returns>
    /// /// <exception cref="EArgumentOutOfRangeHashLibException">AByteCount must be greater than zero.</exception>
    function GetBytes(AByteCount: Int32): THashLibByteArray; override;

  end;

implementation

uses
  HlpBitOperations,
  HlpScryptSimd;

// =============================================================================
// Percival's (i*5 mod 16) permutation rearranges each 16-word Salsa20 state
// from natural order into role-based diagonal order so that column and row
// quarter-rounds map to lane-parallel SIMD operations. Applied once at
// SMixLane entry/exit; all intermediate data stays in permuted order.
// Reference: Colin Percival, crypto_scrypt-sse.c (Tarsnap).
// =============================================================================

procedure Scrypt_Permute(ABlock: PCardinal; AChunkCount: Int32);
var
  LTemp: array[0..15] of UInt32;
  LIdx: Int32;
begin
  while AChunkCount > 0 do
  begin
    for LIdx := 0 to 15 do
      LTemp[LIdx] := ABlock[(LIdx * 5) and 15];
    System.Move(LTemp, ABlock^, 64);
    Inc(ABlock, 16);
    Dec(AChunkCount);
  end;
end;

procedure Scrypt_Unpermute(ABlock: PCardinal; AChunkCount: Int32);
var
  LTemp: array[0..15] of UInt32;
  LIdx: Int32;
begin
  while AChunkCount > 0 do
  begin
    for LIdx := 0 to 15 do
      LTemp[LIdx] := ABlock[(LIdx * 13) and 15];
    System.Move(LTemp, ABlock^, 64);
    Inc(ABlock, 16);
    Dec(AChunkCount);
  end;
end;

// =============================================================================
// Scalar fallback: fused XOR + Salsa20/8 on Percival-permuted data.
// Loads from permuted positions into natural-named locals, performs standard
// Salsa20/8 column+row rounds, stores back to permuted positions.
// =============================================================================

procedure Scrypt_SalsaXor_Scalar(AState, AInput: Pointer);
var
  LW0, LW1, LW2, LW3, LW4, LW5, LW6, LW7,
  LW8, LW9, LW10, LW11, LW12, LW13, LW14, LW15: UInt32;
  LPS, LPI: PCardinal;
  LIdx: Int32;
begin
  LPS := PCardinal(AState);
  LPI := PCardinal(AInput);

  // Permuted layout: {w0,w5,w10,w15, w4,w9,w14,w3, w8,w13,w2,w7, w12,w1,w6,w11}
  LW0  := LPS[0]  xor LPI[0];
  LW5  := LPS[1]  xor LPI[1];
  LW10 := LPS[2]  xor LPI[2];
  LW15 := LPS[3]  xor LPI[3];
  LW4  := LPS[4]  xor LPI[4];
  LW9  := LPS[5]  xor LPI[5];
  LW14 := LPS[6]  xor LPI[6];
  LW3  := LPS[7]  xor LPI[7];
  LW8  := LPS[8]  xor LPI[8];
  LW13 := LPS[9]  xor LPI[9];
  LW2  := LPS[10] xor LPI[10];
  LW7  := LPS[11] xor LPI[11];
  LW12 := LPS[12] xor LPI[12];
  LW1  := LPS[13] xor LPI[13];
  LW6  := LPS[14] xor LPI[14];
  LW11 := LPS[15] xor LPI[15];

  LPS[0]  := LW0;
  LPS[1]  := LW5;
  LPS[2]  := LW10;
  LPS[3]  := LW15;
  LPS[4]  := LW4;
  LPS[5]  := LW9;
  LPS[6]  := LW14;
  LPS[7]  := LW3;
  LPS[8]  := LW8;
  LPS[9]  := LW13;
  LPS[10] := LW2;
  LPS[11] := LW7;
  LPS[12] := LW12;
  LPS[13] := LW1;
  LPS[14] := LW6;
  LPS[15] := LW11;

  LIdx := 4;
  while LIdx > 0 do
  begin
    LW4  := LW4  xor TBitOperations.RotateLeft32(LW0  + LW12, 7);
    LW8  := LW8  xor TBitOperations.RotateLeft32(LW4  + LW0,  9);
    LW12 := LW12 xor TBitOperations.RotateLeft32(LW8  + LW4,  13);
    LW0  := LW0  xor TBitOperations.RotateLeft32(LW12 + LW8,  18);
    LW9  := LW9  xor TBitOperations.RotateLeft32(LW5  + LW1,  7);
    LW13 := LW13 xor TBitOperations.RotateLeft32(LW9  + LW5,  9);
    LW1  := LW1  xor TBitOperations.RotateLeft32(LW13 + LW9,  13);
    LW5  := LW5  xor TBitOperations.RotateLeft32(LW1  + LW13, 18);
    LW14 := LW14 xor TBitOperations.RotateLeft32(LW10 + LW6,  7);
    LW2  := LW2  xor TBitOperations.RotateLeft32(LW14 + LW10, 9);
    LW6  := LW6  xor TBitOperations.RotateLeft32(LW2  + LW14, 13);
    LW10 := LW10 xor TBitOperations.RotateLeft32(LW6  + LW2,  18);
    LW3  := LW3  xor TBitOperations.RotateLeft32(LW15 + LW11, 7);
    LW7  := LW7  xor TBitOperations.RotateLeft32(LW3  + LW15, 9);
    LW11 := LW11 xor TBitOperations.RotateLeft32(LW7  + LW3,  13);
    LW15 := LW15 xor TBitOperations.RotateLeft32(LW11 + LW7,  18);

    LW1  := LW1  xor TBitOperations.RotateLeft32(LW0  + LW3,  7);
    LW2  := LW2  xor TBitOperations.RotateLeft32(LW1  + LW0,  9);
    LW3  := LW3  xor TBitOperations.RotateLeft32(LW2  + LW1,  13);
    LW0  := LW0  xor TBitOperations.RotateLeft32(LW3  + LW2,  18);
    LW6  := LW6  xor TBitOperations.RotateLeft32(LW5  + LW4,  7);
    LW7  := LW7  xor TBitOperations.RotateLeft32(LW6  + LW5,  9);
    LW4  := LW4  xor TBitOperations.RotateLeft32(LW7  + LW6,  13);
    LW5  := LW5  xor TBitOperations.RotateLeft32(LW4  + LW7,  18);
    LW11 := LW11 xor TBitOperations.RotateLeft32(LW10 + LW9,  7);
    LW8  := LW8  xor TBitOperations.RotateLeft32(LW11 + LW10, 9);
    LW9  := LW9  xor TBitOperations.RotateLeft32(LW8  + LW11, 13);
    LW10 := LW10 xor TBitOperations.RotateLeft32(LW9  + LW8,  18);
    LW12 := LW12 xor TBitOperations.RotateLeft32(LW15 + LW14, 7);
    LW13 := LW13 xor TBitOperations.RotateLeft32(LW12 + LW15, 9);
    LW14 := LW14 xor TBitOperations.RotateLeft32(LW13 + LW12, 13);
    LW15 := LW15 xor TBitOperations.RotateLeft32(LW14 + LW13, 18);

    System.Dec(LIdx);
  end;

  LPS[0]  := LPS[0]  + LW0;
  LPS[1]  := LPS[1]  + LW5;
  LPS[2]  := LPS[2]  + LW10;
  LPS[3]  := LPS[3]  + LW15;
  LPS[4]  := LPS[4]  + LW4;
  LPS[5]  := LPS[5]  + LW9;
  LPS[6]  := LPS[6]  + LW14;
  LPS[7]  := LPS[7]  + LW3;
  LPS[8]  := LPS[8]  + LW8;
  LPS[9]  := LPS[9]  + LW13;
  LPS[10] := LPS[10] + LW2;
  LPS[11] := LPS[11] + LW7;
  LPS[12] := LPS[12] + LW12;
  LPS[13] := LPS[13] + LW1;
  LPS[14] := LPS[14] + LW6;
  LPS[15] := LPS[15] + LW11;
end;

{ TPBKDF_ScryptNotBuildInAdapter }

class function TPBKDF_ScryptNotBuildInAdapter.IsPowerOf2(AValue: Int32): Boolean;
begin
  Result := (AValue > 0) and ((AValue and (AValue - 1)) = 0);
end;

class function TPBKDF_ScryptNotBuildInAdapter.SingleIterationPBKDF2
  (const APasswordBytes, ASaltBytes: THashLibByteArray; AOutputLength: Int32)
  : THashLibByteArray;
begin
  Result := (TPBKDF2_HMACNotBuildInAdapter.Create(TSHA2_256.Create() as IHash,
    APasswordBytes, ASaltBytes, 1) as IPBKDF2_HMAC).GetBytes(AOutputLength);
end;

class procedure TPBKDF_ScryptNotBuildInAdapter.BlockMix(
  const ASourceBlock: THashLibUInt32Array; AScratchState: PCardinal;
  const AMixedOut: THashLibUInt32Array; ABlockSize: Int32);
var
  LBlockOffset, LYOffset, LHalfLength, LIdx: Int32;
begin
  System.Move(ASourceBlock[System.Length(ASourceBlock) - 16], AScratchState^,
    16 * System.SizeOf(UInt32));

  LBlockOffset := 0;
  LYOffset := 0;
  LHalfLength := System.Length(ASourceBlock) div 2;

  LIdx := 2 * ABlockSize;

  while LIdx > 0 do
  begin
    Scrypt_SalsaXor(AScratchState, @ASourceBlock[LBlockOffset]);
    System.Move(AScratchState^, AMixedOut[LYOffset], 16 * System.SizeOf(UInt32));

    LYOffset := LHalfLength + LBlockOffset - LYOffset;
    LBlockOffset := LBlockOffset + 16;
    System.Dec(LIdx);
  end;
end;

class procedure TPBKDF_ScryptNotBuildInAdapter.SMixLane(AIdx: Int32;
  APtrB: PCardinal; ACost, ABlockSize: Int32);
var
  LBCount, LIdx, LRandomIndex, LOffset: Int32;
  LMask: UInt32;
  LScratchState: array[0..15] of UInt32;
  LBlockY, LWorkBlock, LScryptRom: THashLibUInt32Array;
  LPY, LPW: PUInt64;
begin
  AIdx := AIdx * 32 * ABlockSize;
  LBCount := ABlockSize * 32;

  System.SetLength(LBlockY, LBCount);
  System.SetLength(LWorkBlock, LBCount);
  System.SetLength(LScryptRom, ACost * LBCount);

  try
    System.Move(APtrB[AIdx], LWorkBlock[0], LBCount * System.SizeOf(UInt32));
    Scrypt_Permute(@LWorkBlock[0], LBCount div 16);

    LOffset := 0;
    LIdx := 0;
    while LIdx < ACost do
    begin
      System.Move(LWorkBlock[0], LScryptRom[LOffset], LBCount * System.SizeOf(UInt32));
      LOffset := LOffset + LBCount;
      BlockMix(LWorkBlock, @LScratchState[0], LBlockY, ABlockSize);
      System.Move(LBlockY[0], LScryptRom[LOffset], LBCount * System.SizeOf(UInt32));
      LOffset := LOffset + LBCount;
      BlockMix(LBlockY, @LScratchState[0], LWorkBlock, ABlockSize);
      System.Inc(LIdx, 2);
    end;

    LMask := UInt32(ACost) - 1;

    LIdx := 0;
    while LIdx < ACost do
    begin
      LRandomIndex := Int32(LWorkBlock[LBCount - 16] and LMask);
      System.Move(LScryptRom[LRandomIndex * LBCount], LBlockY[0],
        LBCount * System.SizeOf(UInt32));

      LPY := PUInt64(@LBlockY[0]);
      LPW := PUInt64(@LWorkBlock[0]);
      LOffset := (LBCount div 2) - 1;
      while LOffset >= 0 do
      begin
        LPY[LOffset] := LPY[LOffset] xor LPW[LOffset];
        System.Dec(LOffset);
      end;

      BlockMix(LBlockY, @LScratchState[0], LWorkBlock, ABlockSize);
      System.Inc(LIdx);
    end;

    Scrypt_Unpermute(@LWorkBlock[0], LBCount div 16);
    System.Move(LWorkBlock[0], APtrB[AIdx], LBCount * System.SizeOf(UInt32));
  finally
    TArrayUtils.ZeroFill(LScryptRom);
    TArrayUtils.ZeroFill(THashLibMatrixUInt32Array.Create(LWorkBlock, LBlockY));
    System.FillChar(LScratchState, System.SizeOf(LScratchState), 0);
  end;
end;

class procedure TPBKDF_ScryptNotBuildInAdapter.DoParallelSMix(
  APtrB: PCardinal; AParallelism, ACost, ABlockSize: Int32);
{$IFNDEF HASHLIB_USE_PPL}
var
  LIdx: Int32;
{$ENDIF}
begin
{$IFDEF HASHLIB_USE_PPL}
  TParallel.&For(
    0,
    AParallelism - 1,
    procedure(AIdx: Integer)
    begin
      SMixLane(AIdx, APtrB, ACost, ABlockSize);
    end
  );
{$ELSE}
  for LIdx := 0 to AParallelism - 1 do
  begin
    SMixLane(LIdx, APtrB, ACost, ABlockSize);
  end;
{$ENDIF HASHLIB_USE_PPL}
end;

class function TPBKDF_ScryptNotBuildInAdapter.MFCrypt(const APasswordBytes,
  ASaltBytes: THashLibByteArray; ACost, ABlockSize, AParallelism,
  AOutputLength: Int32): THashLibByteArray;
var
  LMFLenBytes, LBLen: Int32;
  LBytes: THashLibByteArray;
  LBlockWords: THashLibUInt32Array;
begin
  LMFLenBytes := ABlockSize * 128;
  LBytes := SingleIterationPBKDF2(APasswordBytes, ASaltBytes,
    AParallelism * LMFLenBytes);

  try
    LBLen := System.Length(LBytes) div 4;
    System.SetLength(LBlockWords, LBLen);

    TBinaryPrimitives.CopyUInt32LittleEndian(PByte(LBytes), 0, PCardinal(LBlockWords), 0,
      System.Length(LBytes) * System.SizeOf(Byte));

    DoParallelSMix(PCardinal(LBlockWords), AParallelism, ACost, ABlockSize);

    TBinaryPrimitives.CopyUInt32LittleEndian(PCardinal(LBlockWords), 0, PByte(LBytes), 0,
      System.Length(LBlockWords) * System.SizeOf(UInt32));

    Result := SingleIterationPBKDF2(APasswordBytes, LBytes, AOutputLength);
  finally
    TArrayUtils.ZeroFill(LBlockWords);
    TArrayUtils.ZeroFill(LBytes);
  end;

end;

class procedure TPBKDF_ScryptNotBuildInAdapter.ValidatePBKDF_ScryptInputs(ACost,
  ABlockSize, AParallelism: Int32; ARelaxCostRestriction: Boolean);
var
  LMaxParallel: Int32;
begin

  if ((ACost <= 1) or (not IsPowerOf2(ACost))) then
  begin
    raise EArgumentHashLibException.CreateRes(@SInvalidCost);
  end;

  if (not ARelaxCostRestriction) then
  begin
    if ((ABlockSize = 1) and (ACost >= 65536)) then
    begin
      raise EArgumentHashLibException.CreateRes(@SBlockSizeAndCostIncompatible);
    end;
  end;

  if (ABlockSize < 1) then
  begin
    raise EArgumentHashLibException.CreateRes(@SBlockSizeTooSmall);
  end;

  LMaxParallel := System.High(Int32) div (128 * ABlockSize * 8);

  if ((AParallelism < 1) or (AParallelism > LMaxParallel)) then
  begin
    raise EArgumentHashLibException.CreateResFmt(@SInvalidParallelism,
      [LMaxParallel, ABlockSize]);
  end;
end;

procedure TPBKDF_ScryptNotBuildInAdapter.Clear();
begin
  TArrayUtils.ZeroFill(FPasswordBytes);
  TArrayUtils.ZeroFill(FSaltBytes);
end;

constructor TPBKDF_ScryptNotBuildInAdapter.Create(const APasswordBytes,
  ASaltBytes: THashLibByteArray; ACost, ABlockSize, AParallelism: Int32;
  ARelaxCostRestriction: Boolean);
begin
  inherited Create();
  ValidatePBKDF_ScryptInputs(ACost, ABlockSize, AParallelism, ARelaxCostRestriction);
  FPasswordBytes := System.Copy(APasswordBytes);
  FSaltBytes := System.Copy(ASaltBytes);
  FCost := ACost;
  FBlockSize := ABlockSize;
  FParallelism := AParallelism;
end;

destructor TPBKDF_ScryptNotBuildInAdapter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TPBKDF_ScryptNotBuildInAdapter.GetBytes(AByteCount: Int32)
  : THashLibByteArray;
begin
  if (AByteCount <= 0) then
  begin
    raise EArgumentHashLibException.CreateRes(@SInvalidByteCount);
  end;

  Result := MFCrypt(FPasswordBytes, FSaltBytes, FCost, FBlockSize, FParallelism,
    AByteCount);
end;

initialization
  Scrypt_SalsaXor := TScryptSimd.Select(@Scrypt_SalsaXor_Scalar);

end.
