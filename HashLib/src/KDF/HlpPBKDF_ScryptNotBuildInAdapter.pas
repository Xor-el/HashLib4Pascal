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
  HlpBits,
  HlpSHA2_256,
  HlpIHashInfo,
  HlpPBKDF2_HMACNotBuildInAdapter,
  HlpConverters,
  HlpArrayUtils,
  HlpHashLibTypes;

resourcestring
  SInvalidByteCount =
    '"(AByteCount)" Argument must be a value greater than zero.';
  SInvalidCost = 'Cost parameter must be > 1 and a power of 2.';
  SBlockSizeAndCostIncompatible = 'Cost parameter must be > 1 and < 65536.';
  SBlockSizeTooSmall = 'Block size must be >= 1.';
  SInvalidParallelism =
    'Parallelism parameter must be >= 1 and <= %d (based on block size of %d)';
  SRoundsMustBeEven = 'Number of Rounds Must be Even';

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

    /// <summary>
    /// lifted from <c>ClpSalsa20Engine.pas</c> in CryptoLib4Pascal with
    /// minor modifications.
    /// </summary>
    class procedure SalsaCore(ARounds: Int32;
      const AInput, AOutWords: THashLibUInt32Array); static;

    class procedure &Xor(const ALeftWords, ARightWords: THashLibUInt32Array;
      ARightWordOffset: Int32; const AOutput: THashLibUInt32Array); static;

    class procedure SMixLane(AIdx: Int32; APtrB: PCardinal;
      ACost, ABlockSize: Int32); static;

    class procedure BlockMix(const ASourceBlock, AScratchX1, AScratchX2,
      AMixedOut: THashLibUInt32Array; ABlockSize: Int32); static;

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

class procedure TPBKDF_ScryptNotBuildInAdapter.&Xor(const ALeftWords,
  ARightWords: THashLibUInt32Array; ARightWordOffset: Int32;
  const AOutput: THashLibUInt32Array);
var
  LIdx: Int32;
begin
  LIdx := System.Length(AOutput) - 1;
  while LIdx >= 0 do
  begin
    AOutput[LIdx] := ALeftWords[LIdx] xor ARightWords[ARightWordOffset + LIdx];
    System.Dec(LIdx);
  end;
end;

class procedure TPBKDF_ScryptNotBuildInAdapter.SalsaCore(ARounds: Int32;
  const AInput, AOutWords: THashLibUInt32Array);
var
  LWord0, LWord1, LWord2, LWord3, LWord4, LWord5, LWord6, LWord7, LWord8, LWord9, LWord10, LWord11, LWord12, LWord13, LWord14,
    LWord15: UInt32;
  LIdx: Int32;
begin
  if (System.Length(AInput) <> 16) then
  begin
    raise EArgumentHashLibException.Create('AInput length must be 16');
  end;
  if (System.Length(AOutWords) <> 16) then
  begin
    raise EArgumentHashLibException.Create('AOutWords length must be 16');
  end;
  if ((ARounds mod 2) <> 0) then
  begin
    raise EArgumentHashLibException.CreateRes(@SRoundsMustBeEven);
  end;

  LWord0 := AInput[0];
  LWord1 := AInput[1];
  LWord2 := AInput[2];
  LWord3 := AInput[3];
  LWord4 := AInput[4];
  LWord5 := AInput[5];
  LWord6 := AInput[6];
  LWord7 := AInput[7];
  LWord8 := AInput[8];
  LWord9 := AInput[9];
  LWord10 := AInput[10];
  LWord11 := AInput[11];
  LWord12 := AInput[12];
  LWord13 := AInput[13];
  LWord14 := AInput[14];
  LWord15 := AInput[15];

  LIdx := ARounds;
  while LIdx > 0 do
  begin

    LWord4 := LWord4 xor (TBits.RotateLeft32((LWord0 + LWord12), 7));
    LWord8 := LWord8 xor (TBits.RotateLeft32((LWord4 + LWord0), 9));
    LWord12 := LWord12 xor (TBits.RotateLeft32((LWord8 + LWord4), 13));
    LWord0 := LWord0 xor (TBits.RotateLeft32((LWord12 + LWord8), 18));
    LWord9 := LWord9 xor (TBits.RotateLeft32((LWord5 + LWord1), 7));
    LWord13 := LWord13 xor (TBits.RotateLeft32((LWord9 + LWord5), 9));
    LWord1 := LWord1 xor (TBits.RotateLeft32((LWord13 + LWord9), 13));
    LWord5 := LWord5 xor (TBits.RotateLeft32((LWord1 + LWord13), 18));
    LWord14 := LWord14 xor (TBits.RotateLeft32((LWord10 + LWord6), 7));
    LWord2 := LWord2 xor (TBits.RotateLeft32((LWord14 + LWord10), 9));
    LWord6 := LWord6 xor (TBits.RotateLeft32((LWord2 + LWord14), 13));
    LWord10 := LWord10 xor (TBits.RotateLeft32((LWord6 + LWord2), 18));
    LWord3 := LWord3 xor (TBits.RotateLeft32((LWord15 + LWord11), 7));
    LWord7 := LWord7 xor (TBits.RotateLeft32((LWord3 + LWord15), 9));
    LWord11 := LWord11 xor (TBits.RotateLeft32((LWord7 + LWord3), 13));
    LWord15 := LWord15 xor (TBits.RotateLeft32((LWord11 + LWord7), 18));

    LWord1 := LWord1 xor (TBits.RotateLeft32((LWord0 + LWord3), 7));
    LWord2 := LWord2 xor (TBits.RotateLeft32((LWord1 + LWord0), 9));
    LWord3 := LWord3 xor (TBits.RotateLeft32((LWord2 + LWord1), 13));
    LWord0 := LWord0 xor (TBits.RotateLeft32((LWord3 + LWord2), 18));
    LWord6 := LWord6 xor (TBits.RotateLeft32((LWord5 + LWord4), 7));
    LWord7 := LWord7 xor (TBits.RotateLeft32((LWord6 + LWord5), 9));
    LWord4 := LWord4 xor (TBits.RotateLeft32((LWord7 + LWord6), 13));
    LWord5 := LWord5 xor (TBits.RotateLeft32((LWord4 + LWord7), 18));
    LWord11 := LWord11 xor (TBits.RotateLeft32((LWord10 + LWord9), 7));
    LWord8 := LWord8 xor (TBits.RotateLeft32((LWord11 + LWord10), 9));
    LWord9 := LWord9 xor (TBits.RotateLeft32((LWord8 + LWord11), 13));
    LWord10 := LWord10 xor (TBits.RotateLeft32((LWord9 + LWord8), 18));
    LWord12 := LWord12 xor (TBits.RotateLeft32((LWord15 + LWord14), 7));
    LWord13 := LWord13 xor (TBits.RotateLeft32((LWord12 + LWord15), 9));
    LWord14 := LWord14 xor (TBits.RotateLeft32((LWord13 + LWord12), 13));
    LWord15 := LWord15 xor (TBits.RotateLeft32((LWord14 + LWord13), 18));

    System.Dec(LIdx, 2);
  end;

  AOutWords[0] := LWord0 + AInput[0];
  AOutWords[1] := LWord1 + AInput[1];
  AOutWords[2] := LWord2 + AInput[2];
  AOutWords[3] := LWord3 + AInput[3];
  AOutWords[4] := LWord4 + AInput[4];
  AOutWords[5] := LWord5 + AInput[5];
  AOutWords[6] := LWord6 + AInput[6];
  AOutWords[7] := LWord7 + AInput[7];
  AOutWords[8] := LWord8 + AInput[8];
  AOutWords[9] := LWord9 + AInput[9];
  AOutWords[10] := LWord10 + AInput[10];
  AOutWords[11] := LWord11 + AInput[11];
  AOutWords[12] := LWord12 + AInput[12];
  AOutWords[13] := LWord13 + AInput[13];
  AOutWords[14] := LWord14 + AInput[14];
  AOutWords[15] := LWord15 + AInput[15];

end;

class procedure TPBKDF_ScryptNotBuildInAdapter.BlockMix(const ASourceBlock,
  AScratchX1, AScratchX2, AMixedOut: THashLibUInt32Array; ABlockSize: Int32);
var
  LBlockOffset, LYOffset, LHalfLength, LIdx: Int32;
begin
  System.Move(ASourceBlock[System.Length(ASourceBlock) - 16], AScratchX1[0],
    16 * System.SizeOf(UInt32));

  LBlockOffset := 0;
  LYOffset := 0;
  LHalfLength := System.Length(ASourceBlock) div 2;

  LIdx := 2 * ABlockSize;

  while LIdx > 0 do
  begin
    &Xor(AScratchX1, ASourceBlock, LBlockOffset, AScratchX2);

    SalsaCore(8, AScratchX2, AScratchX1);
    System.Move(AScratchX1[0], AMixedOut[LYOffset], 16 * System.SizeOf(UInt32));

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
  LBlockX1, LBlockX2, LBlockY, LWorkBlock, LScryptRom: THashLibUInt32Array;
begin
  AIdx := AIdx * 32 * ABlockSize;
  LBCount := ABlockSize * 32;

  System.SetLength(LBlockX1, 16);
  System.SetLength(LBlockX2, 16);
  System.SetLength(LBlockY, LBCount);
  System.SetLength(LWorkBlock, LBCount);
  System.SetLength(LScryptRom, ACost * LBCount);

  try
    System.Move(APtrB[AIdx], LWorkBlock[0], LBCount * System.SizeOf(UInt32));

    LOffset := 0;
    LIdx := 0;
    while LIdx < ACost do
    begin
      System.Move(LWorkBlock[0], LScryptRom[LOffset], LBCount * System.SizeOf(UInt32));
      LOffset := LOffset + LBCount;
      BlockMix(LWorkBlock, LBlockX1, LBlockX2, LBlockY, ABlockSize);
      System.Move(LBlockY[0], LScryptRom[LOffset], LBCount * System.SizeOf(UInt32));
      LOffset := LOffset + LBCount;
      BlockMix(LBlockY, LBlockX1, LBlockX2, LWorkBlock, ABlockSize);
      System.Inc(LIdx, 2);
    end;

    LMask := UInt32(ACost) - 1;

    LIdx := 0;
    while LIdx < ACost do
    begin
      LRandomIndex := Int32(LWorkBlock[LBCount - 16] and LMask);
      System.Move(LScryptRom[LRandomIndex * LBCount], LBlockY[0],
        LBCount * System.SizeOf(UInt32));
      &Xor(LBlockY, LWorkBlock, 0, LBlockY);
      BlockMix(LBlockY, LBlockX1, LBlockX2, LWorkBlock, ABlockSize);
      System.Inc(LIdx);
    end;

    System.Move(LWorkBlock[0], APtrB[AIdx], LBCount * System.SizeOf(UInt32));
  finally
    TArrayUtils.ZeroFill(LScryptRom);
    TArrayUtils.ZeroFill(THashLibMatrixUInt32Array.Create(LWorkBlock, LBlockX1,
      LBlockX2, LBlockY));
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

    TConverters.le32_copy(PByte(LBytes), 0, PCardinal(LBlockWords), 0,
      System.Length(LBytes) * System.SizeOf(Byte));

    DoParallelSMix(PCardinal(LBlockWords), AParallelism, ACost, ABlockSize);

    TConverters.le32_copy(PCardinal(LBlockWords), 0, PByte(LBytes), 0,
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

end.

