unit HlpXXHash128;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpHash,
  HlpIHash,
  HlpConverters,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpBits,
  HlpXXHash3;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type

  TXXHash128 = class sealed(THash, IHash128, IHashWithKey, ITransformBlock)

  strict private
  var
    FKey: UInt64;
    FHashLow, FHashHigh: UInt64;

  const
    CKEY = UInt64(0);

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

  type

    TXXH128_State = record

    private
    var
      FAcc: TXXH3AccArray;
      FCustomSecret: THashLibByteArray;
      FBuffer: THashLibByteArray;
      FBufferedSize: UInt32;
      FNbStripesSoFar: Int32;
      FTotalLength: UInt64;

      function Clone(): TXXH128_State;

    end;

  strict private
  var
    FState: TXXH128_State;

    class procedure XXH128_mix32B(var ALow, AHigh: UInt64;
      AInput1, AInput2, ASecret: PByte; ASeed: UInt64); static;
    class procedure XXH3_len_1to3_128b(AInput, ASecret: PByte;
      ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64); static;
    class procedure XXH3_len_4to8_128b(AInput, ASecret: PByte;
      ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64); static;
    class procedure XXH3_len_9to16_128b(AInput, ASecret: PByte;
      ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64); static;
    class procedure XXH3_len_0to16_128b(AInput, ASecret: PByte;
      ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64); static;
    class procedure XXH3_len_17to128_128b(AInput, ASecret: PByte;
      ALen, ASecretSize: Int32; ASeed: UInt64;
      out ALow, AHigh: UInt64); static;
    class procedure XXH3_len_129to240_128b(AInput, ASecret: PByte;
      ALen, ASecretSize: Int32; ASeed: UInt64;
      out ALow, AHigh: UInt64); static;
    class procedure XXH3_hashLong_128b_internal(AInput: PByte; ALen: Int32;
      ASecret: PByte; ASecretSize: Int32;
      out ALow, AHigh: UInt64); static;
    class procedure XXH3_hashLong_128b_withSeed(AInput: PByte; ALen: Int32;
      ASeed: UInt64; out ALow, AHigh: UInt64); static;
    class procedure XXH3_128bits_internal(AInput: PByte; ALen: Int32;
      ASeed: UInt64; ASecret: PByte; ASecretLen: Int32;
      out ALow, AHigh: UInt64); static;

    procedure DigestLong(var AAcc: TXXH3AccArray);

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;
    function Clone(): IHash; override;
    property KeyLength: Int32 read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TXXHash128.TXXH128_State }

function TXXHash128.TXXH128_State.Clone(): TXXH128_State;
begin
  Result := Default(TXXH128_State);
  System.Move(FAcc, Result.FAcc, System.SizeOf(TXXH3AccArray));
  Result.FCustomSecret := System.Copy(FCustomSecret);
  Result.FBuffer := System.Copy(FBuffer);
  Result.FBufferedSize := FBufferedSize;
  Result.FNbStripesSoFar := FNbStripesSoFar;
  Result.FTotalLength := FTotalLength;
end;

{ TXXHash128 }

constructor TXXHash128.Create;
begin
  inherited Create(16, 64);
  FKey := CKEY;
  System.SetLength(FState.FBuffer, TXXH3Core.XXH3_INTERNALBUFFER_SIZE);
  System.SetLength(FState.FCustomSecret, TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);
end;

function TXXHash128.Clone(): IHash;
var
  LHashInstance: TXXHash128;
begin
  LHashInstance := TXXHash128.Create();
  LHashInstance.FKey := FKey;
  LHashInstance.FHashLow := FHashLow;
  LHashInstance.FHashHigh := FHashHigh;
  LHashInstance.FState := FState.Clone();
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

function TXXHash128.GetKey: THashLibByteArray;
begin
  Result := TConverters.ReadUInt64AsBytesLE(FKey);
end;

function TXXHash128.GetKeyLength: Int32;
begin
  Result := 8;
end;

procedure TXXHash128.SetKey(const AValue: THashLibByteArray);
begin
  if (AValue = nil) then
  begin
    FKey := CKEY;
  end
  else
  begin
    if System.Length(AValue) <> KeyLength then
    begin
      raise EArgumentHashLibException.CreateResFmt(@SInvalidKeyLength,
        [KeyLength]);
    end;
    FKey := TConverters.ReadBytesAsUInt64LE(PByte(AValue), 0);
  end;
end;

procedure TXXHash128.Initialize;
begin
  FHashLow := 0;
  FHashHigh := 0;
  System.Move(TXXH3Core.XXH3_INIT_ACC, FState.FAcc,
    System.SizeOf(TXXH3AccArray));

  if FKey <> 0 then
    TXXH3Core.XXH3_initCustomSecret(PByte(FState.FCustomSecret), FKey)
  else
    System.Move(TXXH3Core.XXH3_SECRET[0], FState.FCustomSecret[0],
      TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);

  FState.FTotalLength := 0;
  FState.FBufferedSize := 0;
  FState.FNbStripesSoFar := 0;
end;

class procedure TXXHash128.XXH128_mix32B(var ALow, AHigh: UInt64;
  AInput1, AInput2, ASecret: PByte; ASeed: UInt64);
begin
  ALow := ALow + TXXH3Core.XXH3_mix16B(AInput1, ASecret, ASeed);
  ALow := ALow xor (TConverters.ReadBytesAsUInt64LE(AInput2, 0) +
    TConverters.ReadBytesAsUInt64LE(AInput2, 8));
  AHigh := AHigh + TXXH3Core.XXH3_mix16B(AInput2, ASecret + 16, ASeed);
  AHigh := AHigh xor (TConverters.ReadBytesAsUInt64LE(AInput1, 0) +
    TConverters.ReadBytesAsUInt64LE(AInput1, 8));
end;

class procedure TXXHash128.XXH3_len_1to3_128b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LC1, LC2, LC3: Byte;
  LCombinedL, LCombinedH: UInt32;
  LBitflipL, LBitflipH: UInt64;
begin
  LC1 := AInput[0];
  LC2 := AInput[TBits.Asr32(ALen, 1)];
  LC3 := AInput[ALen - 1];

  LCombinedL := (UInt32(LC1) shl 16) or (UInt32(LC2) shl 24) or
    (UInt32(LC3) shl 0) or (UInt32(ALen) shl 8);
  LCombinedH := TBits.RotateLeft32(TBits.ReverseBytesUInt32(LCombinedL), 13);

  LBitflipL := UInt64(TConverters.ReadBytesAsUInt32LE(ASecret, 0) xor
    TConverters.ReadBytesAsUInt32LE(ASecret, 4)) + ASeed;
  LBitflipH := UInt64(TConverters.ReadBytesAsUInt32LE(ASecret, 8) xor
    TConverters.ReadBytesAsUInt32LE(ASecret, 12)) - ASeed;

  ALow := TXXH3Core.XXH64_avalanche(UInt64(LCombinedL) xor LBitflipL);
  AHigh := TXXH3Core.XXH64_avalanche(UInt64(LCombinedH) xor LBitflipH);
end;

class procedure TXXHash128.XXH3_len_4to8_128b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LInputLo, LInputHi: UInt32;
  LInput64, LBitflip, LKeyed: UInt64;
  LMLow, LMHigh: UInt64;
begin
  ASeed := ASeed xor (UInt64(TBits.ReverseBytesUInt32(UInt32(ASeed))) shl 32);

  LInputLo := TConverters.ReadBytesAsUInt32LE(AInput, 0);
  LInputHi := TConverters.ReadBytesAsUInt32LE(AInput, ALen - 4);
  LInput64 := UInt64(LInputLo) + (UInt64(LInputHi) shl 32);
  LBitflip := (TConverters.ReadBytesAsUInt64LE(ASecret, 16) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 24)) + ASeed;
  LKeyed := LInput64 xor LBitflip;

  TXXH3Core.XXH_mult64to128(LKeyed, TXXH3Core.XXH_PRIME64_1 +
    (UInt64(ALen) shl 2), LMLow, LMHigh);

  LMHigh := LMHigh + (LMLow shl 1);
  LMLow := LMLow xor (LMHigh shr 3);

  LMLow := LMLow xor (LMLow shr 35);
  LMLow := LMLow * UInt64($9FB21C651E98DF25);
  LMLow := LMLow xor (LMLow shr 28);
  LMHigh := TXXH3Core.XXH3_avalanche(LMHigh);

  ALow := LMLow;
  AHigh := LMHigh;
end;

class procedure TXXHash128.XXH3_len_9to16_128b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LBitflipL, LBitflipH, LInputLo, LInputHi: UInt64;
  LMLow, LMHigh, LHLow, LHHigh: UInt64;
begin
  LBitflipL := (TConverters.ReadBytesAsUInt64LE(ASecret, 32) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 40)) - ASeed;
  LBitflipH := (TConverters.ReadBytesAsUInt64LE(ASecret, 48) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 56)) + ASeed;
  LInputLo := TConverters.ReadBytesAsUInt64LE(AInput, 0);
  LInputHi := TConverters.ReadBytesAsUInt64LE(AInput, ALen - 8);

  TXXH3Core.XXH_mult64to128(LInputLo xor LInputHi xor LBitflipL,
    TXXH3Core.XXH_PRIME64_1, LMLow, LMHigh);

  LMLow := LMLow + (UInt64(ALen - 1) shl 54);
  LInputHi := LInputHi xor LBitflipH;

  LMHigh := LMHigh + LInputHi +
    TXXH3Core.XXH_mult32to64(UInt32(LInputHi),
    TXXH3Core.XXH_PRIME32_2 - 1);
  LMLow := LMLow xor TBits.ReverseBytesUInt64(LMHigh);

  TXXH3Core.XXH_mult64to128(LMLow, TXXH3Core.XXH_PRIME64_2, LHLow, LHHigh);
  LHHigh := LHHigh + LMHigh * TXXH3Core.XXH_PRIME64_2;

  ALow := TXXH3Core.XXH3_avalanche(LHLow);
  AHigh := TXXH3Core.XXH3_avalanche(LHHigh);
end;

class procedure TXXHash128.XXH3_len_0to16_128b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LBitflipL, LBitflipH: UInt64;
begin
  if ALen > 8 then
    XXH3_len_9to16_128b(AInput, ASecret, ALen, ASeed, ALow, AHigh)
  else if ALen >= 4 then
    XXH3_len_4to8_128b(AInput, ASecret, ALen, ASeed, ALow, AHigh)
  else if ALen <> 0 then
    XXH3_len_1to3_128b(AInput, ASecret, ALen, ASeed, ALow, AHigh)
  else
  begin
    LBitflipL := TConverters.ReadBytesAsUInt64LE(ASecret, 64) xor
      TConverters.ReadBytesAsUInt64LE(ASecret, 72);
    LBitflipH := TConverters.ReadBytesAsUInt64LE(ASecret, 80) xor
      TConverters.ReadBytesAsUInt64LE(ASecret, 88);
    ALow := TXXH3Core.XXH64_avalanche(ASeed xor LBitflipL);
    AHigh := TXXH3Core.XXH64_avalanche(ASeed xor LBitflipH);
  end;
end;

class procedure TXXHash128.XXH3_len_17to128_128b(AInput, ASecret: PByte;
  ALen, ASecretSize: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LAccLow, LAccHigh: UInt64;
begin
  LAccLow := UInt64(ALen) * TXXH3Core.XXH_PRIME64_1;
  LAccHigh := 0;

  if ALen > 32 then
  begin
    if ALen > 64 then
    begin
      if ALen > 96 then
        XXH128_mix32B(LAccLow, LAccHigh, AInput + 48, AInput + ALen - 64,
          ASecret + 96, ASeed);
      XXH128_mix32B(LAccLow, LAccHigh, AInput + 32, AInput + ALen - 48,
        ASecret + 64, ASeed);
    end;
    XXH128_mix32B(LAccLow, LAccHigh, AInput + 16, AInput + ALen - 32,
      ASecret + 32, ASeed);
  end;
  XXH128_mix32B(LAccLow, LAccHigh, AInput, AInput + ALen - 16,
    ASecret, ASeed);

  ALow := TXXH3Core.XXH3_avalanche(LAccLow + LAccHigh);
  AHigh := UInt64(0) - TXXH3Core.XXH3_avalanche(
    LAccLow * TXXH3Core.XXH_PRIME64_1 +
    LAccHigh * TXXH3Core.XXH_PRIME64_4 +
    (UInt64(ALen) - ASeed) * TXXH3Core.XXH_PRIME64_2);
end;

class procedure TXXHash128.XXH3_len_129to240_128b(AInput, ASecret: PByte;
  ALen, ASecretSize: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LAccLow, LAccHigh: UInt64;
  LNbRounds, I: Int32;
begin
  LAccLow := UInt64(ALen) * TXXH3Core.XXH_PRIME64_1;
  LAccHigh := 0;
  LNbRounds := ALen div 32;

  for I := 0 to 3 do
    XXH128_mix32B(LAccLow, LAccHigh, AInput + (32 * I),
      AInput + (32 * I) + 16, ASecret + (32 * I), ASeed);

  LAccLow := TXXH3Core.XXH3_avalanche(LAccLow);
  LAccHigh := TXXH3Core.XXH3_avalanche(LAccHigh);

  for I := 4 to LNbRounds - 1 do
    XXH128_mix32B(LAccLow, LAccHigh, AInput + (32 * I),
      AInput + (32 * I) + 16,
      ASecret + TXXH3Core.XXH3_MIDSIZE_STARTOFFSET + (32 * (I - 4)), ASeed);

  XXH128_mix32B(LAccLow, LAccHigh, AInput + ALen - 16, AInput + ALen - 32,
    ASecret + TXXH3Core.XXH3_SECRET_SIZE_MIN -
    TXXH3Core.XXH3_MIDSIZE_LASTOFFSET - 16, UInt64(0) - ASeed);

  ALow := TXXH3Core.XXH3_avalanche(LAccLow + LAccHigh);
  AHigh := UInt64(0) - TXXH3Core.XXH3_avalanche(
    LAccLow * TXXH3Core.XXH_PRIME64_1 +
    LAccHigh * TXXH3Core.XXH_PRIME64_4 +
    (UInt64(ALen) - ASeed) * TXXH3Core.XXH_PRIME64_2);
end;

class procedure TXXHash128.XXH3_hashLong_128b_internal(AInput: PByte;
  ALen: Int32; ASecret: PByte; ASecretSize: Int32;
  out ALow, AHigh: UInt64);
var
  LAcc: TXXH3AccArray;
begin
  System.Move(TXXH3Core.XXH3_INIT_ACC, LAcc, System.SizeOf(TXXH3AccArray));

  TXXH3Core.XXH3_hashLong_internal_loop(LAcc, AInput, ALen,
    ASecret, ASecretSize);

  ALow := TXXH3Core.XXH3_mergeAccs(LAcc,
    ASecret + TXXH3Core.XXH_SECRET_MERGEACCS_START,
    UInt64(ALen) * TXXH3Core.XXH_PRIME64_1);
  AHigh := TXXH3Core.XXH3_mergeAccs(LAcc,
    ASecret + ASecretSize - TXXH3Core.XXH3_ACC_SIZE -
    TXXH3Core.XXH_SECRET_MERGEACCS_START,
    not (UInt64(ALen) * TXXH3Core.XXH_PRIME64_2));
end;

class procedure TXXHash128.XXH3_hashLong_128b_withSeed(AInput: PByte;
  ALen: Int32; ASeed: UInt64; out ALow, AHigh: UInt64);
var
  LSecret: array [0 .. 191] of Byte;
begin
  if ASeed = 0 then
  begin
    XXH3_hashLong_128b_internal(AInput, ALen,
      PByte(@TXXH3Core.XXH3_SECRET[0]),
      TXXH3Core.XXH3_SECRET_DEFAULT_SIZE, ALow, AHigh);
    Exit;
  end;

  TXXH3Core.XXH3_initCustomSecret(PByte(@LSecret[0]), ASeed);
  XXH3_hashLong_128b_internal(AInput, ALen, PByte(@LSecret[0]),
    TXXH3Core.XXH3_SECRET_DEFAULT_SIZE, ALow, AHigh);
end;

class procedure TXXHash128.XXH3_128bits_internal(AInput: PByte;
  ALen: Int32; ASeed: UInt64; ASecret: PByte; ASecretLen: Int32;
  out ALow, AHigh: UInt64);
begin
  if ALen <= 16 then
    XXH3_len_0to16_128b(AInput, ASecret, ALen, ASeed, ALow, AHigh)
  else if ALen <= 128 then
    XXH3_len_17to128_128b(AInput, ASecret, ALen, ASecretLen, ASeed,
      ALow, AHigh)
  else if ALen <= TXXH3Core.XXH3_MIDSIZE_MAX then
    XXH3_len_129to240_128b(AInput, ASecret, ALen, ASecretLen, ASeed,
      ALow, AHigh)
  else
    XXH3_hashLong_128b_withSeed(AInput, ALen, ASeed, ALow, AHigh);
end;

procedure TXXHash128.DigestLong(var AAcc: TXXH3AccArray);
var
  LSecret: PByte;
  LNbStripes, LNbStripesSoFar: Int32;
  LLastStripe: array [0 .. 63] of Byte;
  LCatchupSize: Int32;
begin
  LSecret := PByte(FState.FCustomSecret);

  if FState.FBufferedSize >= TXXH3Core.XXH_STRIPE_LEN then
  begin
    LNbStripes := Int32((FState.FBufferedSize - 1) div
      TXXH3Core.XXH_STRIPE_LEN);
    LNbStripesSoFar := FState.FNbStripesSoFar;
    TXXH3Core.XXH3_consumeStripes(AAcc, LNbStripesSoFar,
      TXXH3Core.XXH3_STRIPES_PER_BLOCK, PByte(FState.FBuffer), LSecret,
      LNbStripes, TXXH3Core.XXH3_SECRET_LIMIT);

    TXXH3Core.XXH3_accumulate_512(AAcc,
      PByte(FState.FBuffer) + FState.FBufferedSize -
      TXXH3Core.XXH_STRIPE_LEN,
      LSecret + TXXH3Core.XXH3_SECRET_LIMIT -
      TXXH3Core.XXH_SECRET_LASTACC_START);
  end
  else
  begin
    LCatchupSize := TXXH3Core.XXH_STRIPE_LEN - Int32(FState.FBufferedSize);
    System.Move(FState.FBuffer[TXXH3Core.XXH3_INTERNALBUFFER_SIZE -
      LCatchupSize], LLastStripe[0], LCatchupSize);
    System.Move(FState.FBuffer[0], LLastStripe[LCatchupSize],
      FState.FBufferedSize);

    TXXH3Core.XXH3_accumulate_512(AAcc, PByte(@LLastStripe[0]),
      LSecret + TXXH3Core.XXH3_SECRET_LIMIT -
      TXXH3Core.XXH_SECRET_LASTACC_START);
  end;
end;

procedure TXXHash128.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LPtrInput, LPtrEnd: PByte;
  LLoadSize, LRemaining: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LPtrInput := PByte(AData) + AIndex;
  LPtrEnd := LPtrInput + UInt32(ALength);
  FState.FTotalLength := FState.FTotalLength + UInt64(ALength);

  if FState.FBufferedSize + UInt32(ALength) <=
    UInt32(TXXH3Core.XXH3_INTERNALBUFFER_SIZE) then
  begin
    System.Move(LPtrInput^, FState.FBuffer[FState.FBufferedSize], ALength);
    FState.FBufferedSize := FState.FBufferedSize + UInt32(ALength);
    Exit;
  end;

  LLoadSize := TXXH3Core.XXH3_INTERNALBUFFER_SIZE -
    Int32(FState.FBufferedSize);
  System.Move(LPtrInput^, FState.FBuffer[FState.FBufferedSize], LLoadSize);
  LPtrInput := LPtrInput + LLoadSize;

  TXXH3Core.XXH3_consumeStripes(FState.FAcc, FState.FNbStripesSoFar,
    TXXH3Core.XXH3_STRIPES_PER_BLOCK, PByte(FState.FBuffer),
    PByte(FState.FCustomSecret), TXXH3Core.XXH3_INTERNALBUFFER_STRIPES,
    TXXH3Core.XXH3_SECRET_LIMIT);
  FState.FBufferedSize := 0;

  if LPtrEnd - LPtrInput > TXXH3Core.XXH3_INTERNALBUFFER_SIZE then
  begin
    repeat
      TXXH3Core.XXH3_consumeStripes(FState.FAcc, FState.FNbStripesSoFar,
        TXXH3Core.XXH3_STRIPES_PER_BLOCK, LPtrInput,
        PByte(FState.FCustomSecret), TXXH3Core.XXH3_INTERNALBUFFER_STRIPES,
        TXXH3Core.XXH3_SECRET_LIMIT);
      LPtrInput := LPtrInput + TXXH3Core.XXH3_INTERNALBUFFER_SIZE;
    until not(LPtrEnd - LPtrInput > TXXH3Core.XXH3_INTERNALBUFFER_SIZE);

    System.Move((LPtrInput - TXXH3Core.XXH_STRIPE_LEN)^,
      FState.FBuffer[TXXH3Core.XXH3_INTERNALBUFFER_SIZE -
      TXXH3Core.XXH_STRIPE_LEN], TXXH3Core.XXH_STRIPE_LEN);
  end;

  LRemaining := LPtrEnd - LPtrInput;
  System.Move(LPtrInput^, FState.FBuffer[0], LRemaining);
  FState.FBufferedSize := UInt32(LRemaining);
end;

function TXXHash128.TransformFinal: IHashResult;
var
  LAcc: TXXH3AccArray;
  LBufferBytes: THashLibByteArray;
begin
  if FState.FTotalLength > UInt64(TXXH3Core.XXH3_MIDSIZE_MAX) then
  begin
    System.Move(FState.FAcc, LAcc, System.SizeOf(TXXH3AccArray));
    DigestLong(LAcc);
    FHashLow := TXXH3Core.XXH3_mergeAccs(LAcc,
      PByte(FState.FCustomSecret) + TXXH3Core.XXH_SECRET_MERGEACCS_START,
      FState.FTotalLength * TXXH3Core.XXH_PRIME64_1);
    FHashHigh := TXXH3Core.XXH3_mergeAccs(LAcc,
      PByte(FState.FCustomSecret) + TXXH3Core.XXH3_SECRET_DEFAULT_SIZE -
      TXXH3Core.XXH3_ACC_SIZE - TXXH3Core.XXH_SECRET_MERGEACCS_START,
      not (FState.FTotalLength * TXXH3Core.XXH_PRIME64_2));
  end
  else
  begin
    XXH3_128bits_internal(PByte(FState.FBuffer),
      Int32(FState.FTotalLength), FKey,
      PByte(@TXXH3Core.XXH3_SECRET[0]),
      TXXH3Core.XXH3_SECRET_DEFAULT_SIZE,
      FHashLow, FHashHigh);
  end;

  System.SetLength(LBufferBytes, HashSize);
  TConverters.ReadUInt64AsBytesBE(FHashHigh, LBufferBytes, 0);
  TConverters.ReadUInt64AsBytesBE(FHashLow, LBufferBytes, 8);

  Result := THashResult.Create(LBufferBytes);
  Initialize();
end;

end.
