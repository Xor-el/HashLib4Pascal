unit HlpXXHash3;

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
  HlpBits;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type
  TXXH3AccArray = array [0 .. 7] of UInt64;

  TXXH3Core = class sealed(TObject)

  public

    const

    XXH3_SECRET_DEFAULT_SIZE = Int32(192);
    XXH3_SECRET_SIZE_MIN = Int32(136);
    XXH_STRIPE_LEN = Int32(64);
    XXH_ACC_NB = Int32(8);
    XXH_SECRET_CONSUME_RATE = Int32(8);
    XXH_SECRET_MERGEACCS_START = Int32(11);
    XXH_SECRET_LASTACC_START = Int32(7);
    XXH3_MIDSIZE_MAX = Int32(240);
    XXH3_MIDSIZE_STARTOFFSET = Int32(3);
    XXH3_MIDSIZE_LASTOFFSET = Int32(17);
    XXH3_INTERNALBUFFER_SIZE = Int32(256);
    XXH3_INTERNALBUFFER_STRIPES = Int32(4);
    XXH3_ACC_SIZE = Int32(64);

    XXH_PRIME32_1 = UInt32($9E3779B1);
    XXH_PRIME32_2 = UInt32($85EBCA77);
    XXH_PRIME32_3 = UInt32($C2B2AE3D);

    XXH3_STRIPES_PER_BLOCK =
      (XXH3_SECRET_DEFAULT_SIZE - XXH_STRIPE_LEN) div XXH_SECRET_CONSUME_RATE;
    XXH3_SECRET_LIMIT = XXH3_SECRET_DEFAULT_SIZE - XXH_STRIPE_LEN;

    XXH3_SECRET: array [0 .. 191] of Byte = ($B8, $FE, $6C, $39, $23, $A4,
      $4B, $BE, $7C, $01, $81, $2C, $F7, $21, $AD, $1C, $DE, $D4, $6D, $E9,
      $83, $90, $97, $DB, $72, $40, $A4, $A4, $B7, $B3, $67, $1F, $CB, $79,
      $E6, $4E, $CC, $C0, $E5, $78, $82, $5A, $D0, $7D, $CC, $FF, $72, $21,
      $B8, $08, $46, $74, $F7, $43, $24, $8E, $E0, $35, $90, $E6, $81, $3A,
      $26, $4C, $3C, $28, $52, $BB, $91, $C3, $00, $CB, $88, $D0, $65, $8B,
      $1B, $53, $2E, $A3, $71, $64, $48, $97, $A2, $0D, $F9, $4E, $38, $19,
      $EF, $46, $A9, $DE, $AC, $D8, $A8, $FA, $76, $3F, $E3, $9C, $34, $3F,
      $F9, $DC, $BB, $C7, $C7, $0B, $4F, $1D, $8A, $51, $E0, $4B, $CD, $B4,
      $59, $31, $C8, $9F, $7E, $C9, $D9, $78, $73, $64, $EA, $C5, $AC, $83,
      $34, $D3, $EB, $C3, $C5, $81, $A0, $FF, $FA, $13, $63, $EB, $17, $0D,
      $DD, $51, $B7, $F0, $DA, $49, $D3, $16, $55, $26, $29, $D4, $68, $9E,
      $2B, $16, $BE, $58, $7D, $47, $A1, $FC, $8F, $F8, $B8, $D1, $7A, $D0,
      $31, $CE, $45, $CB, $3A, $8F, $95, $16, $04, $28, $AF, $D7, $FB, $CA,
      $BB, $4B, $40, $7E);

    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
    XXH_PRIME64_1: UInt64 = UInt64($9E3779B185EBCA87);
    XXH_PRIME64_2: UInt64 = UInt64($C2B2AE3D27D4EB4F);
    XXH_PRIME64_3: UInt64 = UInt64($165667B19E3779F9);
    XXH_PRIME64_4: UInt64 = UInt64($85EBCA77C2B2AE63);
    XXH_PRIME64_5: UInt64 = UInt64($27D4EB2F165667C5);

    XXH3_INIT_ACC: array [0 .. 7] of UInt64 = (UInt64($C2B2AE3D),
      UInt64($9E3779B185EBCA87), UInt64($C2B2AE3D27D4EB4F),
      UInt64($165667B19E3779F9), UInt64($85EBCA77C2B2AE63),
      UInt64($85EBCA77), UInt64($27D4EB2F165667C5), UInt64($9E3779B1));

    class function XXH_mult32to64(AX, AY: UInt32): UInt64; static; inline;
    class procedure XXH_mult64to128(ALhs, ARhs: UInt64;
      out ALow, AHigh: UInt64); static; inline;
    class function XXH3_mul128_fold64(ALhs, ARhs: UInt64): UInt64;
      static; inline;
    class function XXH3_avalanche(AH64: UInt64): UInt64; static; inline;
    class function XXH3_rrmxmx(AH64: UInt64; ALen: Int32): UInt64;
      static; inline;
    class function XXH64_avalanche(AH64: UInt64): UInt64; static; inline;
    class function XXH3_mix16B(AInput, ASecret: PByte; ASeed: UInt64): UInt64;
      static; inline;
    class function XXH3_mix2Accs(const AAcc: TXXH3AccArray;
      ALaneStart: Int32; ASecret: PByte): UInt64; static; inline;
    class function XXH3_mergeAccs(const AAcc: TXXH3AccArray; ASecret: PByte;
      AStart: UInt64): UInt64; static;
    class procedure XXH3_scalarRound(var AAcc: TXXH3AccArray;
      AInput, ASecret: PByte; ALane: Int32); static; inline;
    class procedure XXH3_accumulate_512(var AAcc: TXXH3AccArray;
      AInput, ASecret: PByte); static; inline;
    class procedure XXH3_scalarScrambleRound(var AAcc: TXXH3AccArray;
      ASecret: PByte; ALane: Int32); static; inline;
    class procedure XXH3_scrambleAcc(var AAcc: TXXH3AccArray;
      ASecret: PByte); static; inline;
    class procedure XXH3_accumulate(var AAcc: TXXH3AccArray;
      AInput, ASecret: PByte; ANbStripes: Int32); static;
    class procedure XXH3_hashLong_internal_loop(var AAcc: TXXH3AccArray;
      AInput: PByte; ALen: Int32; ASecret: PByte; ASecretSize: Int32); static;
    class procedure XXH3_initCustomSecret(ACustomSecret: PByte;
      ASeed: UInt64); static;
    class procedure XXH3_consumeStripes(var AAcc: TXXH3AccArray;
      var ANbStripesSoFar: Int32; ANbStripesPerBlock: Int32;
      AInput, ASecret: PByte; ANbStripes, ASecretLimit: Int32); static;
  end;

  TXXHash3 = class sealed(THash, IHash64, IHashWithKey, ITransformBlock)

  strict private
  var
    FKey, FHash: UInt64;

  const
    CKEY = UInt64(0);

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

  type

    TXXH3_State = record

    private
    var
      FAcc: TXXH3AccArray;
      FCustomSecret: THashLibByteArray;
      FBuffer: THashLibByteArray;
      FBufferedSize: UInt32;
      FNbStripesSoFar: Int32;
      FTotalLength: UInt64;

      function Clone(): TXXH3_State;

    end;

  strict private
  var
    FState: TXXH3_State;

    class function XXH3_len_1to3_64b(AInput, ASecret: PByte; ALen: Int32;
      ASeed: UInt64): UInt64; static;
    class function XXH3_len_4to8_64b(AInput, ASecret: PByte; ALen: Int32;
      ASeed: UInt64): UInt64; static;
    class function XXH3_len_9to16_64b(AInput, ASecret: PByte; ALen: Int32;
      ASeed: UInt64): UInt64; static;
    class function XXH3_len_0to16_64b(AInput, ASecret: PByte; ALen: Int32;
      ASeed: UInt64): UInt64; static;
    class function XXH3_len_17to128_64b(AInput, ASecret: PByte;
      ALen, ASecretSize: Int32; ASeed: UInt64): UInt64; static;
    class function XXH3_len_129to240_64b(AInput, ASecret: PByte;
      ALen, ASecretSize: Int32; ASeed: UInt64): UInt64; static;
    class function XXH3_hashLong_64b_internal(AInput: PByte; ALen: Int32;
      ASecret: PByte; ASecretSize: Int32): UInt64; static;
    class function XXH3_hashLong_64b_withSeed(AInput: PByte; ALen: Int32;
      ASeed: UInt64): UInt64; static;
    class function XXH3_64bits_internal(AInput: PByte; ALen: Int32;
      ASeed: UInt64; ASecret: PByte; ASecretLen: Int32): UInt64; static;

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

{ TXXH3Core }

class function TXXH3Core.XXH_mult32to64(AX, AY: UInt32): UInt64;
begin
  Result := UInt64(AX) * UInt64(AY);
end;

class procedure TXXH3Core.XXH_mult64to128(ALhs, ARhs: UInt64;
  out ALow, AHigh: UInt64);
var
  LLoLo, LHiLo, LLoHi, LHiHi, LCross: UInt64;
begin
  LLoLo := UInt64(UInt32(ALhs)) * UInt64(UInt32(ARhs));
  LHiLo := UInt64(UInt32(ALhs shr 32)) * UInt64(UInt32(ARhs));
  LLoHi := UInt64(UInt32(ALhs)) * UInt64(UInt32(ARhs shr 32));
  LHiHi := UInt64(UInt32(ALhs shr 32)) * UInt64(UInt32(ARhs shr 32));

  LCross := (LLoLo shr 32) + (LHiLo and $FFFFFFFF) + LLoHi;
  AHigh := (LHiLo shr 32) + (LCross shr 32) + LHiHi;
  ALow := (LCross shl 32) or (LLoLo and $FFFFFFFF);
end;

class function TXXH3Core.XXH3_mul128_fold64(ALhs, ARhs: UInt64): UInt64;
var
  LLow, LHigh: UInt64;
begin
  XXH_mult64to128(ALhs, ARhs, LLow, LHigh);
  Result := LLow xor LHigh;
end;

class function TXXH3Core.XXH3_avalanche(AH64: UInt64): UInt64;
begin
  AH64 := AH64 xor (AH64 shr 37);
  AH64 := AH64 * UInt64($165667919E3779F9);
  AH64 := AH64 xor (AH64 shr 32);
  Result := AH64;
end;

class function TXXH3Core.XXH3_rrmxmx(AH64: UInt64; ALen: Int32): UInt64;
begin
  AH64 := AH64 xor (TBits.RotateLeft64(AH64, 49) xor
    TBits.RotateLeft64(AH64, 24));
  AH64 := AH64 * UInt64($9FB21C651E98DF25);
  AH64 := AH64 xor ((AH64 shr 35) + UInt64(ALen));
  AH64 := AH64 * UInt64($9FB21C651E98DF25);
  AH64 := AH64 xor (AH64 shr 28);
  Result := AH64;
end;

class function TXXH3Core.XXH64_avalanche(AH64: UInt64): UInt64;
begin
  AH64 := AH64 xor (AH64 shr 33);
  AH64 := AH64 * XXH_PRIME64_2;
  AH64 := AH64 xor (AH64 shr 29);
  AH64 := AH64 * XXH_PRIME64_3;
  AH64 := AH64 xor (AH64 shr 32);
  Result := AH64;
end;

class function TXXH3Core.XXH3_mix16B(AInput, ASecret: PByte;
  ASeed: UInt64): UInt64;
var
  LInputLo, LInputHi: UInt64;
begin
  LInputLo := TConverters.ReadBytesAsUInt64LE(AInput, 0);
  LInputHi := TConverters.ReadBytesAsUInt64LE(AInput, 8);
  Result := XXH3_mul128_fold64(LInputLo xor
    (TConverters.ReadBytesAsUInt64LE(ASecret, 0) + ASeed),
    LInputHi xor (TConverters.ReadBytesAsUInt64LE(ASecret, 8) - ASeed));
end;

class function TXXH3Core.XXH3_mix2Accs(const AAcc: TXXH3AccArray;
  ALaneStart: Int32; ASecret: PByte): UInt64;
begin
  Result := XXH3_mul128_fold64(AAcc[ALaneStart] xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 0),
    AAcc[ALaneStart + 1] xor TConverters.ReadBytesAsUInt64LE(ASecret, 8));
end;

class function TXXH3Core.XXH3_mergeAccs(const AAcc: TXXH3AccArray;
  ASecret: PByte; AStart: UInt64): UInt64;
var
  I: Int32;
begin
  Result := AStart;
  for I := 0 to 3 do
    Result := Result + XXH3_mix2Accs(AAcc, 2 * I, ASecret + 16 * I);
  Result := XXH3_avalanche(Result);
end;

class procedure TXXH3Core.XXH3_scalarRound(var AAcc: TXXH3AccArray;
  AInput, ASecret: PByte; ALane: Int32);
var
  LDataVal, LDataKey: UInt64;
begin
  LDataVal := TConverters.ReadBytesAsUInt64LE(AInput, ALane * 8);
  LDataKey := LDataVal xor TConverters.ReadBytesAsUInt64LE(ASecret, ALane * 8);
  AAcc[ALane xor 1] := AAcc[ALane xor 1] + LDataVal;
  AAcc[ALane] := AAcc[ALane] + XXH_mult32to64(UInt32(LDataKey),
    UInt32(LDataKey shr 32));
end;

class procedure TXXH3Core.XXH3_accumulate_512(var AAcc: TXXH3AccArray;
  AInput, ASecret: PByte);
var
  I: Int32;
begin
  for I := 0 to XXH_ACC_NB - 1 do
    XXH3_scalarRound(AAcc, AInput, ASecret, I);
end;

class procedure TXXH3Core.XXH3_scalarScrambleRound(var AAcc: TXXH3AccArray;
  ASecret: PByte; ALane: Int32);
var
  LKey64, LAcc64: UInt64;
begin
  LKey64 := TConverters.ReadBytesAsUInt64LE(ASecret, ALane * 8);
  LAcc64 := AAcc[ALane];
  LAcc64 := LAcc64 xor (LAcc64 shr 47);
  LAcc64 := LAcc64 xor LKey64;
  LAcc64 := LAcc64 * XXH_PRIME32_1;
  AAcc[ALane] := LAcc64;
end;

class procedure TXXH3Core.XXH3_scrambleAcc(var AAcc: TXXH3AccArray;
  ASecret: PByte);
var
  I: Int32;
begin
  for I := 0 to XXH_ACC_NB - 1 do
    XXH3_scalarScrambleRound(AAcc, ASecret, I);
end;

class procedure TXXH3Core.XXH3_accumulate(var AAcc: TXXH3AccArray;
  AInput, ASecret: PByte; ANbStripes: Int32);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    XXH3_accumulate_512(AAcc, AInput + N * XXH_STRIPE_LEN,
      ASecret + N * XXH_SECRET_CONSUME_RATE);
end;

class procedure TXXH3Core.XXH3_hashLong_internal_loop(
  var AAcc: TXXH3AccArray; AInput: PByte; ALen: Int32; ASecret: PByte;
  ASecretSize: Int32);
var
  LNbStripesPerBlock, LBlockLen, LNbBlocks, LNbStripes, N: Int32;
  LP: PByte;
begin
  LNbStripesPerBlock := (ASecretSize - XXH_STRIPE_LEN) div
    XXH_SECRET_CONSUME_RATE;
  LBlockLen := XXH_STRIPE_LEN * LNbStripesPerBlock;
  LNbBlocks := (ALen - 1) div LBlockLen;

  for N := 0 to LNbBlocks - 1 do
  begin
    XXH3_accumulate(AAcc, AInput + N * LBlockLen, ASecret,
      LNbStripesPerBlock);
    XXH3_scrambleAcc(AAcc, ASecret + ASecretSize - XXH_STRIPE_LEN);
  end;

  LNbStripes := ((ALen - 1) - (LBlockLen * LNbBlocks)) div XXH_STRIPE_LEN;
  XXH3_accumulate(AAcc, AInput + LNbBlocks * LBlockLen, ASecret, LNbStripes);

  LP := AInput + ALen - XXH_STRIPE_LEN;
  XXH3_accumulate_512(AAcc, LP, ASecret + ASecretSize - XXH_STRIPE_LEN -
    XXH_SECRET_LASTACC_START);
end;

class procedure TXXH3Core.XXH3_initCustomSecret(ACustomSecret: PByte;
  ASeed: UInt64);
var
  I: Int32;
  LLo, LHi: UInt64;
begin
  for I := 0 to (XXH3_SECRET_DEFAULT_SIZE div 16) - 1 do
  begin
    LLo := TConverters.ReadBytesAsUInt64LE(PByte(@XXH3_SECRET[0]),
      16 * I) + ASeed;
    LHi := TConverters.ReadBytesAsUInt64LE(PByte(@XXH3_SECRET[0]),
      16 * I + 8) - ASeed;
    PUInt64(ACustomSecret + 16 * I)^ := LLo;
    PUInt64(ACustomSecret + 16 * I + 8)^ := LHi;
  end;
end;

class procedure TXXH3Core.XXH3_consumeStripes(var AAcc: TXXH3AccArray;
  var ANbStripesSoFar: Int32; ANbStripesPerBlock: Int32;
  AInput, ASecret: PByte; ANbStripes, ASecretLimit: Int32);
var
  LNbStripesToEnd: Int32;
begin
  if ANbStripesPerBlock - ANbStripesSoFar <= ANbStripes then
  begin
    LNbStripesToEnd := ANbStripesPerBlock - ANbStripesSoFar;
    XXH3_accumulate(AAcc, AInput,
      ASecret + ANbStripesSoFar * XXH_SECRET_CONSUME_RATE, LNbStripesToEnd);
    XXH3_scrambleAcc(AAcc, ASecret + ASecretLimit);
    ANbStripesSoFar := 0;
    AInput := AInput + LNbStripesToEnd * XXH_STRIPE_LEN;
    ANbStripes := ANbStripes - LNbStripesToEnd;

    while ANbStripes >= ANbStripesPerBlock do
    begin
      XXH3_accumulate(AAcc, AInput, ASecret, ANbStripesPerBlock);
      XXH3_scrambleAcc(AAcc, ASecret + ASecretLimit);
      AInput := AInput + ANbStripesPerBlock * XXH_STRIPE_LEN;
      ANbStripes := ANbStripes - ANbStripesPerBlock;
    end;

    XXH3_accumulate(AAcc, AInput, ASecret, ANbStripes);
    ANbStripesSoFar := ANbStripes;
  end
  else
  begin
    XXH3_accumulate(AAcc, AInput,
      ASecret + ANbStripesSoFar * XXH_SECRET_CONSUME_RATE, ANbStripes);
    ANbStripesSoFar := ANbStripesSoFar + ANbStripes;
  end;
end;

{ TXXHash3.TXXH3_State }

function TXXHash3.TXXH3_State.Clone(): TXXH3_State;
begin
  Result := Default(TXXH3_State);
  System.Move(FAcc, Result.FAcc, System.SizeOf(TXXH3AccArray));
  Result.FCustomSecret := System.Copy(FCustomSecret);
  Result.FBuffer := System.Copy(FBuffer);
  Result.FBufferedSize := FBufferedSize;
  Result.FNbStripesSoFar := FNbStripesSoFar;
  Result.FTotalLength := FTotalLength;
end;

{ TXXHash3 }

constructor TXXHash3.Create;
begin
  inherited Create(8, 64);
  FKey := CKEY;
  System.SetLength(FState.FBuffer, TXXH3Core.XXH3_INTERNALBUFFER_SIZE);
  System.SetLength(FState.FCustomSecret, TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);
end;

function TXXHash3.Clone(): IHash;
var
  LHashInstance: TXXHash3;
begin
  LHashInstance := TXXHash3.Create();
  LHashInstance.FKey := FKey;
  LHashInstance.FHash := FHash;
  LHashInstance.FState := FState.Clone();
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

function TXXHash3.GetKey: THashLibByteArray;
begin
  Result := TConverters.ReadUInt64AsBytesLE(FKey);
end;

function TXXHash3.GetKeyLength: Int32;
begin
  Result := 8;
end;

procedure TXXHash3.SetKey(const AValue: THashLibByteArray);
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

procedure TXXHash3.Initialize;
begin
  FHash := 0;
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

class function TXXHash3.XXH3_len_1to3_64b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64): UInt64;
var
  LC1, LC2, LC3: Byte;
  LCombined: UInt32;
  LBitflip, LKeyed: UInt64;
begin
  LC1 := AInput[0];
  LC2 := AInput[TBits.Asr32(ALen, 1)];
  LC3 := AInput[ALen - 1];
  LCombined := (UInt32(LC1) shl 16) or (UInt32(LC2) shl 24) or
    (UInt32(LC3) shl 0) or (UInt32(ALen) shl 8);
  LBitflip := UInt64(TConverters.ReadBytesAsUInt32LE(ASecret, 0) xor
    TConverters.ReadBytesAsUInt32LE(ASecret, 4)) + ASeed;
  LKeyed := UInt64(LCombined) xor LBitflip;
  Result := TXXH3Core.XXH64_avalanche(LKeyed);
end;

class function TXXHash3.XXH3_len_4to8_64b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64): UInt64;
var
  LInput1, LInput2: UInt32;
  LBitflip, LInput64, LKeyed: UInt64;
begin
  ASeed := ASeed xor (UInt64(TBits.ReverseBytesUInt32(UInt32(ASeed))) shl 32);
  LInput1 := TConverters.ReadBytesAsUInt32LE(AInput, 0);
  LInput2 := TConverters.ReadBytesAsUInt32LE(AInput, ALen - 4);
  LBitflip := (TConverters.ReadBytesAsUInt64LE(ASecret, 8) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 16)) - ASeed;
  LInput64 := UInt64(LInput2) + (UInt64(LInput1) shl 32);
  LKeyed := LInput64 xor LBitflip;
  Result := TXXH3Core.XXH3_rrmxmx(LKeyed, ALen);
end;

class function TXXHash3.XXH3_len_9to16_64b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64): UInt64;
var
  LBitflip1, LBitflip2, LInputLo, LInputHi, LAcc: UInt64;
begin
  LBitflip1 := (TConverters.ReadBytesAsUInt64LE(ASecret, 24) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 32)) + ASeed;
  LBitflip2 := (TConverters.ReadBytesAsUInt64LE(ASecret, 40) xor
    TConverters.ReadBytesAsUInt64LE(ASecret, 48)) - ASeed;
  LInputLo := TConverters.ReadBytesAsUInt64LE(AInput, 0) xor LBitflip1;
  LInputHi := TConverters.ReadBytesAsUInt64LE(AInput, ALen - 8) xor LBitflip2;
  LAcc := UInt64(ALen) + TBits.ReverseBytesUInt64(LInputLo) + LInputHi +
    TXXH3Core.XXH3_mul128_fold64(LInputLo, LInputHi);
  Result := TXXH3Core.XXH3_avalanche(LAcc);
end;

class function TXXHash3.XXH3_len_0to16_64b(AInput, ASecret: PByte;
  ALen: Int32; ASeed: UInt64): UInt64;
begin
  if ALen > 8 then
    Result := XXH3_len_9to16_64b(AInput, ASecret, ALen, ASeed)
  else if ALen >= 4 then
    Result := XXH3_len_4to8_64b(AInput, ASecret, ALen, ASeed)
  else if ALen <> 0 then
    Result := XXH3_len_1to3_64b(AInput, ASecret, ALen, ASeed)
  else
    Result := TXXH3Core.XXH64_avalanche(ASeed xor
      (TConverters.ReadBytesAsUInt64LE(ASecret, 56) xor
      TConverters.ReadBytesAsUInt64LE(ASecret, 64)));
end;

class function TXXHash3.XXH3_len_17to128_64b(AInput, ASecret: PByte;
  ALen, ASecretSize: Int32; ASeed: UInt64): UInt64;
var
  LAcc: UInt64;
begin
  LAcc := UInt64(ALen) * TXXH3Core.XXH_PRIME64_1;

  if ALen > 32 then
  begin
    if ALen > 64 then
    begin
      if ALen > 96 then
      begin
        LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + 48,
          ASecret + 96, ASeed);
        LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + ALen - 64,
          ASecret + 112, ASeed);
      end;
      LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + 32,
        ASecret + 64, ASeed);
      LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + ALen - 48,
        ASecret + 80, ASeed);
    end;
    LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + 16, ASecret + 32, ASeed);
    LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + ALen - 32,
      ASecret + 48, ASeed);
  end;

  LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + 0, ASecret + 0, ASeed);
  LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + ALen - 16,
    ASecret + 16, ASeed);
  Result := TXXH3Core.XXH3_avalanche(LAcc);
end;

class function TXXHash3.XXH3_len_129to240_64b(AInput, ASecret: PByte;
  ALen, ASecretSize: Int32; ASeed: UInt64): UInt64;
var
  LAcc: UInt64;
  LNbRounds, I: Int32;
begin
  LAcc := UInt64(ALen) * TXXH3Core.XXH_PRIME64_1;
  LNbRounds := ALen div 16;

  for I := 0 to 7 do
    LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + (16 * I),
      ASecret + (16 * I), ASeed);
  LAcc := TXXH3Core.XXH3_avalanche(LAcc);

  for I := 8 to LNbRounds - 1 do
    LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + (16 * I),
      ASecret + (16 * (I - 8)) + TXXH3Core.XXH3_MIDSIZE_STARTOFFSET, ASeed);

  LAcc := LAcc + TXXH3Core.XXH3_mix16B(AInput + ALen - 16,
    ASecret + TXXH3Core.XXH3_SECRET_SIZE_MIN -
    TXXH3Core.XXH3_MIDSIZE_LASTOFFSET, ASeed);
  Result := TXXH3Core.XXH3_avalanche(LAcc);
end;

class function TXXHash3.XXH3_hashLong_64b_internal(AInput: PByte;
  ALen: Int32; ASecret: PByte; ASecretSize: Int32): UInt64;
var
  LAcc: TXXH3AccArray;
begin
  System.Move(TXXH3Core.XXH3_INIT_ACC, LAcc, System.SizeOf(TXXH3AccArray));

  TXXH3Core.XXH3_hashLong_internal_loop(LAcc, AInput, ALen,
    ASecret, ASecretSize);

  Result := TXXH3Core.XXH3_mergeAccs(LAcc,
    ASecret + TXXH3Core.XXH_SECRET_MERGEACCS_START,
    UInt64(ALen) * TXXH3Core.XXH_PRIME64_1);
end;

class function TXXHash3.XXH3_hashLong_64b_withSeed(AInput: PByte;
  ALen: Int32; ASeed: UInt64): UInt64;
var
  LSecret: array [0 .. 191] of Byte;
begin
  if ASeed = 0 then
  begin
    Result := XXH3_hashLong_64b_internal(AInput, ALen,
      PByte(@TXXH3Core.XXH3_SECRET[0]), TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);
    Exit;
  end;

  TXXH3Core.XXH3_initCustomSecret(PByte(@LSecret[0]), ASeed);
  Result := XXH3_hashLong_64b_internal(AInput, ALen, PByte(@LSecret[0]),
    TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);
end;

class function TXXHash3.XXH3_64bits_internal(AInput: PByte; ALen: Int32;
  ASeed: UInt64; ASecret: PByte; ASecretLen: Int32): UInt64;
begin
  if ALen <= 16 then
    Result := XXH3_len_0to16_64b(AInput, ASecret, ALen, ASeed)
  else if ALen <= 128 then
    Result := XXH3_len_17to128_64b(AInput, ASecret, ALen, ASecretLen, ASeed)
  else if ALen <= TXXH3Core.XXH3_MIDSIZE_MAX then
    Result := XXH3_len_129to240_64b(AInput, ASecret, ALen, ASecretLen, ASeed)
  else
    Result := XXH3_hashLong_64b_withSeed(AInput, ALen, ASeed);
end;

procedure TXXHash3.DigestLong(var AAcc: TXXH3AccArray);
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

procedure TXXHash3.TransformBytes(const AData: THashLibByteArray;
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

function TXXHash3.TransformFinal: IHashResult;
var
  LAcc: TXXH3AccArray;
begin
  if FState.FTotalLength > UInt64(TXXH3Core.XXH3_MIDSIZE_MAX) then
  begin
    System.Move(FState.FAcc, LAcc, System.SizeOf(TXXH3AccArray));
    DigestLong(LAcc);
    FHash := TXXH3Core.XXH3_mergeAccs(LAcc,
      PByte(FState.FCustomSecret) + TXXH3Core.XXH_SECRET_MERGEACCS_START,
      FState.FTotalLength * TXXH3Core.XXH_PRIME64_1);
  end
  else
  begin
    FHash := XXH3_64bits_internal(PByte(FState.FBuffer),
      Int32(FState.FTotalLength), FKey,
      PByte(@TXXH3Core.XXH3_SECRET[0]),
      TXXH3Core.XXH3_SECRET_DEFAULT_SIZE);
  end;

  Result := THashResult.Create(FHash);
  Initialize();
end;

end.
