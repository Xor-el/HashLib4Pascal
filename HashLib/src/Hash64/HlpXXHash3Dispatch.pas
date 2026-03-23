unit HlpXXHash3Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TXXH3Accumulate512Proc = procedure(AAcc: Pointer; AInput: Pointer;
    ASecret: Pointer);
  TXXH3AccumulateProc = procedure(AAcc: Pointer; AInput: Pointer;
    ASecret: Pointer; ANbStripes: Int32);
  TXXH3ScrambleAccProc = procedure(AAcc: Pointer; ASecret: Pointer);
  TXXH3InitSecretProc = procedure(ACustomSecret: Pointer;
    ADefaultSecret: Pointer; ASeed: UInt64);

var
  XXH3_Accumulate512: TXXH3Accumulate512Proc;
  XXH3_Accumulate: TXXH3AccumulateProc;
  XXH3_ScrambleAcc: TXXH3ScrambleAccProc;
  XXH3_InitSecret: TXXH3InitSecretProc;

implementation

uses
  HlpSimd;

const
  XXH_STRIPE_LEN = 64;
  XXH_ACC_NB = 8;
  XXH_SECRET_CONSUME_RATE = 8;
  XXH_PRIME32_1 = UInt32($9E3779B1);

// =============================================================================
// Scalar fallback implementations
// =============================================================================

procedure XXH3_accumulate_512_scalar(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
var
  LPAcc: PUInt64;
  LPInput, LPSecret: PByte;
  I: Int32;
  LDataVal, LDataKey: UInt64;
begin
  LPAcc := PUInt64(AAcc);
  LPInput := PByte(AInput);
  LPSecret := PByte(ASecret);
  for I := 0 to XXH_ACC_NB - 1 do
  begin
    LDataVal := PUInt64(LPInput + I * 8)^;
    LDataKey := LDataVal xor PUInt64(LPSecret + I * 8)^;
    PUInt64(PByte(LPAcc) + (I xor 1) * 8)^ :=
      PUInt64(PByte(LPAcc) + (I xor 1) * 8)^ + LDataVal;
    PUInt64(PByte(LPAcc) + I * 8)^ :=
      PUInt64(PByte(LPAcc) + I * 8)^ +
      UInt64(UInt32(LDataKey)) * UInt64(UInt32(LDataKey shr 32));
  end;
end;

procedure XXH3_scrambleAcc_scalar(AAcc: Pointer; ASecret: Pointer);
var
  LPAcc: PUInt64;
  LPSecret: PByte;
  I: Int32;
  LKey64, LAcc64: UInt64;
begin
  LPAcc := PUInt64(AAcc);
  LPSecret := PByte(ASecret);
  for I := 0 to XXH_ACC_NB - 1 do
  begin
    LKey64 := PUInt64(LPSecret + I * 8)^;
    LAcc64 := PUInt64(PByte(LPAcc) + I * 8)^;
    LAcc64 := LAcc64 xor (LAcc64 shr 47);
    LAcc64 := LAcc64 xor LKey64;
    LAcc64 := LAcc64 * XXH_PRIME32_1;
    PUInt64(PByte(LPAcc) + I * 8)^ := LAcc64;
  end;
end;

procedure XXH3_initSecret_scalar(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
var
  I: Int32;
  LPSrc, LPDst: PByte;
begin
  LPSrc := PByte(ADefaultSecret);
  LPDst := PByte(ACustomSecret);
  for I := 0 to (192 div 16) - 1 do
  begin
    PUInt64(LPDst + 16 * I)^ := PUInt64(LPSrc + 16 * I)^ + ASeed;
    PUInt64(LPDst + 16 * I + 8)^ := PUInt64(LPSrc + 16 * I + 8)^ - ASeed;
  end;
end;

procedure XXH3_accumulate_scalar(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    XXH3_accumulate_512_scalar(AAcc, PByte(AInput) + N * XXH_STRIPE_LEN,
      PByte(ASecret) + N * XXH_SECRET_CONSUME_RATE);
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

// ----- SSE2 -----

procedure XXH3_accumulate_512_sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc3Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3Acc512Sse2.inc}
end;

procedure XXH3_scrambleAcc_sse2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3ScrambleSse2.inc}
end;

procedure XXH3_initSecret_sse2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\Include\Simd\Common\SimdProc3Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3InitSecretSse2.inc}
end;

procedure XXH3_accumulate_sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    XXH3_accumulate_512_sse2(AAcc, PByte(AInput) + N * XXH_STRIPE_LEN,
      PByte(ASecret) + N * XXH_SECRET_CONSUME_RATE);
end;

{$IFDEF HASHLIB_AVX2_ASM_SUPPORTED}

// ----- AVX2 -----

procedure XXH3_accumulate_512_avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc3Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3Acc512Avx2.inc}
end;

procedure XXH3_scrambleAcc_avx2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3ScrambleAvx2.inc}
end;

procedure XXH3_initSecret_avx2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\Include\Simd\Common\SimdProc3Begin.inc}
  {$I ..\Include\Simd\XXH3\XXH3InitSecretAvx2.inc}
end;

procedure XXH3_accumulate_avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    XXH3_accumulate_512_avx2(AAcc, PByte(AInput) + N * XXH_STRIPE_LEN,
      PByte(ASecret) + N * XXH_SECRET_CONSUME_RATE);
end;

{$ENDIF HASHLIB_AVX2_ASM_SUPPORTED}

{$ENDIF HASHLIB_X86_64}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  case TSimd.GetActiveLevel() of
{$IFDEF HASHLIB_X86_64}
  {$IFDEF HASHLIB_AVX2_ASM_SUPPORTED}
    TSimdLevel.AVX2:
    begin
      XXH3_Accumulate512 := @XXH3_accumulate_512_avx2;
      XXH3_Accumulate := @XXH3_accumulate_avx2;
      XXH3_ScrambleAcc := @XXH3_scrambleAcc_avx2;
      XXH3_InitSecret := @XXH3_initSecret_avx2;
    end;
  {$ENDIF HASHLIB_AVX2_ASM_SUPPORTED}
    TSimdLevel.SSE2:
    begin
      XXH3_Accumulate512 := @XXH3_accumulate_512_sse2;
      XXH3_Accumulate := @XXH3_accumulate_sse2;
      XXH3_ScrambleAcc := @XXH3_scrambleAcc_sse2;
      XXH3_InitSecret := @XXH3_initSecret_sse2;
    end;
{$ENDIF}
    TSimdLevel.Scalar:
    begin
      XXH3_Accumulate512 := @XXH3_accumulate_512_scalar;
      XXH3_Accumulate := @XXH3_accumulate_scalar;
      XXH3_ScrambleAcc := @XXH3_scrambleAcc_scalar;
      XXH3_InitSecret := @XXH3_initSecret_scalar;
    end;
  end;
end;

initialization
  InitDispatch();

end.
