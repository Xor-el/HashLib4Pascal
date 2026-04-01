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

procedure XXH3_Accumulate512_Scalar(AAcc: Pointer; AInput: Pointer;
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

procedure XXH3_ScrambleAcc_Scalar(AAcc: Pointer; ASecret: Pointer);
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

procedure XXH3_InitSecret_Scalar(ACustomSecret: Pointer;
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

procedure XXH3_Accumulate_Scalar(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    XXH3_Accumulate512_Scalar(AAcc, PByte(AInput) + N * XXH_STRIPE_LEN,
      PByte(ASecret) + N * XXH_SECRET_CONSUME_RATE);
end;

// =============================================================================
// SIMD implementations: SSE2 (IA-32); SSE2 / SSSE3 / AVX2 (x86-64)
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure XXH3_Accumulate512_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc3Begin_i386.inc}
  {$I ..\Include\Simd\XXH3\XXH3Acc512Sse2_i386.inc}
end;

procedure XXH3_ScrambleAcc_Sse2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin_i386.inc}
  {$I ..\Include\Simd\XXH3\XXH3ScrambleSse2_i386.inc}
end;

procedure XXH3_InitSecret_Sse2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\Include\Simd\Common\SimdProc3Begin_i386.inc}
  {$I ..\Include\Simd\XXH3\XXH3InitSecretSse2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

// ----- SSE2 -----

procedure XXH3_Accumulate512_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3Acc512Sse2_x86_64.inc}
end;

procedure XXH3_ScrambleAcc_Sse2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3ScrambleSse2_x86_64.inc}
end;

procedure XXH3_InitSecret_Sse2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3InitSecretSse2_x86_64.inc}
end;

// ----- AVX2 -----

procedure XXH3_Accumulate512_Avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3Acc512Avx2_x86_64.inc}
end;

procedure XXH3_ScrambleAcc_Avx2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3ScrambleAvx2_x86_64.inc}
end;

procedure XXH3_InitSecret_Avx2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
  {$I ..\Include\Simd\XXH3\XXH3InitSecretAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_X86_SIMD}

type
  TXXH3_Accumulate512Proc = procedure(AAcc, AInput, ASecret: Pointer);

procedure XXH3_Accumulate_Loop(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32; AAcc512: TXXH3_Accumulate512Proc);
var
  N: Int32;
begin
  for N := 0 to ANbStripes - 1 do
    AAcc512(AAcc, PByte(AInput) + N * XXH_STRIPE_LEN,
      PByte(ASecret) + N * XXH_SECRET_CONSUME_RATE);
end;

procedure XXH3_Accumulate_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
begin
  XXH3_Accumulate_Loop(AAcc, AInput, ASecret, ANbStripes, @XXH3_Accumulate512_Sse2);
end;

{$ENDIF HASHLIB_X86_SIMD}

{$IFDEF HASHLIB_X86_64_ASM}

procedure XXH3_Accumulate_Avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
begin
  XXH3_Accumulate_Loop(AAcc, AInput, ASecret, ANbStripes, @XXH3_Accumulate512_Avx2);
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  XXH3_Accumulate512 := @XXH3_Accumulate512_Scalar;
  XXH3_Accumulate := @XXH3_Accumulate_Scalar;
  XXH3_ScrambleAcc := @XXH3_ScrambleAcc_Scalar;
  XXH3_InitSecret := @XXH3_InitSecret_Scalar;
{$IFDEF HASHLIB_I386_ASM}
  case TSimd.GetActiveLevel() of
    TSimdLevel.SSE2, TSimdLevel.SSSE3:
    begin
      XXH3_Accumulate512 := @XXH3_Accumulate512_Sse2;
      XXH3_Accumulate := @XXH3_Accumulate_Sse2;
      XXH3_ScrambleAcc := @XXH3_ScrambleAcc_Sse2;
      XXH3_InitSecret := @XXH3_InitSecret_Sse2;
    end;
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      XXH3_Accumulate512 := @XXH3_Accumulate512_Avx2;
      XXH3_Accumulate := @XXH3_Accumulate_Avx2;
      XXH3_ScrambleAcc := @XXH3_ScrambleAcc_Avx2;
      XXH3_InitSecret := @XXH3_InitSecret_Avx2;
    end;
    TSimdLevel.SSE2, TSimdLevel.SSSE3:
    begin
      XXH3_Accumulate512 := @XXH3_Accumulate512_Sse2;
      XXH3_Accumulate := @XXH3_Accumulate_Sse2;
      XXH3_ScrambleAcc := @XXH3_ScrambleAcc_Sse2;
      XXH3_InitSecret := @XXH3_InitSecret_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
