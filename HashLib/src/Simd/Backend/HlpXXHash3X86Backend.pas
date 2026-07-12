unit HlpXXHash3X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpXXHash3;

type
  /// <summary>
  /// x86 SIMD backend for XXH3: owns the SSE2 / AVX2 accumulate / scramble /
  /// init-secret kernels (bodies in <c>Include\Simd\XXH3\</c>) and the runtime
  /// tier selection via <c>TCpuFeatures.X86</c>. Compiles on every target -
  /// without x86 SIMD the selectors return the scalar routines.
  /// </summary>
  TXXHash3X86Backend = class sealed
  public
    class function SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc; static;
    class function SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc; static;
    class function SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc; static;
    class function SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   i386:    AVX2, SSE2
//   x86_64:  AVX2, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure XXH3_Accumulate512_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3Acc512Sse2_i386.inc}
end;

procedure XXH3_ScrambleAcc_Sse2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3ScrambleSse2_i386.inc}
end;

procedure XXH3_InitSecret_Sse2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3InitSecretSse2_i386.inc}
end;

procedure XXH3_Accumulate512_Avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3Acc512Avx2_i386.inc}
end;

procedure XXH3_ScrambleAcc_Avx2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3ScrambleAvx2_i386.inc}
end;

procedure XXH3_InitSecret_Avx2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_i386.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3InitSecretAvx2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure XXH3_Accumulate512_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3Acc512Sse2_x86_64.inc}
end;

procedure XXH3_ScrambleAcc_Sse2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3ScrambleSse2_x86_64.inc}
end;

procedure XXH3_InitSecret_Sse2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3InitSecretSse2_x86_64.inc}
end;

procedure XXH3_Accumulate512_Avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3Acc512Avx2_x86_64.inc}
end;

procedure XXH3_ScrambleAcc_Avx2(AAcc: Pointer; ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3ScrambleAvx2_x86_64.inc}
end;

procedure XXH3_InitSecret_Avx2(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_x86_64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3InitSecretAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure XXH3_Accumulate_Sse2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
begin
  XXH3_Accumulate_Loop(AAcc, AInput, ASecret, ANbStripes, @XXH3_Accumulate512_Sse2);
end;

procedure XXH3_Accumulate_Avx2(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
begin
  XXH3_Accumulate_Loop(AAcc, AInput, ASecret, ANbStripes, @XXH3_Accumulate512_Avx2);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TXXHash3X86Backend }

class function TXXHash3X86Backend.SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@XXH3_Accumulate512_Avx2);
    TX86SimdLevel.SSE2:
      Exit(@XXH3_Accumulate512_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3X86Backend.SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@XXH3_Accumulate_Avx2);
    TX86SimdLevel.SSE2:
      Exit(@XXH3_Accumulate_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3X86Backend.SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@XXH3_ScrambleAcc_Avx2);
    TX86SimdLevel.SSE2:
      Exit(@XXH3_ScrambleAcc_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3X86Backend.SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@XXH3_InitSecret_Avx2);
    TX86SimdLevel.SSE2:
      Exit(@XXH3_InitSecret_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
