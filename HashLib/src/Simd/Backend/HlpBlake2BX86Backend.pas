unit HlpBlake2BX86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2B;

type
  /// <summary>
  /// x86 SIMD backend for Blake2B: owns the SSE2 / AVX2 compression kernels
  /// (bodies in <c>Include\Simd\Blake2B\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86</c>. Compiles on every target - built without x86 SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TBlake2BX86Backend = class sealed
  public
    class function Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   i386:    SSE2
//   x86_64:  AVX2, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure Blake2B_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Blake2B\Blake2BCompressSse2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Blake2B_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake2B\Blake2BCompressSse2_x86_64.inc}
end;

procedure Blake2B_Compress_Avx2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake2B\Blake2BCompressAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TBlake2BX86Backend }

class function TBlake2BX86Backend.Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(@Blake2B_Compress_Sse2);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Blake2B_Compress_Avx2);
    TX86SimdLevel.SSE2:
      Exit(@Blake2B_Compress_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
