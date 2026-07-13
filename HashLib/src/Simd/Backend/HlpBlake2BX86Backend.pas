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

const
  // vpshufb byte-rotation masks for the AVX2 kernel: rotr64 by 24 (at +0) and
  // by 16 (at +32) as single byte shuffles. Each 128-bit pattern is stored
  // twice to fill a 256-bit register. Matches the official BLAKE2 AVX2
  // implementation's r24/r16 shuffle constants.
  BLAKE2B_ROT_MASKS: array [0 .. 7] of UInt64 = (
    UInt64($0201000706050403), UInt64($0A09080F0E0D0C0B),
    UInt64($0201000706050403), UInt64($0A09080F0E0D0C0B),
    UInt64($0100070605040302), UInt64($09080F0E0D0C0B0A),
    UInt64($0100070605040302), UInt64($09080F0E0D0C0B0A)
  );

// =============================================================================
// SIMD kernels
//   i386:    AVX2, SSSE3, SSE2
//   x86_64:  AVX2, SSSE3, SSE2
// =============================================================================

procedure Blake2B_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressSse2_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressSse2_i386.inc}
{$ENDIF}
end;

procedure Blake2B_Compress_Ssse3(AState, AMsg, ACounterFlags, AIV,
  AMasks: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressSsse3_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressSsse3_i386.inc}
{$ENDIF}
end;

procedure Blake2B_Compress_Ssse3_Wrap(AState, AMsg, ACounterFlags,
  AIV: Pointer);
begin
  Blake2B_Compress_Ssse3(AState, AMsg, ACounterFlags, AIV,
    @BLAKE2B_ROT_MASKS);
end;

procedure Blake2B_Compress_Avx2(AState, AMsg, ACounterFlags, AIV,
  AMasks: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressAvx2_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2B\Blake2BCompressAvx2_i386.inc}
{$ENDIF}
end;

procedure Blake2B_Compress_Avx2_Wrap(AState, AMsg, ACounterFlags,
  AIV: Pointer);
begin
  Blake2B_Compress_Avx2(AState, AMsg, ACounterFlags, AIV,
    @BLAKE2B_ROT_MASKS);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TBlake2BX86Backend }

class function TBlake2BX86Backend.Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Blake2B_Compress_Avx2_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@Blake2B_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@Blake2B_Compress_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
