unit HlpBlake2SX86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2S;

type
  /// <summary>
  /// x86 SIMD backend for Blake2S: owns the SSE2 / AVX2 compression kernels
  /// (bodies in <c>Include\Simd\Blake2S\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86</c>. Compiles on every target - built without x86 SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TBlake2SX86Backend = class sealed
  public
    class function Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // pshufb byte-rotation masks for the AVX and SSSE3 kernels: rotr32 by 16 (at +0) and
  // by 8 (at +16) as single byte shuffles. Matches the official BLAKE2 SSSE3+
  // implementation's r16/r8 shuffle constants.
  BLAKE2S_ROT_MASKS: array [0 .. 3] of UInt64 = (
    UInt64($0504070601000302), UInt64($0D0C0F0E09080B0A),
    UInt64($0407060500030201), UInt64($0C0F0E0D080B0A09)
  );

// =============================================================================
// SIMD kernels
//   i386:    AVX2, SSSE3, SSE2
//   x86_64:  AVX2, SSSE3, SSE2
// =============================================================================

procedure Blake2S_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressSse2_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressSse2_i386.inc}
{$ENDIF}
end;

procedure Blake2S_Compress_Ssse3(AState, AMsg, ACounterFlags, AIV,
  AMasks: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressSsse3_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressSsse3_i386.inc}
{$ENDIF}
end;

procedure Blake2S_Compress_Ssse3_Wrap(AState, AMsg, ACounterFlags,
  AIV: Pointer);
begin
  Blake2S_Compress_Ssse3(AState, AMsg, ACounterFlags, AIV,
    @BLAKE2S_ROT_MASKS);
end;

procedure Blake2S_Compress_Avx(AState, AMsg, ACounterFlags, AIV,
  AMasks: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressAvx_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
{$I ..\..\Include\Simd\Blake2S\Blake2SCompressAvx_i386.inc}
{$ENDIF}
end;

procedure Blake2S_Compress_Avx_Wrap(AState, AMsg, ACounterFlags,
  AIV: Pointer);
begin
  Blake2S_Compress_Avx(AState, AMsg, ACounterFlags, AIV,
    @BLAKE2S_ROT_MASKS);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TBlake2SX86Backend }

class function TBlake2SX86Backend.Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Blake2S_Compress_Avx_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@Blake2S_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@Blake2S_Compress_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
