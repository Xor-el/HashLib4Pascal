unit HlpSHA1X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA1;

type
  /// <summary>
  /// x86 SIMD backend for SHA-1: owns the SSE2 / AVX2 / SHA-NI keystream kernels
  /// (bodies in <c>Include\Simd\SHA1\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86</c>. Compiles on every target - built without x86 SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TSHA1X86Backend = class sealed
  public
    class function Select(AScalar: TSHA1CompressProc): TSHA1CompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // BSWAP32 shuffle mask for pshufb (x86 SIMD only): byte-swaps and reverses
  // dword order in one shuffle (sha1rnds4 reads its four words in reverse). Not a
  // SHA-1 constant; used only by the SHA-NI kernel.
  BSWAP32_MASK: array [0 .. 3] of UInt32 = (
    $0C0D0E0F, $08090A0B, $04050607, $00010203
  );

  // Doubled SHA-1 round constants plus the AVX2 byte-swap masks, shared by the
  // AVX2 and SSE2 SIMD-schedule SHA-1 kernels. Each round constant fills a 128-bit
  // lane (its four dwords) and is stored twice so one table feeds both the 256-bit
  // AVX2 read and the 128-bit SSE2 reads (both read at a 32-byte stride, skipping
  // the duplicate halves). Only the AVX2 kernel uses the appended masks: the
  // byte-swap mask (BSWAP32 pattern, twice) then a whole-vector reverse mask; the
  // SSE2 kernel computes its byte-swap and needs no mask.
  K_SHA1_Doubled: array [0 .. 43] of UInt32 = (
    $5A827999, $5A827999, $5A827999, $5A827999,
    $5A827999, $5A827999, $5A827999, $5A827999,
    $6ED9EBA1, $6ED9EBA1, $6ED9EBA1, $6ED9EBA1,
    $6ED9EBA1, $6ED9EBA1, $6ED9EBA1, $6ED9EBA1,
    $8F1BBCDC, $8F1BBCDC, $8F1BBCDC, $8F1BBCDC,
    $8F1BBCDC, $8F1BBCDC, $8F1BBCDC, $8F1BBCDC,
    $CA62C1D6, $CA62C1D6, $CA62C1D6, $CA62C1D6,
    $CA62C1D6, $CA62C1D6, $CA62C1D6, $CA62C1D6,
    $00010203, $04050607, $08090A0B, $0C0D0E0F,
    $00010203, $04050607, $08090A0B, $0C0D0E0F,
    $0C0D0E0F, $08090A0B, $04050607, $00010203
  );

// =============================================================================
// SIMD kernels
//   i386:    ShaNi, AVX2, SSSE3, SSE2
//   x86_64:  ShaNi, AVX2, SSSE3, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure SHA1_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressShaNi_i386.inc}
end;

procedure SHA1_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_ShaNi(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

procedure SHA1_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressSse2_i386.inc}
end;

procedure SHA1_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressSsse3_i386.inc}
end;

procedure SHA1_Compress_Avx(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressAvx_i386.inc}
end;

procedure SHA1_Compress_Avx_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Avx(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure SHA1_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants, AMask: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressShaNi_x86_64.inc}
end;

procedure SHA1_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_ShaNi(AState, AData, ANumBlocks, @K_SHA1, @BSWAP32_MASK);
end;

procedure SHA1_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressSse2_x86_64.inc}
end;

procedure SHA1_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressSsse3_x86_64.inc}
end;

procedure SHA1_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressAvx2_x86_64.inc}
end;

procedure SHA1_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Avx2(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure SHA1_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Sse2(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

procedure SHA1_Compress_Ssse3_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Ssse3(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TSHA1X86Backend }

class function TSHA1X86Backend.Select(AScalar: TSHA1CompressProc): TSHA1CompressProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  if TCpuFeatures.X86.HasSHANI() then
    Exit(@SHA1_Compress_ShaNi_Wrap);
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@SHA1_Compress_Avx_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@SHA1_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@SHA1_Compress_Sse2_Wrap);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  if TCpuFeatures.X86.HasSHANI() then
    Exit(@SHA1_Compress_ShaNi_Wrap);
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@SHA1_Compress_Avx2_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@SHA1_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@SHA1_Compress_Sse2_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
