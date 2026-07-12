unit HlpSHA2_256X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA2_256Base;

type
  /// <summary>
  /// x86 SIMD backend for SHA-256: owns the SSE2 / AVX2 / SHA-NI keystream
  /// kernels (bodies in <c>Include\Simd\SHA256\</c>) and the runtime tier
  /// selection via <c>TCpuFeatures.X86</c>. Compiles on every target - built
  /// without x86 SIMD, <c>Select</c> just returns the scalar routine.
  /// </summary>
  TSHA2_256X86Backend = class sealed
  public
    class function Select(AScalar: TSHA256CompressProc): TSHA256CompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // BSWAP32 shuffle mask for pshufb (x86 SIMD only): reverses bytes within each
  // dword. Not a SHA-256 constant; used only by the SHA-NI kernel.
  BSWAP32_MASK: array [0 .. 3] of UInt32 = (
    $00010203, $04050607, $08090A0B, $0C0D0E0F
  );

  // Doubled K256 round constants plus the three AVX2 message-schedule masks,
  // shared by the AVX2 and SSE2 SIMD-schedule SHA-256 kernels. Each 128-bit K256
  // quadruple is stored twice so one table feeds both the 256-bit AVX2 lanes and
  // the 128-bit SSE2 reads (both read at a 32-byte stride, skipping the duplicate
  // halves). Only the AVX2 kernel uses the appended masks: the byte-swap mask
  // (BSWAP32 pattern, twice) occupies [128..135] and the two schedule shuffle
  // masks follow at [136..143] and [144..151]; the SSE2 kernel computes its
  // byte-swap and needs no mask. Derived from K256.
  K256_Doubled: array [0 .. 151] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2,
    $00010203, $04050607, $08090A0B, $0C0D0E0F,
    $00010203, $04050607, $08090A0B, $0C0D0E0F,
    $03020100, $0B0A0908, $FFFFFFFF, $FFFFFFFF,
    $03020100, $0B0A0908, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $03020100, $0B0A0908,
    $FFFFFFFF, $FFFFFFFF, $03020100, $0B0A0908
  );

// =============================================================================
// SIMD kernels
//   i386:    ShaNi, AVX2, SSSE3, SSE2
//   x86_64:  ShaNi, AVX2, SSSE3, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure SHA256_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressShaNi_i386.inc}
end;

procedure SHA256_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_ShaNi(AState, AData, ANumBlocks, @K256_Doubled);
end;

procedure SHA256_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressSse2_i386.inc}
end;

procedure SHA256_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressSsse3_i386.inc}
end;

procedure SHA256_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressAvx2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure SHA256_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants, AMask: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressShaNi_x86_64.inc}
end;

procedure SHA256_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_ShaNi(AState, AData, ANumBlocks, @K256, @BSWAP32_MASK);
end;

procedure SHA256_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressSse2_x86_64.inc}
end;

procedure SHA256_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressSsse3_x86_64.inc}
end;

procedure SHA256_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure SHA256_Compress_Ssse3_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Ssse3(AState, AData, ANumBlocks, @K256_Doubled);
end;

procedure SHA256_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Avx2(AState, AData, ANumBlocks, @K256_Doubled);
end;

procedure SHA256_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Sse2(AState, AData, ANumBlocks, @K256_Doubled);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TSHA2_256X86Backend }

class function TSHA2_256X86Backend.Select(AScalar: TSHA256CompressProc): TSHA256CompressProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  if TCpuFeatures.X86.HasSHANI() then
    Exit(@SHA256_Compress_ShaNi_Wrap);
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@SHA256_Compress_Avx2_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@SHA256_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@SHA256_Compress_Sse2_Wrap);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  if TCpuFeatures.X86.HasSHANI() then
    Exit(@SHA256_Compress_ShaNi_Wrap);
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@SHA256_Compress_Avx2_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@SHA256_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@SHA256_Compress_Sse2_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
