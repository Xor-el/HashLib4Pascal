unit HlpArgon2X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_Argon2NotBuildInAdapter;

type
  /// <summary>
  /// x86 SIMD backend for Argon2's fill-block: owns the SSE2 / AVX2 kernels
  /// (bodies in <c>Include\Simd\Argon2\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.X86</c>. Compiles on every target - built without x86 SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TArgon2X86Backend = class sealed
  public
    class function Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // vpshufb byte-rotation masks for the AVX2 and SSSE3 kernels: rotr64 by 24
  // (at +0) and by 16 (at +32) as single byte shuffles - Argon2's G uses the
  // BLAKE2b rotations, so these match the official BLAKE2 AVX2 r24/r16
  // constants. Each 128-bit pattern is stored twice so one table serves both
  // the 256-bit AVX2 loads and the 128-bit SSSE3 loads.
  ARGON2_ROT_MASKS: array [0 .. 7] of UInt64 = (
    UInt64($0201000706050403), UInt64($0A09080F0E0D0C0B),
    UInt64($0201000706050403), UInt64($0A09080F0E0D0C0B),
    UInt64($0100070605040302), UInt64($09080F0E0D0C0B0A),
    UInt64($0100070605040302), UInt64($09080F0E0D0C0B0A)
  );

// =============================================================================
// SIMD kernels
//   i386:    AVX2, SSE2
//   x86_64:  AVX2, SSSE3, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure Argon2_FillBlock_Sse2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockSse2_i386.inc}
end;

procedure Argon2_FillBlock_Avx2(ALeft, ARight, ACurrent: Pointer;
  AWithXor: Int32; AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockAvx2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Argon2_FillBlock_Sse2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockSse2_x86_64.inc}
end;

procedure Argon2_FillBlock_Ssse3(ALeft, ARight, ACurrent: Pointer;
  AWithXor: Int32; AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockSsse3_x86_64.inc}
end;

procedure Argon2_FillBlock_Ssse3_Wrap(ALeft, ARight, ACurrent: Pointer;
  AWithXor: Int32);
begin
  Argon2_FillBlock_Ssse3(ALeft, ARight, ACurrent, AWithXor,
    @ARGON2_ROT_MASKS);
end;

procedure Argon2_FillBlock_Avx2(ALeft, ARight, ACurrent: Pointer;
  AWithXor: Int32; AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure Argon2_FillBlock_Avx2_Wrap(ALeft, ARight, ACurrent: Pointer;
  AWithXor: Int32);
begin
  Argon2_FillBlock_Avx2(ALeft, ARight, ACurrent, AWithXor,
    @ARGON2_ROT_MASKS);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TArgon2X86Backend }

class function TArgon2X86Backend.Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Argon2_FillBlock_Avx2_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@Argon2_FillBlock_Sse2);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Argon2_FillBlock_Avx2_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@Argon2_FillBlock_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@Argon2_FillBlock_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
