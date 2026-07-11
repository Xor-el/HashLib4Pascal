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

// =============================================================================
// SIMD kernels
//   i386:    SSE2
//   x86_64:  AVX2, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure Argon2_FillBlock_Sse2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockSse2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Argon2_FillBlock_Sse2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockSse2_x86_64.inc}
end;

procedure Argon2_FillBlock_Avx2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TArgon2X86Backend }

class function TArgon2X86Backend.Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2: Exit(@Argon2_FillBlock_Sse2);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2: Exit(@Argon2_FillBlock_Avx2);
    TX86SimdLevel.SSE2: Exit(@Argon2_FillBlock_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
