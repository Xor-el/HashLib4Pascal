unit HlpScryptX86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_ScryptNotBuildInAdapter;

type
  /// <summary>
  /// x86 SIMD backend for scrypt's Salsa20/8 XOR core: owns the SSE2 / AVX2
  /// kernels (bodies in <c>Include\Simd\Scrypt\</c>) and the runtime tier
  /// selection via <c>TCpuFeatures.X86</c>. Compiles on every target - built
  /// without x86 SIMD, <c>Select</c> just returns the scalar routine.
  /// </summary>
  TScryptX86Backend = class sealed
  public
    class function Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc; static;
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

procedure Scrypt_SalsaXor_Sse2(AState, AInput: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_i386.inc}
  {$I ..\..\Include\Simd\Scrypt\ScryptSalsa8Sse2_i386.inc}
end;

procedure Scrypt_SalsaXor_Avx(AState, AInput: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_i386.inc}
  {$I ..\..\Include\Simd\Scrypt\ScryptSalsa8Avx_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Scrypt_SalsaXor_Sse2(AState, AInput: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Scrypt\ScryptSalsa8Sse2_x86_64.inc}
end;

procedure Scrypt_SalsaXor_Avx(AState, AInput: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Scrypt\ScryptSalsa8Avx_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TScryptX86Backend }

class function TScryptX86Backend.Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Scrypt_SalsaXor_Avx);
    TX86SimdLevel.SSE2:
      Exit(@Scrypt_SalsaXor_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
