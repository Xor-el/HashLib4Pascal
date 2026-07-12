unit HlpAdler32X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpAdler32;

type
  /// <summary>
  /// x86 SIMD backend for Adler-32: owns the SSE2 / SSSE3 / AVX2 block-processing
  /// kernels (bodies in <c>Include\Simd\Adler32\</c>) and the runtime tier
  /// selection via <c>TCpuFeatures.X86</c>. The SSSE3 tier is kept (its
  /// pmaddubsw is materially faster than the SSE2 emulation). Compiles on every
  /// target - without x86 SIMD, <c>Select</c> just returns the scalar routine.
  /// </summary>
  TAdler32X86Backend = class sealed
  public
    class function Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   i386:    AVX2, SSSE3, SSE2
//   x86_64:  AVX2, SSSE3, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure Adler32_ProcessBlocks_Sse2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksSse2_i386.inc}
end;

procedure Adler32_ProcessBlocks_Ssse3(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksSsse3_i386.inc}
end;

procedure Adler32_ProcessBlocks_Avx2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksAvx2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Adler32_ProcessBlocks_Sse2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksSse2_x86_64.inc}
end;

procedure Adler32_ProcessBlocks_Ssse3(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksSsse3_x86_64.inc}
end;

procedure Adler32_ProcessBlocks_Avx2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure Adler32_Update_Sse2(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Sse2);
end;

procedure Adler32_Update_Ssse3(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Ssse3);
end;

procedure Adler32_Update_Avx2(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Avx2);
end;

{$ENDIF HASHLIB_X86_SIMD}

{ TAdler32X86Backend }

class function TAdler32X86Backend.Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc;
begin
{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Adler32_Update_Avx2);
    TX86SimdLevel.SSSE3:
      Exit(@Adler32_Update_Ssse3);
    TX86SimdLevel.SSE2:
      Exit(@Adler32_Update_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
