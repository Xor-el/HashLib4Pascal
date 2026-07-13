unit HlpSHA3X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA3;

type
  /// <summary>
  /// x86 SIMD backend for Keccak-F1600: owns the x86_64 AVX2 permute / absorb
  /// kernels and the i386 SSE2 permute kernel (bodies in
  /// <c>Include\Simd\SHA3\</c>) plus the runtime tier selection via
  /// <c>TCpuFeatures.X86</c>. Compiles on every target - without a matching
  /// tier the selectors return the scalar routines.
  /// </summary>
  TSHA3X86Backend = class sealed
  public
    class function SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc; static;
    class function SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // Plain 24-entry iota round constants (stride 8) for the scalar-layout
  // kernels (i386 SSE2 + x86_64 GPR; the AVX2 kernel uses the x4-broadcast
  // table below).
  K_KECCAK_IOTAS: array [0 .. 23] of UInt64 = (
    UInt64($0000000000000001), UInt64($0000000000008082),
    UInt64($800000000000808A), UInt64($8000000080008000),
    UInt64($000000000000808B), UInt64($0000000080000001),
    UInt64($8000000080008081), UInt64($8000000000008009),
    UInt64($000000000000008A), UInt64($0000000000000088),
    UInt64($0000000080008009), UInt64($000000008000000A),
    UInt64($000000008000808B), UInt64($800000000000008B),
    UInt64($8000000000008089), UInt64($8000000000008003),
    UInt64($8000000000008002), UInt64($8000000000000080),
    UInt64($000000000000800A), UInt64($800000008000000A),
    UInt64($8000000080008081), UInt64($8000000000008080),
    UInt64($0000000080000001), UInt64($8000000080008008));

  K_KECCAK: packed record
    RhotatesLeft: array [0..23] of UInt64;
    RhotatesRight: array [0..23] of UInt64;
    Iotas: array [0..95] of UInt64;
    Jagged: array [0..24] of Int32;
  end = (
    RhotatesLeft: (
       3, 18, 36, 41,   //  ymm2: [2][0] [4][0] [1][0] [3][0]
       1, 62, 28, 27,   //  ymm1: [0][1] [0][2] [0][3] [0][4]
      45,  6, 56, 39,   //  ymm3: [3][1] [1][2] [4][3] [2][4]
      10, 61, 55,  8,   //  ymm4: [2][1] [4][2] [1][3] [3][4]
       2, 15, 25, 20,   //  ymm5: [4][1] [3][2] [2][3] [1][4]
      44, 43, 21, 14);  //  ymm6: [1][1] [2][2] [3][3] [4][4]
    RhotatesRight: (
      61, 46, 28, 23,
      63,  2, 36, 37,
      19, 58,  8, 25,
      54,  3,  9, 56,
      62, 49, 39, 44,
      20, 21, 43, 50);
    Iotas: (
      UInt64($0000000000000001), UInt64($0000000000000001), UInt64($0000000000000001), UInt64($0000000000000001),
      UInt64($0000000000008082), UInt64($0000000000008082), UInt64($0000000000008082), UInt64($0000000000008082),
      UInt64($800000000000808A), UInt64($800000000000808A), UInt64($800000000000808A), UInt64($800000000000808A),
      UInt64($8000000080008000), UInt64($8000000080008000), UInt64($8000000080008000), UInt64($8000000080008000),
      UInt64($000000000000808B), UInt64($000000000000808B), UInt64($000000000000808B), UInt64($000000000000808B),
      UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001),
      UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081),
      UInt64($8000000000008009), UInt64($8000000000008009), UInt64($8000000000008009), UInt64($8000000000008009),
      UInt64($000000000000008A), UInt64($000000000000008A), UInt64($000000000000008A), UInt64($000000000000008A),
      UInt64($0000000000000088), UInt64($0000000000000088), UInt64($0000000000000088), UInt64($0000000000000088),
      UInt64($0000000080008009), UInt64($0000000080008009), UInt64($0000000080008009), UInt64($0000000080008009),
      UInt64($000000008000000A), UInt64($000000008000000A), UInt64($000000008000000A), UInt64($000000008000000A),
      UInt64($000000008000808B), UInt64($000000008000808B), UInt64($000000008000808B), UInt64($000000008000808B),
      UInt64($800000000000008B), UInt64($800000000000008B), UInt64($800000000000008B), UInt64($800000000000008B),
      UInt64($8000000000008089), UInt64($8000000000008089), UInt64($8000000000008089), UInt64($8000000000008089),
      UInt64($8000000000008003), UInt64($8000000000008003), UInt64($8000000000008003), UInt64($8000000000008003),
      UInt64($8000000000008002), UInt64($8000000000008002), UInt64($8000000000008002), UInt64($8000000000008002),
      UInt64($8000000000000080), UInt64($8000000000000080), UInt64($8000000000000080), UInt64($8000000000000080),
      UInt64($000000000000800A), UInt64($000000000000800A), UInt64($000000000000800A), UInt64($000000000000800A),
      UInt64($800000008000000A), UInt64($800000008000000A), UInt64($800000008000000A), UInt64($800000008000000A),
      UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081), UInt64($8000000080008081),
      UInt64($8000000000008080), UInt64($8000000000008080), UInt64($8000000000008080), UInt64($8000000000008080),
      UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001), UInt64($0000000080000001),
      UInt64($8000000080008008), UInt64($8000000080008008), UInt64($8000000080008008), UInt64($8000000080008008));
    Jagged: (
      0, 32, 40, 48, 56, 80, 192, 104, 144, 184,
      64, 128, 200, 176, 120, 88, 96, 168, 208, 152,
      72, 160, 136, 112, 216)
  );

// =============================================================================
// SIMD kernels
//   i386:    SSE2
//   x86_64:  AVX2, SSE2
// =============================================================================

{$IFDEF HASHLIB_X86_64_ASM}

procedure KeccakF1600_Avx2(AState: Pointer; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Avx2_x86_64.inc}
end;

procedure KeccakF1600_Avx2_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Avx2Absorb_x86_64.inc}
end;

procedure KeccakF1600_Gpr(AState: Pointer; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Gpr_x86_64.inc}
end;

procedure KeccakF1600_Gpr_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600GprAbsorb_x86_64.inc}
end;

procedure KeccakF1600_Avx2_Wrap(AState: Pointer);
begin
  KeccakF1600_Avx2(AState, @K_KECCAK);
end;

procedure KeccakF1600_Avx2_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_Avx2_Absorb(AState, AData, ABlockCount, ABlockSize, @K_KECCAK);
end;

procedure KeccakF1600_Gpr_Wrap(AState: Pointer);
begin
  KeccakF1600_Gpr(AState, @K_KECCAK_IOTAS);
end;

procedure KeccakF1600_Gpr_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_Gpr_Absorb(AState, AData, ABlockCount, ABlockSize,
    @K_KECCAK_IOTAS);
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_I386_ASM}

procedure KeccakF1600_Sse2(AState: Pointer; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Sse2_i386.inc}
end;

procedure KeccakF1600_Sse2_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_i386.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Sse2Absorb_i386.inc}
end;

procedure KeccakF1600_Sse2_Wrap(AState: Pointer);
begin
  KeccakF1600_Sse2(AState, @K_KECCAK_IOTAS);
end;

procedure KeccakF1600_Sse2_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_Sse2_Absorb(AState, AData, ABlockCount, ABlockSize,
    @K_KECCAK_IOTAS);
end;

{$ENDIF HASHLIB_I386_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TSHA3X86Backend }

class function TSHA3X86Backend.SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc;
begin
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@KeccakF1600_Avx2_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@KeccakF1600_Gpr_Wrap);
  end;
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(@KeccakF1600_Sse2_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TSHA3X86Backend.SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc;
begin
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@KeccakF1600_Avx2_Absorb_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@KeccakF1600_Gpr_Absorb_Wrap);
  end;
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(@KeccakF1600_Sse2_Absorb_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
