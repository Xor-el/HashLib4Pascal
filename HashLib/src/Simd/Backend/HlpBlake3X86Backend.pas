unit HlpBlake3X86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake3;

type
  /// <summary>
  /// x86 SIMD backend for Blake3: owns the SSE2 / AVX2 compression and 4-/8-way
  /// hash-many kernels (bodies in <c>Include\Simd\Blake3\</c>) and the runtime
  /// tier selection via <c>TCpuFeatures.X86</c>. The hash-many wrappers process
  /// full parallel groups in asm and delegate the remainder to the scalar
  /// hash-many. Compiles on every target - without x86 SIMD the selectors return
  /// the scalar routines / degree 1.
  /// </summary>
  TBlake3X86Backend = class sealed
  public
    class function SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc; static;
    class function SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc; static;
    class function SelectParallelDegree(ADefault: Int32): Int32; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // vpshufb byte-rotation masks for the AVX2 kernels: rotr32 by 16 (at +0)
  // and by 8 (at +32) as single byte shuffles. Each 128-bit pattern is stored
  // twice so one table serves both the 256-bit Hash8 loads and the 128-bit
  // Compress loads. Matches the official BLAKE3 AVX2 implementation's
  // ROT16/ROT8 shuffle constants.
  BLAKE3_ROT_MASKS: array [0 .. 7] of UInt64 = (
    UInt64($0504070601000302), UInt64($0D0C0F0E09080B0A),
    UInt64($0504070601000302), UInt64($0D0C0F0E09080B0A),
    UInt64($0407060500030201), UInt64($0C0F0E0D080B0A09),
    UInt64($0407060500030201), UInt64($0C0F0E0D080B0A09)
  );

// =============================================================================
// SIMD kernels
//   i386:    SSE2
//   x86_64:  AVX2, SSSE3, SSE2
// =============================================================================

procedure Blake3_Compress_Sse2(AState, AMsg, ACV, ACounterFlags: Pointer);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake3\Blake3CompressSse2_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
{$I ..\..\Include\Simd\Blake3\Blake3CompressSse2_i386.inc}
{$ENDIF}
end;

{$IFDEF HASHLIB_X86_64_ASM}

procedure Blake3_Compress_Ssse3(AState, AMsg, ACV, ACounterFlags,
  AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3CompressSsse3_x86_64.inc}
end;

procedure Blake3_Compress_Ssse3_Wrap(AState, AMsg, ACV,
  ACounterFlags: Pointer);
begin
  Blake3_Compress_Ssse3(AState, AMsg, ACV, ACounterFlags,
    @BLAKE3_ROT_MASKS);
end;

procedure Blake3_Compress_Avx(AState, AMsg, ACV, ACounterFlags,
  AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3CompressAvx_x86_64.inc}
end;

procedure Blake3_Compress_Avx_Wrap(AState, AMsg, ACV,
  ACounterFlags: Pointer);
begin
  Blake3_Compress_Avx(AState, AMsg, ACV, ACounterFlags,
    @BLAKE3_ROT_MASKS);
end;

{$ENDIF HASHLIB_X86_64_ASM}

procedure Blake3_Hash4_Sse2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
{$IFDEF HASHLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc6Begin_x86_64.inc}
{$I ..\..\Include\Simd\Blake3\Blake3Hash4Sse2_x86_64.inc}
{$ENDIF}
{$IFDEF HASHLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\HlpSimdProc6Begin_i386.inc}
{$I ..\..\Include\Simd\Blake3\Blake3Hash4Sse2_i386.inc}
{$ENDIF}
end;

{$IFDEF HASHLIB_X86_64_ASM}

procedure Blake3_Hash4_Ssse3(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32; AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc7Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3Hash4Ssse3_x86_64.inc}
end;

procedure Blake3_Hash8_Avx2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32; AMasks: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc7Begin_x86_64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3Hash8Avx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

// SSE2 hash_many: hash4 -> delegate remainder to scalar hash_many
procedure Blake3_HashMany_Sse2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 4 do
  begin
    Blake3_Hash4_Sse2(LPInput, AKey, LPOut, 4, ACounter, AFlags);
    System.Inc(LPInput, 4 * 1024);
    System.Inc(LPOut, 4 * 32);
    System.Inc(ACounter, 4);
    System.Dec(ANumChunks, 4);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Scalar(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

{$IFDEF HASHLIB_X86_64_ASM}

// SSSE3 hash_many: hash4 -> delegate remainder to scalar hash_many
procedure Blake3_HashMany_Ssse3(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 4 do
  begin
    Blake3_Hash4_Ssse3(LPInput, AKey, LPOut, 4, ACounter, AFlags,
      @BLAKE3_ROT_MASKS);
    System.Inc(LPInput, 4 * 1024);
    System.Inc(LPOut, 4 * 32);
    System.Inc(ACounter, 4);
    System.Dec(ANumChunks, 4);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Scalar(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

// AVX2 hash_many: hash8 -> delegate remainder to SSSE3 hash_many
procedure Blake3_HashMany_Avx2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 8 do
  begin
    Blake3_Hash8_Avx2(LPInput, AKey, LPOut, 8, ACounter, AFlags,
      @BLAKE3_ROT_MASKS);
    System.Inc(LPInput, 8 * 1024);
    System.Inc(LPOut, 8 * 32);
    System.Inc(ACounter, 8);
    System.Dec(ANumChunks, 8);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Ssse3(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TBlake3X86Backend }

class function TBlake3X86Backend.SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(@Blake3_Compress_Sse2);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Blake3_Compress_Avx_Wrap);
    TX86SimdLevel.SSSE3:
      Exit(@Blake3_Compress_Ssse3_Wrap);
    TX86SimdLevel.SSE2:
      Exit(@Blake3_Compress_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TBlake3X86Backend.SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(@Blake3_HashMany_Sse2);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(@Blake3_HashMany_Avx2);
    TX86SimdLevel.SSSE3:
      Exit(@Blake3_HashMany_Ssse3);
    TX86SimdLevel.SSE2:
      Exit(@Blake3_HashMany_Sse2);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TBlake3X86Backend.SelectParallelDegree(ADefault: Int32): Int32;
begin
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      Exit(4);
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3,
    TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
      Exit(8);
    TX86SimdLevel.SSSE3, TX86SimdLevel.SSE2:
      Exit(4);
  end;
{$ENDIF}
  Result := ADefault;
end;

end.
