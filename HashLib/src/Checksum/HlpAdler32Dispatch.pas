unit HlpAdler32Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TAdler32UpdateProc = procedure(AData: PByte; ALength: UInt32; ASums: Pointer);

var
  Adler32_Update: TAdler32UpdateProc;

implementation

uses
  HlpCpuFeatures,
  HlpSimdLevels;

const
  ModAdler = UInt32(65521);
  NMAX = UInt32(5552);
 // MAX_BLOCKS_PER_CHUNK = NMAX div UInt32(32); // 173

  Adler32Constants: array [0 .. 63] of Byte = (
    // Offset 0..31: weights [32,31,...,1]
    // SSE2/SSSE3 use as two 16-byte halves; AVX2 uses full 32 bytes.
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
    // Offset 32..63: ones_16 (16-bit value 1 in little-endian, repeated)
    // SSSE3 uses first 16 bytes; AVX2 uses all 32 bytes.
    1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
    1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0
  );

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Adler32_Update_Scalar(AData: PByte; ALength: UInt32; ASums: Pointer);
var
  LChunkLen: UInt32;
  LPSumA, LPSumB: PUInt32;
begin
  LPSumA := PUInt32(ASums);
  LPSumB := PUInt32(PByte(ASums) + SizeOf(UInt32));

  while ALength > 0 do
  begin
    LChunkLen := ALength;
    if LChunkLen > NMAX then
      LChunkLen := NMAX;
    Dec(ALength, LChunkLen);

    while LChunkLen > 0 do
    begin
      LPSumA^ := LPSumA^ + AData^;
      LPSumB^ := LPSumB^ + LPSumA^;
      Inc(AData);
      Dec(LChunkLen);
    end;

    LPSumA^ := LPSumA^ mod ModAdler;
    LPSumB^ := LPSumB^ mod ModAdler;
  end;
end;

// =============================================================================
// SIMD implementations: SSE2 / SSSE3 (IA-32); SSE2 / SSSE3 / AVX2 (x86-64)
// =============================================================================

{$IFDEF HASHLIB_X86_SIMD}

type
  TProcessBlocksProc = procedure(AData: PByte; ANumBlocks: UInt32;
    ASums, AConstants: Pointer);

procedure Adler32_Update_Simd(AData: PByte; ALength: UInt32; ASums: Pointer;
  AProcessBlocks: TProcessBlocksProc);
const
  BLOCK_SIZE = UInt32(32);
var
  LChunkLen, LBlocks: UInt32;
  LPSumA, LPSumB: PUInt32;
begin
  LPSumA := PUInt32(ASums);
  LPSumB := PUInt32(PByte(ASums) + SizeOf(UInt32));

  while ALength > 0 do
  begin
    LChunkLen := ALength;
    if LChunkLen > NMAX then
      LChunkLen := NMAX;
    Dec(ALength, LChunkLen);

    LBlocks := LChunkLen div BLOCK_SIZE;
    if LBlocks > 0 then
    begin
      AProcessBlocks(AData, LBlocks, ASums, @Adler32Constants[0]);
      Inc(AData, LBlocks * BLOCK_SIZE);
      Dec(LChunkLen, LBlocks * BLOCK_SIZE);
    end;

    while LChunkLen > 0 do
    begin
      LPSumA^ := LPSumA^ + AData^;
      LPSumB^ := LPSumB^ + LPSumA^;
      Inc(AData);
      Dec(LChunkLen);
    end;

    LPSumA^ := LPSumA^ mod ModAdler;
    LPSumB^ := LPSumB^ mod ModAdler;
  end;
end;

{$ENDIF HASHLIB_X86_SIMD}

{$IFDEF HASHLIB_I386_ASM}

procedure Adler32_ProcessBlocks_Sse2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\Adler32\Adler32BlocksSse2_i386.inc}
end;

procedure Adler32_ProcessBlocks_Ssse3(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\Adler32\Adler32BlocksSsse3_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Adler32_ProcessBlocks_Sse2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\Adler32\Adler32BlocksSse2_x86_64.inc}
end;

procedure Adler32_ProcessBlocks_Ssse3(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\Adler32\Adler32BlocksSsse3_x86_64.inc}
end;

procedure Adler32_ProcessBlocks_Avx2(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\Adler32\Adler32BlocksAvx2_x86_64.inc}
end;

procedure Adler32_Update_Ssse3(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Ssse3);
end;

procedure Adler32_Update_Avx2(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Avx2);
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_X86_SIMD}

procedure Adler32_Update_Sse2(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Sse2);
end;

{$IFDEF HASHLIB_I386_ASM}

procedure Adler32_Update_Ssse3(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Ssse3);
end;

{$ENDIF HASHLIB_I386_ASM}

{$ENDIF HASHLIB_X86_SIMD}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  Adler32_Update := @Adler32_Update_Scalar;
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSSE3, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSSE3:
    begin
      Adler32_Update := @Adler32_Update_Ssse3;
    end;
    TX86SimdLevel.SSE2:
    begin
      Adler32_Update := @Adler32_Update_Sse2;
    end;
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSSE3, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
    begin
      Adler32_Update := @Adler32_Update_Avx2;
    end;
    TX86SimdLevel.SSSE3:
    begin
      Adler32_Update := @Adler32_Update_Ssse3;
    end;
    TX86SimdLevel.SSE2:
    begin
      Adler32_Update := @Adler32_Update_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
