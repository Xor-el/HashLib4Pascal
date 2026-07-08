unit HlpSHA1Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TSHA1CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA1_Compress: TSHA1CompressProc;

const
  // K round constants replicated 4x for SIMD.
  // Layout: K_00_19 (16B) at 0, K_20_39 at 16, K_40_59 at 32, K_60_79 at 48.
  K_SHA1: array [0 .. 15] of UInt32 = (
    $5A827999, $5A827999, $5A827999, $5A827999,
    $6ED9EBA1, $6ED9EBA1, $6ED9EBA1, $6ED9EBA1,
    $8F1BBCDC, $8F1BBCDC, $8F1BBCDC, $8F1BBCDC,
    $CA62C1D6, $CA62C1D6, $CA62C1D6, $CA62C1D6
  );

{$IFDEF HASHLIB_X86_SIMD}
  // BSWAP32 shuffle mask for pshufb (x86 SIMD only): byte-swaps and reverses
  // dword order in one shuffle (sha1rnds4 reads its four words in reverse). Not a
  // SHA-1 constant; used only by the SHA-NI kernel. ARM byte-swaps with REV32 and
  // needs no mask table.
  BSWAP32_MASK: array [0 .. 3] of UInt32 = (
    $0C0D0E0F, $08090A0B, $04050607, $00010203
  );

  // Doubled SHA-1 round constants plus the AVX2 byte-swap masks, shared by the
  // AVX2 and SSE2 SIMD-schedule SHA-1 kernels. Each round constant fills a 128-bit
  // lane (its four dwords) and is stored twice so one table feeds both the 256-bit
  // AVX2 read and the 128-bit SSE2 reads (both read at a 32-byte stride, skipping
  // the duplicate halves). Only the AVX2 kernel uses the appended masks: the
  // byte-swap mask (BSWAP32 pattern, twice) then a whole-vector reverse mask; the
  // SSE2 kernel computes its byte-swap and needs no mask. Read unaligned, so no
  // special alignment is required.
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
{$ENDIF HASHLIB_X86_SIMD}

implementation

uses
  HlpBinaryPrimitives,
  HlpBitOperations,
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure SHA1_Compress_Scalar(AState, AData: Pointer; ANumBlocks: UInt32);
var
  LPState: PCardinal;
  LPData: PByte;
  LA, LB, LC, LD, LE, LT: UInt32;
  LW: array [0 .. 79] of UInt32;
  LRound: Int32;
begin
  LPState := PCardinal(AState);
  LPData := PByte(AData);

  while ANumBlocks > 0 do
  begin
    TBinaryPrimitives.CopyUInt32BigEndian(LPData, 0, @LW[0], 0, 64);

    for LRound := 16 to 79 do
    begin
      LT := LW[LRound - 3] xor LW[LRound - 8] xor LW[LRound - 14]
        xor LW[LRound - 16];
      LW[LRound] := TBitOperations.RotateLeft32(LT, 1);
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2];
    LD := LPState[3]; LE := LPState[4];

    for LRound := 0 to 19 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LD xor (LB and (LC xor LD)))
        + LE + $5A827999 + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 20 to 39 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + $6ED9EBA1 + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 40 to 59 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) +
        ((LB and LC) or (LD and (LB or LC)))
        + LE + $8F1BBCDC + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 60 to 79 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + $CA62C1D6 + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    LPState[0] := LPState[0] + LA; LPState[1] := LPState[1] + LB;
    LPState[2] := LPState[2] + LC; LPState[3] := LPState[3] + LD;
    LPState[4] := LPState[4] + LE;

    System.FillChar(LW, System.SizeOf(LW), 0);
    System.Inc(LPData, 64);
    System.Dec(ANumBlocks);
  end;
end;

// =============================================================================
// SIMD implementations
//
//   i386:    SSE2
//   x86_64:  ShaNi, AVX2, SSE2
//   aarch64: SHA1 Crypto Extensions
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure SHA1_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressSse2_i386.inc}
end;

procedure SHA1_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Sse2(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure SHA1_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants, AMask: Pointer);
  {$I ..\Include\Simd\Common\HlpSimdProc5Begin_x86_64.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressShaNi_x86_64.inc}
end;

procedure SHA1_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_ShaNi(AState, AData, ANumBlocks, @K_SHA1, @BSWAP32_MASK);
end;

procedure SHA1_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressSse2_x86_64.inc}
end;

procedure SHA1_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Sse2(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

procedure SHA1_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressAvx2_x86_64.inc}
end;

procedure SHA1_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Avx2(AState, AData, ANumBlocks, @K_SHA1_Doubled);
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_AARCH64_ASM}

procedure SHA1_Compress_CryptoExt(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressCryptoExt_aarch64.inc}
end;

procedure SHA1_Compress_CryptoExt_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_CryptoExt(AState, AData, ANumBlocks, @K_SHA1);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  SHA1_Compress := @SHA1_Compress_Scalar;
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
    begin
      SHA1_Compress := @SHA1_Compress_Sse2_Wrap;
    end;
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  if TCpuFeatures.X86.HasSHANI() then
  begin
    SHA1_Compress := @SHA1_Compress_ShaNi_Wrap;
    Exit;
  end;
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]) of
    TX86SimdLevel.AVX2:
    begin
      SHA1_Compress := @SHA1_Compress_Avx2_Wrap;
    end;
    TX86SimdLevel.SSE2:
    begin
      SHA1_Compress := @SHA1_Compress_Sse2_Wrap;
    end;
  end;
{$ENDIF}
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA1() then
  begin
    SHA1_Compress := @SHA1_Compress_CryptoExt_Wrap;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
