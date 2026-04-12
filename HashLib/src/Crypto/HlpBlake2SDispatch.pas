unit HlpBlake2SDispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TBlake2SCompressProc = procedure(AState, AMsg, ACounterFlags, AIV: Pointer);

const
  Blake2SIV: array [0 .. 7] of UInt32 = (
    UInt32($6A09E667), UInt32($BB67AE85),
    UInt32($3C6EF372), UInt32($A54FF53A),
    UInt32($510E527F), UInt32($9B05688C),
    UInt32($1F83D9AB), UInt32($5BE0CD19)
  );

var
  Blake2S_Compress: TBlake2SCompressProc;

implementation

uses
  HlpBits,
  HlpCpuFeatures,
  HlpSimdLevels;

const
  Blake2SSigma: array [0 .. 9, 0 .. 15] of Int32 = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0)
  );

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Blake2S_Compress_Scalar(AState, AMsg, ACounterFlags, AIV: Pointer);
var
  LV: array [0 .. 15] of UInt32;
  LPState, LPMsg, LPCounterFlags, LPIV: PByte;
  LRound, I: Int32;

  procedure G(AA, AB, AC, AD, AMsgIdx0, AMsgIdx1: Int32);
  begin
    LV[AA] := LV[AA] + LV[AB] + PUInt32(LPMsg + AMsgIdx0 * SizeOf(UInt32))^;
    LV[AD] := TBits.RotateRight32(LV[AD] xor LV[AA], 16);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight32(LV[AB] xor LV[AC], 12);
    LV[AA] := LV[AA] + LV[AB] + PUInt32(LPMsg + AMsgIdx1 * SizeOf(UInt32))^;
    LV[AD] := TBits.RotateRight32(LV[AD] xor LV[AA], 8);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight32(LV[AB] xor LV[AC], 7);
  end;

begin
  LPState := PByte(AState);
  LPMsg := PByte(AMsg);
  LPCounterFlags := PByte(ACounterFlags);
  LPIV := PByte(AIV);

  for I := 0 to 7 do
    LV[I] := PUInt32(LPState + I * SizeOf(UInt32))^;
  for I := 0 to 7 do
    LV[I + 8] := PUInt32(LPIV + I * SizeOf(UInt32))^;

  LV[12] := LV[12] xor PUInt32(LPCounterFlags)^;
  LV[13] := LV[13] xor PUInt32(LPCounterFlags + SizeOf(UInt32))^;
  LV[14] := LV[14] xor PUInt32(LPCounterFlags + 2 * SizeOf(UInt32))^;
  LV[15] := LV[15] xor PUInt32(LPCounterFlags + 3 * SizeOf(UInt32))^;

  for LRound := 0 to 9 do
  begin
    G(0, 4, 8, 12, Blake2SSigma[LRound, 0], Blake2SSigma[LRound, 1]);
    G(1, 5, 9, 13, Blake2SSigma[LRound, 2], Blake2SSigma[LRound, 3]);
    G(2, 6, 10, 14, Blake2SSigma[LRound, 4], Blake2SSigma[LRound, 5]);
    G(3, 7, 11, 15, Blake2SSigma[LRound, 6], Blake2SSigma[LRound, 7]);
    G(0, 5, 10, 15, Blake2SSigma[LRound, 8], Blake2SSigma[LRound, 9]);
    G(1, 6, 11, 12, Blake2SSigma[LRound, 10], Blake2SSigma[LRound, 11]);
    G(2, 7, 8, 13, Blake2SSigma[LRound, 12], Blake2SSigma[LRound, 13]);
    G(3, 4, 9, 14, Blake2SSigma[LRound, 14], Blake2SSigma[LRound, 15]);
  end;

  for I := 0 to 7 do
    PUInt32(LPState + I * SizeOf(UInt32))^ :=
      PUInt32(LPState + I * SizeOf(UInt32))^ xor (LV[I] xor LV[I + 8]);
end;

// =============================================================================
// SIMD implementations: SSE2 (IA-32); SSE2 / SSSE3 / AVX2 (x86-64)
// IA-32: uses XMM0-XMM6 only.
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

procedure Blake2S_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\Blake2S\Blake2SCompressSse2_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

procedure Blake2S_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\Blake2S\Blake2SCompressSse2_x86_64.inc}
end;

procedure Blake2S_Compress_Avx2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\Blake2S\Blake2SCompressAvx2_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  Blake2S_Compress := @Blake2S_Compress_Scalar;
{$IFDEF HASHLIB_I386_ASM}
  case TCpuFeatures.X86.GetSimdLevel() of
    TX86SimdLevel.SSE2, TX86SimdLevel.SSSE3:
    begin
      Blake2S_Compress := @Blake2S_Compress_Sse2;
    end;
  end;
{$ENDIF}
{$IFDEF HASHLIB_X86_64_ASM}
  case TCpuFeatures.X86.GetActiveSimdLevel() of
    TX86SimdLevel.AVX2:
    begin
      Blake2S_Compress := @Blake2S_Compress_Avx2;
    end;
    TX86SimdLevel.SSE2, TX86SimdLevel.SSSE3:
    begin
      Blake2S_Compress := @Blake2S_Compress_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
