unit HlpBlake2BDispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TBlake2BCompressProc = procedure(AState, AMsg, ACounterFlags, AIV: Pointer);

const
  Blake2BIV: array [0 .. 7] of UInt64 = (
    UInt64($6A09E667F3BCC908), UInt64($BB67AE8584CAA73B),
    UInt64($3C6EF372FE94F82B), UInt64($A54FF53A5F1D36F1),
    UInt64($510E527FADE682D1), UInt64($9B05688C2B3E6C1F),
    UInt64($1F83D9ABFB41BD6B), UInt64($5BE0CD19137E2179)
  );

var
  Blake2B_Compress: TBlake2BCompressProc;

implementation

uses
  HlpBits,
  HlpSimd;

const
  Blake2BSigma: array [0 .. 11, 0 .. 15] of Int32 = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
    (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
    (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
    (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
    (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
    (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
    (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
    (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
  );

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Blake2B_Compress_Scalar(AState, AMsg, ACounterFlags, AIV: Pointer);
var
  LV: array [0 .. 15] of UInt64;
  LPState, LPMsg, LPCounterFlags, LPIV: PByte;
  LRound, I: Int32;

  procedure G(AA, AB, AC, AD, AMsgIdx0, AMsgIdx1: Int32);
  begin
    LV[AA] := LV[AA] + LV[AB] + PUInt64(LPMsg + AMsgIdx0 * SizeOf(UInt64))^;
    LV[AD] := TBits.RotateRight64(LV[AD] xor LV[AA], 32);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight64(LV[AB] xor LV[AC], 24);
    LV[AA] := LV[AA] + LV[AB] + PUInt64(LPMsg + AMsgIdx1 * SizeOf(UInt64))^;
    LV[AD] := TBits.RotateRight64(LV[AD] xor LV[AA], 16);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight64(LV[AB] xor LV[AC], 63);
  end;

begin
  LPState := PByte(AState);
  LPMsg := PByte(AMsg);
  LPCounterFlags := PByte(ACounterFlags);
  LPIV := PByte(AIV);

  for I := 0 to 7 do
    LV[I] := PUInt64(LPState + I * SizeOf(UInt64))^;
  for I := 0 to 7 do
    LV[I + 8] := PUInt64(LPIV + I * SizeOf(UInt64))^;

  LV[12] := LV[12] xor PUInt64(LPCounterFlags)^;
  LV[13] := LV[13] xor PUInt64(LPCounterFlags + SizeOf(UInt64))^;
  LV[14] := LV[14] xor PUInt64(LPCounterFlags + 2 * SizeOf(UInt64))^;
  LV[15] := LV[15] xor PUInt64(LPCounterFlags + 3 * SizeOf(UInt64))^;

  for LRound := 0 to 11 do
  begin
    G(0, 4, 8, 12, Blake2BSigma[LRound, 0], Blake2BSigma[LRound, 1]);
    G(1, 5, 9, 13, Blake2BSigma[LRound, 2], Blake2BSigma[LRound, 3]);
    G(2, 6, 10, 14, Blake2BSigma[LRound, 4], Blake2BSigma[LRound, 5]);
    G(3, 7, 11, 15, Blake2BSigma[LRound, 6], Blake2BSigma[LRound, 7]);
    G(0, 5, 10, 15, Blake2BSigma[LRound, 8], Blake2BSigma[LRound, 9]);
    G(1, 6, 11, 12, Blake2BSigma[LRound, 10], Blake2BSigma[LRound, 11]);
    G(2, 7, 8, 13, Blake2BSigma[LRound, 12], Blake2BSigma[LRound, 13]);
    G(3, 4, 9, 14, Blake2BSigma[LRound, 14], Blake2BSigma[LRound, 15]);
  end;

  for I := 0 to 7 do
    PUInt64(LPState + I * SizeOf(UInt64))^ :=
      PUInt64(LPState + I * SizeOf(UInt64))^ xor (LV[I] xor LV[I + 8]);
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64_ASM}

procedure Blake2B_Compress_Sse2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake2B\Blake2BCompressSse2.inc}
end;

procedure Blake2B_Compress_Avx2(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake2B\Blake2BCompressAvx2.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  Blake2B_Compress := @Blake2B_Compress_Scalar;
{$IFDEF HASHLIB_X86_64_ASM}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      Blake2B_Compress := @Blake2B_Compress_Avx2;
    end;
    TSimdLevel.SSE2, TSimdLevel.SSSE3:
    begin
      Blake2B_Compress := @Blake2B_Compress_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
