unit HlpBlake3Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TBlake3CompressProc = procedure(AState, AMsg, ACV, ACounterFlags: Pointer);

var
  Blake3_Compress: TBlake3CompressProc;

implementation

uses
  HlpBits,
  HlpSimd;

const
  Blake3Sigma: array [0 .. 6, 0 .. 15] of Int32 = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8),
    (3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1),
    (10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6),
    (12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4),
    (9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7),
    (11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13)
  );

  Blake3IV: array [0 .. 3] of UInt32 = (
    UInt32($6A09E667), UInt32($BB67AE85),
    UInt32($3C6EF372), UInt32($A54FF53A)
  );

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Blake3_Compress_Scalar(AState, AMsg, ACV, ACounterFlags: Pointer);
var
  LV: array [0 .. 15] of UInt32;
  LPMsg, LPCV, LPCounterFlags: PCardinal;
  LRound: Int32;

  procedure G(AA, AB, AC, AD, AMsgIdx0, AMsgIdx1: Int32);
  begin
    LV[AA] := LV[AA] + LV[AB] + LPMsg[AMsgIdx0];
    LV[AD] := TBits.RotateRight32(LV[AD] xor LV[AA], 16);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight32(LV[AB] xor LV[AC], 12);
    LV[AA] := LV[AA] + LV[AB] + LPMsg[AMsgIdx1];
    LV[AD] := TBits.RotateRight32(LV[AD] xor LV[AA], 8);
    LV[AC] := LV[AC] + LV[AD];
    LV[AB] := TBits.RotateRight32(LV[AB] xor LV[AC], 7);
  end;

var
  LPState: PCardinal;
  I: Int32;
begin
  LPMsg := PCardinal(AMsg);
  LPCV := PCardinal(ACV);
  LPCounterFlags := PCardinal(ACounterFlags);
  LPState := PCardinal(AState);

  for I := 0 to 7 do
    LV[I] := LPCV[I];
  LV[8] := Blake3IV[0];
  LV[9] := Blake3IV[1];
  LV[10] := Blake3IV[2];
  LV[11] := Blake3IV[3];
  LV[12] := LPCounterFlags[0];
  LV[13] := LPCounterFlags[1];
  LV[14] := LPCounterFlags[2];
  LV[15] := LPCounterFlags[3];

  for LRound := 0 to 6 do
  begin
    G(0, 4, 8, 12, Blake3Sigma[LRound, 0], Blake3Sigma[LRound, 1]);
    G(1, 5, 9, 13, Blake3Sigma[LRound, 2], Blake3Sigma[LRound, 3]);
    G(2, 6, 10, 14, Blake3Sigma[LRound, 4], Blake3Sigma[LRound, 5]);
    G(3, 7, 11, 15, Blake3Sigma[LRound, 6], Blake3Sigma[LRound, 7]);
    G(0, 5, 10, 15, Blake3Sigma[LRound, 8], Blake3Sigma[LRound, 9]);
    G(1, 6, 11, 12, Blake3Sigma[LRound, 10], Blake3Sigma[LRound, 11]);
    G(2, 7, 8, 13, Blake3Sigma[LRound, 12], Blake3Sigma[LRound, 13]);
    G(3, 4, 9, 14, Blake3Sigma[LRound, 14], Blake3Sigma[LRound, 15]);
  end;

  for I := 0 to 7 do
    LPState[I] := LV[I] xor LV[I + 8];
  for I := 0 to 7 do
    LPState[I + 8] := LV[I + 8] xor LPCV[I];
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

procedure Blake3_Compress_sse2(AState, AMsg, ACV, ACounterFlags: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3CompressSse2.inc}
end;

{$IFDEF HASHLIB_AVX2_ASM_SUPPORTED}

procedure Blake3_Compress_avx2(AState, AMsg, ACV, ACounterFlags: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3CompressAvx2.inc}
end;

{$ENDIF HASHLIB_AVX2_ASM_SUPPORTED}

{$ENDIF HASHLIB_X86_64}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  case TSimd.GetActiveLevel() of
{$IFDEF HASHLIB_X86_64}
  {$IFDEF HASHLIB_AVX2_ASM_SUPPORTED}
    TSimdLevel.AVX2:
    begin
      Blake3_Compress := @Blake3_Compress_avx2;
    end;
  {$ENDIF HASHLIB_AVX2_ASM_SUPPORTED}
    TSimdLevel.SSE2:
    begin
      Blake3_Compress := @Blake3_Compress_sse2;
    end;
{$ENDIF}
    TSimdLevel.Scalar:
    begin
      Blake3_Compress := @Blake3_Compress_Scalar;
    end;
  end;
end;

initialization
  InitDispatch();

end.
