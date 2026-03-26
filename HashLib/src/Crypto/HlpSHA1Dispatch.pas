unit HlpSHA1Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TSHA1CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA1_Compress: TSHA1CompressProc;

const
  // K constants replicated 4x for SIMD, followed by BSWAP32 mask.
  // Layout: K_00_19 (16B) at 0, K_20_39 at 16, K_40_59 at 32,
  //   K_60_79 at 48, BSWAP32 mask at 64.
  K_SHA1: array [0 .. 19] of UInt32 = (
    $5A827999, $5A827999, $5A827999, $5A827999,
    $6ED9EBA1, $6ED9EBA1, $6ED9EBA1, $6ED9EBA1,
    $8F1BBCDC, $8F1BBCDC, $8F1BBCDC, $8F1BBCDC,
    $CA62C1D6, $CA62C1D6, $CA62C1D6, $CA62C1D6,
    $00010203, $04050607, $08090A0B, $0C0D0E0F
  );

implementation

uses
  HlpBits,
  HlpConverters,
  HlpSimd;

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
    TConverters.be32_copy(LPData, 0, @LW[0], 0, 64);

    for LRound := 16 to 79 do
    begin
      LT := LW[LRound - 3] xor LW[LRound - 8] xor LW[LRound - 14]
        xor LW[LRound - 16];
      LW[LRound] := TBits.RotateLeft32(LT, 1);
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2];
    LD := LPState[3]; LE := LPState[4];

    for LRound := 0 to 19 do
    begin
      LT := TBits.RotateLeft32(LA, 5) + (LD xor (LB and (LC xor LD)))
        + LE + $5A827999 + LW[LRound];
      LE := LD; LD := LC; LC := TBits.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 20 to 39 do
    begin
      LT := TBits.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + $6ED9EBA1 + LW[LRound];
      LE := LD; LD := LC; LC := TBits.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 40 to 59 do
    begin
      LT := TBits.RotateLeft32(LA, 5) +
        ((LB and LC) or (LD and (LB or LC)))
        + LE + $8F1BBCDC + LW[LRound];
      LE := LD; LD := LC; LC := TBits.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 60 to 79 do
    begin
      LT := TBits.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + $CA62C1D6 + LW[LRound];
      LE := LD; LD := LC; LC := TBits.RotateLeft32(LB, 30);
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
// SIMD implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

procedure SHA1_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressShaNi.inc}
end;

procedure SHA1_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_ShaNi(AState, AData, ANumBlocks, @K_SHA1);
end;

procedure SHA1_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32);
  {$I ..\Include\Simd\Common\SimdProc3Begin.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressSse2.inc}
end;

procedure SHA1_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressSsse3.inc}
end;

procedure SHA1_Compress_Ssse3_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Ssse3(AState, AData, ANumBlocks, @K_SHA1);
end;

procedure SHA1_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA1\SHA1CompressAvx2.inc}
end;

procedure SHA1_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_Avx2(AState, AData, ANumBlocks, @K_SHA1);
end;

{$ENDIF HASHLIB_X86_64}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  SHA1_Compress := @SHA1_Compress_Scalar;
{$IFDEF HASHLIB_X86_64}
  if TSimd.HasSHANI() then
  begin
    SHA1_Compress := @SHA1_Compress_ShaNi_Wrap;
    Exit;
  end;
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      SHA1_Compress := @SHA1_Compress_Avx2_Wrap;
    end;
    TSimdLevel.SSSE3:
    begin
      SHA1_Compress := @SHA1_Compress_Ssse3_Wrap;
    end;
    TSimdLevel.SSE2:
    begin
      SHA1_Compress := @SHA1_Compress_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
