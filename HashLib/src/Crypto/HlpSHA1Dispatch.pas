unit HlpSHA1Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TSHA1CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA1_Compress: TSHA1CompressProc;

const
  // BSWAP32 mask for pshufb: reverses bytes within each dword (big-endian to little-endian)
  K_SHA1: array [0 .. 3] of UInt32 = (
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
{$IFDEF HASHLIB_X86_64}
  if TSimd.HasSHANI() and (TSimd.GetActiveLevel() >= TSimdLevel.SSSE3) then
  begin
    SHA1_Compress := @SHA1_Compress_ShaNi_Wrap;
    Exit;
  end;
  if TSimd.GetActiveLevel() >= TSimdLevel.AVX2 then
  begin
    SHA1_Compress := @SHA1_Compress_Avx2_Wrap;
    Exit;
  end;
  if TSimd.GetActiveLevel() >= TSimdLevel.SSSE3 then
  begin
    SHA1_Compress := @SHA1_Compress_Ssse3_Wrap;
    Exit;
  end;
{$ENDIF}
  SHA1_Compress := @SHA1_Compress_Scalar;
end;

initialization
  InitDispatch();

end.
