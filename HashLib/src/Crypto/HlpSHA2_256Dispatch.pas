unit HlpSHA2_256Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TSHA256CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA256_Compress: TSHA256CompressProc;

const
  // K256 round constants (64 UInt32 = 256 bytes)
  // followed by BSWAP32 mask for pshufb (4 UInt32 = 16 bytes) at offset 256
  K256: array [0 .. 67] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2,
    // BSWAP32 mask at offset 256: reverses bytes within each dword
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

procedure SHA256_Compress_Scalar(AState, AData: Pointer; ANumBlocks: UInt32);
var
  LPState: PCardinal;
  LPData: PByte;
  LA, LB, LC, LD, LE, LF, LG, LH, LT1, LT2: UInt32;
  LW: array [0 .. 63] of UInt32;
  LRound: Int32;
begin
  LPState := PCardinal(AState);
  LPData := PByte(AData);

  while ANumBlocks > 0 do
  begin
    TConverters.be32_copy(LPData, 0, @LW[0], 0, 64);

    for LRound := 16 to 63 do
    begin
      LT1 := LW[LRound - 2];
      LT2 := LW[LRound - 15];
      LW[LRound] := (TBits.RotateRight32(LT1, 17) xor TBits.RotateRight32(LT1, 19)
        xor (LT1 shr 10)) + LW[LRound - 7] +
        (TBits.RotateRight32(LT2, 7) xor TBits.RotateRight32(LT2, 18)
        xor (LT2 shr 3)) + LW[LRound - 16];
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2]; LD := LPState[3];
    LE := LPState[4]; LF := LPState[5]; LG := LPState[6]; LH := LPState[7];

    for LRound := 0 to 63 do
    begin
      LT1 := LH + (TBits.RotateRight32(LE, 6) xor TBits.RotateRight32(LE, 11)
        xor TBits.RotateRight32(LE, 25)) + ((LE and LF) xor (not LE and LG))
        + K256[LRound] + LW[LRound];
      LT2 := (TBits.RotateRight32(LA, 2) xor TBits.RotateRight32(LA, 13)
        xor TBits.RotateRight32(LA, 22)) +
        ((LA and LB) xor (LA and LC) xor (LB and LC));
      LH := LG; LG := LF; LF := LE; LE := LD + LT1;
      LD := LC; LC := LB; LB := LA; LA := LT1 + LT2;
    end;

    LPState[0] := LPState[0] + LA; LPState[1] := LPState[1] + LB;
    LPState[2] := LPState[2] + LC; LPState[3] := LPState[3] + LD;
    LPState[4] := LPState[4] + LE; LPState[5] := LPState[5] + LF;
    LPState[6] := LPState[6] + LG; LPState[7] := LPState[7] + LH;

    System.FillChar(LW, System.SizeOf(LW), 0);
    System.Inc(LPData, 64);
    System.Dec(ANumBlocks);
  end;
end;

// =============================================================================
// SIMD implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64_ASM}

procedure SHA256_Compress_ShaNi(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA256\SHA256CompressShaNi.inc}
end;

procedure SHA256_Compress_ShaNi_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_ShaNi(AState, AData, ANumBlocks, @K256);
end;

procedure SHA256_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA256\SHA256CompressSse2.inc}
end;

procedure SHA256_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Sse2(AState, AData, ANumBlocks, @K256);
end;

procedure SHA256_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA256\SHA256CompressSsse3.inc}
end;

procedure SHA256_Compress_Ssse3_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Ssse3(AState, AData, ANumBlocks, @K256);
end;

procedure SHA256_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA256\SHA256CompressAvx2.inc}
end;

procedure SHA256_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Avx2(AState, AData, ANumBlocks, @K256);
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  SHA256_Compress := @SHA256_Compress_Scalar;
{$IFDEF HASHLIB_X86_64_ASM}
  if TSimd.HasSHANI() then
  begin
    SHA256_Compress := @SHA256_Compress_ShaNi_Wrap;
    Exit;
  end;
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      SHA256_Compress := @SHA256_Compress_Avx2_Wrap;
    end;
    TSimdLevel.SSSE3:
    begin
      SHA256_Compress := @SHA256_Compress_Ssse3_Wrap;
    end;
    TSimdLevel.SSE2:
    begin
      SHA256_Compress := @SHA256_Compress_Sse2_Wrap;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
