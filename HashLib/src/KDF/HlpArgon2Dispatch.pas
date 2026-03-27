unit HlpArgon2Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TArgon2FillBlockProc = procedure(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);

var
  Argon2_FillBlock: TArgon2FillBlockProc;

implementation

uses
  HlpBits,
  HlpSimd;

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Argon2_FillBlock_Scalar(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
var
  LR, LZ: array [0 .. 127] of UInt64;
  LPLeft, LPRight, LPCurrent: PUInt64;
  LIdx, LRoundIdx, LColBase, LRowBase: Int32;

  procedure G(AA, AB, AC, AD: Int32);
  var
    LProd: UInt64;
  begin
    LProd := UInt64(UInt32(LZ[AA])) * UInt64(UInt32(LZ[AB]));
    LZ[AA] := LZ[AA] + LZ[AB] + (2 * LProd);
    LZ[AD] := TBits.RotateRight64(LZ[AD] xor LZ[AA], 32);

    LProd := UInt64(UInt32(LZ[AC])) * UInt64(UInt32(LZ[AD]));
    LZ[AC] := LZ[AC] + LZ[AD] + (2 * LProd);
    LZ[AB] := TBits.RotateRight64(LZ[AB] xor LZ[AC], 24);

    LProd := UInt64(UInt32(LZ[AA])) * UInt64(UInt32(LZ[AB]));
    LZ[AA] := LZ[AA] + LZ[AB] + (2 * LProd);
    LZ[AD] := TBits.RotateRight64(LZ[AD] xor LZ[AA], 16);

    LProd := UInt64(UInt32(LZ[AC])) * UInt64(UInt32(LZ[AD]));
    LZ[AC] := LZ[AC] + LZ[AD] + (2 * LProd);
    LZ[AB] := TBits.RotateRight64(LZ[AB] xor LZ[AC], 63);
  end;

  procedure RoundFunction(AV0, AV1, AV2, AV3, AV4, AV5, AV6, AV7,
    AV8, AV9, AV10, AV11, AV12, AV13, AV14, AV15: Int32);
  begin
    G(AV0, AV4, AV8, AV12);
    G(AV1, AV5, AV9, AV13);
    G(AV2, AV6, AV10, AV14);
    G(AV3, AV7, AV11, AV15);

    G(AV0, AV5, AV10, AV15);
    G(AV1, AV6, AV11, AV12);
    G(AV2, AV7, AV8, AV13);
    G(AV3, AV4, AV9, AV14);
  end;

begin
  LPLeft := PUInt64(ALeft);
  LPRight := PUInt64(ARight);
  LPCurrent := PUInt64(ACurrent);

  for LIdx := 0 to 127 do
    LR[LIdx] := LPLeft[LIdx] xor LPRight[LIdx];

  System.Move(LR, LZ, SizeOf(LR));

  for LRoundIdx := 0 to 7 do
  begin
    LColBase := 16 * LRoundIdx;
    RoundFunction(LColBase, LColBase + 1, LColBase + 2, LColBase + 3,
      LColBase + 4, LColBase + 5, LColBase + 6, LColBase + 7,
      LColBase + 8, LColBase + 9, LColBase + 10, LColBase + 11,
      LColBase + 12, LColBase + 13, LColBase + 14, LColBase + 15);
  end;

  for LRoundIdx := 0 to 7 do
  begin
    LRowBase := 2 * LRoundIdx;
    RoundFunction(LRowBase, LRowBase + 1, LRowBase + 16, LRowBase + 17,
      LRowBase + 32, LRowBase + 33, LRowBase + 48, LRowBase + 49,
      LRowBase + 64, LRowBase + 65, LRowBase + 80, LRowBase + 81,
      LRowBase + 96, LRowBase + 97, LRowBase + 112, LRowBase + 113);
  end;

  if AWithXor <> 0 then
  begin
    for LIdx := 0 to 127 do
      LPCurrent[LIdx] := LR[LIdx] xor LZ[LIdx] xor LPCurrent[LIdx];
  end
  else
  begin
    for LIdx := 0 to 127 do
      LPCurrent[LIdx] := LR[LIdx] xor LZ[LIdx];
  end;
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64_ASM}

procedure Argon2_FillBlock_Sse2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Argon2\Argon2FillBlockSse2.inc}
end;

procedure Argon2_FillBlock_Avx2(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Argon2\Argon2FillBlockAvx2.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  Argon2_FillBlock := @Argon2_FillBlock_Scalar;
{$IFDEF HASHLIB_X86_64_ASM}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      Argon2_FillBlock := @Argon2_FillBlock_Avx2;
    end;
    TSimdLevel.SSE2, TSimdLevel.SSSE3:
    begin
      Argon2_FillBlock := @Argon2_FillBlock_Sse2;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
