unit HlpScryptDispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TScryptSalsaXorProc = procedure(AState, AInput: Pointer);

var
  Scrypt_SalsaXor: TScryptSalsaXorProc;

procedure Scrypt_Permute(ABlock: PCardinal; AChunkCount: Int32);
procedure Scrypt_Unpermute(ABlock: PCardinal; AChunkCount: Int32);

implementation

uses
  HlpBits,
  HlpSimd;

// =============================================================================
// Percival's (i*5 mod 16) permutation rearranges each 16-word Salsa20 state
// from natural order into role-based diagonal order so that column and row
// quarter-rounds map to lane-parallel SIMD operations. Applied once at
// SMixLane entry/exit; all intermediate data stays in permuted order.
// Reference: Colin Percival, crypto_scrypt-sse.c (Tarsnap).
// =============================================================================

procedure Scrypt_Permute(ABlock: PCardinal; AChunkCount: Int32);
var
  LTemp: array[0..15] of UInt32;
  LIdx: Int32;
begin
  while AChunkCount > 0 do
  begin
    for LIdx := 0 to 15 do
      LTemp[LIdx] := ABlock[(LIdx * 5) and 15];
    System.Move(LTemp, ABlock^, 64);
    Inc(ABlock, 16);
    Dec(AChunkCount);
  end;
end;

procedure Scrypt_Unpermute(ABlock: PCardinal; AChunkCount: Int32);
var
  LTemp: array[0..15] of UInt32;
  LIdx: Int32;
begin
  while AChunkCount > 0 do
  begin
    for LIdx := 0 to 15 do
      LTemp[LIdx] := ABlock[(LIdx * 13) and 15];
    System.Move(LTemp, ABlock^, 64);
    Inc(ABlock, 16);
    Dec(AChunkCount);
  end;
end;

// =============================================================================
// Scalar fallback: fused XOR + Salsa20/8 on Percival-permuted data.
// Loads from permuted positions into natural-named locals, performs standard
// Salsa20/8 column+row rounds, stores back to permuted positions.
// =============================================================================

procedure Scrypt_SalsaXor_Scalar(AState, AInput: Pointer);
var
  LW0, LW1, LW2, LW3, LW4, LW5, LW6, LW7,
  LW8, LW9, LW10, LW11, LW12, LW13, LW14, LW15: UInt32;
  LPS, LPI: PCardinal;
  LIdx: Int32;
begin
  LPS := PCardinal(AState);
  LPI := PCardinal(AInput);

  // Permuted layout: {w0,w5,w10,w15, w4,w9,w14,w3, w8,w13,w2,w7, w12,w1,w6,w11}
  LW0  := LPS[0]  xor LPI[0];
  LW5  := LPS[1]  xor LPI[1];
  LW10 := LPS[2]  xor LPI[2];
  LW15 := LPS[3]  xor LPI[3];
  LW4  := LPS[4]  xor LPI[4];
  LW9  := LPS[5]  xor LPI[5];
  LW14 := LPS[6]  xor LPI[6];
  LW3  := LPS[7]  xor LPI[7];
  LW8  := LPS[8]  xor LPI[8];
  LW13 := LPS[9]  xor LPI[9];
  LW2  := LPS[10] xor LPI[10];
  LW7  := LPS[11] xor LPI[11];
  LW12 := LPS[12] xor LPI[12];
  LW1  := LPS[13] xor LPI[13];
  LW6  := LPS[14] xor LPI[14];
  LW11 := LPS[15] xor LPI[15];

  LPS[0]  := LW0;
  LPS[1]  := LW5;
  LPS[2]  := LW10;
  LPS[3]  := LW15;
  LPS[4]  := LW4;
  LPS[5]  := LW9;
  LPS[6]  := LW14;
  LPS[7]  := LW3;
  LPS[8]  := LW8;
  LPS[9]  := LW13;
  LPS[10] := LW2;
  LPS[11] := LW7;
  LPS[12] := LW12;
  LPS[13] := LW1;
  LPS[14] := LW6;
  LPS[15] := LW11;

  LIdx := 4;
  while LIdx > 0 do
  begin
    LW4  := LW4  xor TBits.RotateLeft32(LW0  + LW12, 7);
    LW8  := LW8  xor TBits.RotateLeft32(LW4  + LW0,  9);
    LW12 := LW12 xor TBits.RotateLeft32(LW8  + LW4,  13);
    LW0  := LW0  xor TBits.RotateLeft32(LW12 + LW8,  18);
    LW9  := LW9  xor TBits.RotateLeft32(LW5  + LW1,  7);
    LW13 := LW13 xor TBits.RotateLeft32(LW9  + LW5,  9);
    LW1  := LW1  xor TBits.RotateLeft32(LW13 + LW9,  13);
    LW5  := LW5  xor TBits.RotateLeft32(LW1  + LW13, 18);
    LW14 := LW14 xor TBits.RotateLeft32(LW10 + LW6,  7);
    LW2  := LW2  xor TBits.RotateLeft32(LW14 + LW10, 9);
    LW6  := LW6  xor TBits.RotateLeft32(LW2  + LW14, 13);
    LW10 := LW10 xor TBits.RotateLeft32(LW6  + LW2,  18);
    LW3  := LW3  xor TBits.RotateLeft32(LW15 + LW11, 7);
    LW7  := LW7  xor TBits.RotateLeft32(LW3  + LW15, 9);
    LW11 := LW11 xor TBits.RotateLeft32(LW7  + LW3,  13);
    LW15 := LW15 xor TBits.RotateLeft32(LW11 + LW7,  18);

    LW1  := LW1  xor TBits.RotateLeft32(LW0  + LW3,  7);
    LW2  := LW2  xor TBits.RotateLeft32(LW1  + LW0,  9);
    LW3  := LW3  xor TBits.RotateLeft32(LW2  + LW1,  13);
    LW0  := LW0  xor TBits.RotateLeft32(LW3  + LW2,  18);
    LW6  := LW6  xor TBits.RotateLeft32(LW5  + LW4,  7);
    LW7  := LW7  xor TBits.RotateLeft32(LW6  + LW5,  9);
    LW4  := LW4  xor TBits.RotateLeft32(LW7  + LW6,  13);
    LW5  := LW5  xor TBits.RotateLeft32(LW4  + LW7,  18);
    LW11 := LW11 xor TBits.RotateLeft32(LW10 + LW9,  7);
    LW8  := LW8  xor TBits.RotateLeft32(LW11 + LW10, 9);
    LW9  := LW9  xor TBits.RotateLeft32(LW8  + LW11, 13);
    LW10 := LW10 xor TBits.RotateLeft32(LW9  + LW8,  18);
    LW12 := LW12 xor TBits.RotateLeft32(LW15 + LW14, 7);
    LW13 := LW13 xor TBits.RotateLeft32(LW12 + LW15, 9);
    LW14 := LW14 xor TBits.RotateLeft32(LW13 + LW12, 13);
    LW15 := LW15 xor TBits.RotateLeft32(LW14 + LW13, 18);

    System.Dec(LIdx);
  end;

  LPS[0]  := LPS[0]  + LW0;
  LPS[1]  := LPS[1]  + LW5;
  LPS[2]  := LPS[2]  + LW10;
  LPS[3]  := LPS[3]  + LW15;
  LPS[4]  := LPS[4]  + LW4;
  LPS[5]  := LPS[5]  + LW9;
  LPS[6]  := LPS[6]  + LW14;
  LPS[7]  := LPS[7]  + LW3;
  LPS[8]  := LPS[8]  + LW8;
  LPS[9]  := LPS[9]  + LW13;
  LPS[10] := LPS[10] + LW2;
  LPS[11] := LPS[11] + LW7;
  LPS[12] := LPS[12] + LW12;
  LPS[13] := LPS[13] + LW1;
  LPS[14] := LPS[14] + LW6;
  LPS[15] := LPS[15] + LW11;
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

procedure Scrypt_SalsaXor_sse2(AState, AInput: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin.inc}
  {$I ..\Include\Simd\Scrypt\ScryptSalsa8Sse2.inc}
end;

{$IFDEF HASHLIB_AVX2_ASM_SUPPORTED}

procedure Scrypt_SalsaXor_avx2(AState, AInput: Pointer);
  {$I ..\Include\Simd\Common\SimdProc2Begin.inc}
  {$I ..\Include\Simd\Scrypt\ScryptSalsa8Avx2.inc}
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
      Scrypt_SalsaXor := @Scrypt_SalsaXor_avx2;
    end;
  {$ENDIF HASHLIB_AVX2_ASM_SUPPORTED}
    TSimdLevel.SSE2:
    begin
      Scrypt_SalsaXor := @Scrypt_SalsaXor_sse2;
    end;
{$ENDIF}
    TSimdLevel.Scalar:
    begin
      Scrypt_SalsaXor := @Scrypt_SalsaXor_Scalar;
    end;
  end;
end;

initialization
  InitDispatch();

end.
