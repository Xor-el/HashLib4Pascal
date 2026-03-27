unit HlpSHA2_512Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TSHA512CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA512_Compress: TSHA512CompressProc;

const
  // K512 round constants (80 UInt64 = 640 bytes)
  // followed by BSWAP64 mask (2 UInt64 = 16 bytes) at offset 640
  K512: array [0 .. 81] of UInt64 = (
    UInt64($428A2F98D728AE22), UInt64($7137449123EF65CD),
    UInt64($B5C0FBCFEC4D3B2F), UInt64($E9B5DBA58189DBBC),
    UInt64($3956C25BF348B538), UInt64($59F111F1B605D019),
    UInt64($923F82A4AF194F9B), UInt64($AB1C5ED5DA6D8118),
    UInt64($D807AA98A3030242), UInt64($12835B0145706FBE),
    UInt64($243185BE4EE4B28C), UInt64($550C7DC3D5FFB4E2),
    UInt64($72BE5D74F27B896F), UInt64($80DEB1FE3B1696B1),
    UInt64($9BDC06A725C71235), UInt64($C19BF174CF692694),
    UInt64($E49B69C19EF14AD2), UInt64($EFBE4786384F25E3),
    UInt64($0FC19DC68B8CD5B5), UInt64($240CA1CC77AC9C65),
    UInt64($2DE92C6F592B0275), UInt64($4A7484AA6EA6E483),
    UInt64($5CB0A9DCBD41FBD4), UInt64($76F988DA831153B5),
    UInt64($983E5152EE66DFAB), UInt64($A831C66D2DB43210),
    UInt64($B00327C898FB213F), UInt64($BF597FC7BEEF0EE4),
    UInt64($C6E00BF33DA88FC2), UInt64($D5A79147930AA725),
    UInt64($06CA6351E003826F), UInt64($142929670A0E6E70),
    UInt64($27B70A8546D22FFC), UInt64($2E1B21385C26C926),
    UInt64($4D2C6DFC5AC42AED), UInt64($53380D139D95B3DF),
    UInt64($650A73548BAF63DE), UInt64($766A0ABB3C77B2A8),
    UInt64($81C2C92E47EDAEE6), UInt64($92722C851482353B),
    UInt64($A2BFE8A14CF10364), UInt64($A81A664BBC423001),
    UInt64($C24B8B70D0F89791), UInt64($C76C51A30654BE30),
    UInt64($D192E819D6EF5218), UInt64($D69906245565A910),
    UInt64($F40E35855771202A), UInt64($106AA07032BBD1B8),
    UInt64($19A4C116B8D2D0C8), UInt64($1E376C085141AB53),
    UInt64($2748774CDF8EEB99), UInt64($34B0BCB5E19B48A8),
    UInt64($391C0CB3C5C95A63), UInt64($4ED8AA4AE3418ACB),
    UInt64($5B9CCA4F7763E373), UInt64($682E6FF3D6B2B8A3),
    UInt64($748F82EE5DEFB2FC), UInt64($78A5636F43172F60),
    UInt64($84C87814A1F0AB72), UInt64($8CC702081A6439EC),
    UInt64($90BEFFFA23631E28), UInt64($A4506CEBDE82BDE9),
    UInt64($BEF9A3F7B2C67915), UInt64($C67178F2E372532B),
    UInt64($CA273ECEEA26619C), UInt64($D186B8C721C0C207),
    UInt64($EADA7DD6CDE0EB1E), UInt64($F57D4F7FEE6ED178),
    UInt64($06F067AA72176FBA), UInt64($0A637DC5A2C898A6),
    UInt64($113F9804BEF90DAE), UInt64($1B710B35131C471B),
    UInt64($28DB77F523047D84), UInt64($32CAAB7B40C72493),
    UInt64($3C9EBE0A15C9BEBC), UInt64($431D67C49C100D4C),
    UInt64($4CC5D4BECB3E42B6), UInt64($597F299CFC657E2A),
    UInt64($5FCB6FAB3AD6FAEC), UInt64($6C44198C4A475817),
    // BSWAP64 mask at offset 640: reverses bytes within each qword
    UInt64($0001020304050607), UInt64($08090A0B0C0D0E0F)
  );

implementation

uses
  HlpBits,
  HlpConverters,
  HlpSimd;

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure SHA512_Compress_Scalar(AState, AData: Pointer; ANumBlocks: UInt32);
var
  LPState: PUInt64;
  LPData: PByte;
  LA, LB, LC, LD, LE, LF, LG, LH, LT1, LT2: UInt64;
  LW: array [0 .. 79] of UInt64;
  LRound: Int32;
begin
  LPState := PUInt64(AState);
  LPData := PByte(AData);

  while ANumBlocks > 0 do
  begin
    TConverters.be64_copy(LPData, 0, @LW[0], 0, 128);

    for LRound := 16 to 79 do
    begin
      LT1 := LW[LRound - 2];
      LT2 := LW[LRound - 15];
      LW[LRound] := (TBits.RotateRight64(LT1, 19) xor TBits.RotateRight64(LT1, 61)
        xor (LT1 shr 6)) + LW[LRound - 7] +
        (TBits.RotateRight64(LT2, 1) xor TBits.RotateRight64(LT2, 8)
        xor (LT2 shr 7)) + LW[LRound - 16];
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2]; LD := LPState[3];
    LE := LPState[4]; LF := LPState[5]; LG := LPState[6]; LH := LPState[7];

    for LRound := 0 to 79 do
    begin
      LT1 := LH + (TBits.RotateRight64(LE, 14) xor TBits.RotateRight64(LE, 18)
        xor TBits.RotateRight64(LE, 41)) + ((LE and LF) xor (not LE and LG))
        + K512[LRound] + LW[LRound];
      LT2 := (TBits.RotateRight64(LA, 28) xor TBits.RotateRight64(LA, 34)
        xor TBits.RotateRight64(LA, 39)) +
        ((LA and LB) xor (LA and LC) xor (LB and LC));
      LH := LG; LG := LF; LF := LE; LE := LD + LT1;
      LD := LC; LC := LB; LB := LA; LA := LT1 + LT2;
    end;

    LPState[0] := LPState[0] + LA; LPState[1] := LPState[1] + LB;
    LPState[2] := LPState[2] + LC; LPState[3] := LPState[3] + LD;
    LPState[4] := LPState[4] + LE; LPState[5] := LPState[5] + LF;
    LPState[6] := LPState[6] + LG; LPState[7] := LPState[7] + LH;

    System.FillChar(LW, System.SizeOf(LW), 0);
    System.Inc(LPData, 128);
    System.Dec(ANumBlocks);
  end;
end;

// =============================================================================
// SIMD implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64_ASM}

procedure SHA512_Compress_Sse2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA512\SHA512CompressSse2.inc}
end;

procedure SHA512_Compress_Sse2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA512_Compress_Sse2(AState, AData, ANumBlocks, @K512);
end;

procedure SHA512_Compress_Ssse3(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA512\SHA512CompressSsse3.inc}
end;

procedure SHA512_Compress_Ssse3_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA512_Compress_Ssse3(AState, AData, ANumBlocks, @K512);
end;

procedure SHA512_Compress_Avx2(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\SHA512\SHA512CompressAvx2.inc}
end;

procedure SHA512_Compress_Avx2_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA512_Compress_Avx2(AState, AData, ANumBlocks, @K512);
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  SHA512_Compress := @SHA512_Compress_Scalar;
{$IFDEF HASHLIB_X86_64_ASM}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      SHA512_Compress := @SHA512_Compress_Avx2_Wrap;
    end;
    TSimdLevel.SSSE3:
    begin
      SHA512_Compress := @SHA512_Compress_Ssse3_Wrap;
    end;
    TSimdLevel.SSE2:
    begin
      SHA512_Compress := @SHA512_Compress_Sse2_Wrap;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
