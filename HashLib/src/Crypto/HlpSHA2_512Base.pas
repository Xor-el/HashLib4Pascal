unit HlpSHA2_512Base;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA2_512Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$IFNDEF USE_UNROLLED_VARIANT}
{$REGION 'Consts'}
  const
    SK: array [0 .. 79] of UInt64 = (UInt64($428A2F98D728AE22),
      UInt64($7137449123EF65CD), UInt64($B5C0FBCFEC4D3B2F),
      UInt64($E9B5DBA58189DBBC), UInt64($3956C25BF348B538),
      UInt64($59F111F1B605D019), UInt64($923F82A4AF194F9B),
      UInt64($AB1C5ED5DA6D8118), UInt64($D807AA98A3030242),
      UInt64($12835B0145706FBE), UInt64($243185BE4EE4B28C),
      UInt64($550C7DC3D5FFB4E2), UInt64($72BE5D74F27B896F),
      UInt64($80DEB1FE3B1696B1), UInt64($9BDC06A725C71235),
      UInt64($C19BF174CF692694), UInt64($E49B69C19EF14AD2),
      UInt64($EFBE4786384F25E3), UInt64($0FC19DC68B8CD5B5),
      UInt64($240CA1CC77AC9C65), UInt64($2DE92C6F592B0275),
      UInt64($4A7484AA6EA6E483), UInt64($5CB0A9DCBD41FBD4),
      UInt64($76F988DA831153B5), UInt64($983E5152EE66DFAB),
      UInt64($A831C66D2DB43210), UInt64($B00327C898FB213F),
      UInt64($BF597FC7BEEF0EE4), UInt64($C6E00BF33DA88FC2),
      UInt64($D5A79147930AA725), UInt64($06CA6351E003826F),
      UInt64($142929670A0E6E70), UInt64($27B70A8546D22FFC),
      UInt64($2E1B21385C26C926), UInt64($4D2C6DFC5AC42AED),
      UInt64($53380D139D95B3DF), UInt64($650A73548BAF63DE),
      UInt64($766A0ABB3C77B2A8), UInt64($81C2C92E47EDAEE6),
      UInt64($92722C851482353B), UInt64($A2BFE8A14CF10364),
      UInt64($A81A664BBC423001), UInt64($C24B8B70D0F89791),
      UInt64($C76C51A30654BE30), UInt64($D192E819D6EF5218),
      UInt64($D69906245565A910), UInt64($F40E35855771202A),
      UInt64($106AA07032BBD1B8), UInt64($19A4C116B8D2D0C8),
      UInt64($1E376C085141AB53), UInt64($2748774CDF8EEB99),
      UInt64($34B0BCB5E19B48A8), UInt64($391C0CB3C5C95A63),
      UInt64($4ED8AA4AE3418ACB), UInt64($5B9CCA4F7763E373),
      UInt64($682E6FF3D6B2B8A3), UInt64($748F82EE5DEFB2FC),
      UInt64($78A5636F43172F60), UInt64($84C87814A1F0AB72),
      UInt64($8CC702081A6439EC), UInt64($90BEFFFA23631E28),
      UInt64($A4506CEBDE82BDE9), UInt64($BEF9A3F7B2C67915),
      UInt64($C67178F2E372532B), UInt64($CA273ECEEA26619C),
      UInt64($D186B8C721C0C207), UInt64($EADA7DD6CDE0EB1E),
      UInt64($F57D4F7FEE6ED178), UInt64($06F067AA72176FBA),
      UInt64($0A637DC5A2C898A6), UInt64($113F9804BEF90DAE),
      UInt64($1B710B35131C471B), UInt64($28DB77F523047D84),
      UInt64($32CAAB7B40C72493), UInt64($3C9EBE0A15C9BEBC),
      UInt64($431D67C49C100D4C), UInt64($4CC5D4BECB3E42B6),
      UInt64($597F299CFC657E2A), UInt64($5FCB6FAB3AD6FAEC),
      UInt64($6C44198C4A475817));

{$ENDREGION}
{$ENDIF USE_UNROLLED_VARIANT}
  strict protected
  var
    FState: THashLibUInt64Array;

    constructor Create(AHashSize: Int32);

    procedure Finish(); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;
  end;

implementation

{ TSHA2_512Base }

constructor TSHA2_512Base.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 128);
  System.SetLength(FState, 8);
end;

procedure TSHA2_512Base.Finish;
var
  LLoBits, LHiBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LLoBits := FProcessedBytesCount shl 3;
  LHiBits := FProcessedBytesCount shr 61;

  if (FBuffer.Position < 112) then
  begin
    LPadIndex := (111 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (239 - FBuffer.Position);
  end;

  System.Inc(LPadIndex);
  System.SetLength(LPad, LPadIndex + 16);
  LPad[0] := $80;

  LHiBits := TConverters.be2me_64(LHiBits);

  TConverters.ReadUInt64AsBytesLE(LHiBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  LLoBits := TConverters.be2me_64(LLoBits);

  TConverters.ReadUInt64AsBytesLE(LLoBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

procedure TSHA2_512Base.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
{$IFNDEF USE_UNROLLED_VARIANT}
  LScheduleIdx, LBatchIdx, LSkIndex: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
  LT0, LT1, LRegA, LRegB, LRegC, LRegD, LRegE, LRegF, LRegG, LRegH: UInt64;
  LData: array [0 .. 79] of UInt64;
begin
  TConverters.be64_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  // Step 1

{$IFDEF USE_UNROLLED_VARIANT}
  LT0 := LData[16 - 15];
  LT1 := LData[16 - 2];
  LData[16] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[16 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[0];
  LT0 := LData[17 - 15];
  LT1 := LData[17 - 2];
  LData[17] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[17 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[17 - 16];
  LT0 := LData[18 - 15];
  LT1 := LData[18 - 2];
  LData[18] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[18 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[18 - 16];
  LT0 := LData[19 - 15];
  LT1 := LData[19 - 2];
  LData[19] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[19 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[19 - 16];
  LT0 := LData[20 - 15];
  LT1 := LData[20 - 2];
  LData[20] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[20 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[20 - 16];
  LT0 := LData[21 - 15];
  LT1 := LData[21 - 2];
  LData[21] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[21 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[21 - 16];
  LT0 := LData[22 - 15];
  LT1 := LData[22 - 2];
  LData[22] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[22 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[22 - 16];
  LT0 := LData[23 - 15];
  LT1 := LData[23 - 2];
  LData[23] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[23 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[23 - 16];
  LT0 := LData[24 - 15];
  LT1 := LData[24 - 2];
  LData[24] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[24 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[24 - 16];
  LT0 := LData[25 - 15];
  LT1 := LData[25 - 2];
  LData[25] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[25 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[25 - 16];
  LT0 := LData[26 - 15];
  LT1 := LData[26 - 2];
  LData[26] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[26 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[26 - 16];
  LT0 := LData[27 - 15];
  LT1 := LData[27 - 2];
  LData[27] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[27 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[27 - 16];
  LT0 := LData[28 - 15];
  LT1 := LData[28 - 2];
  LData[28] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[28 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[28 - 16];
  LT0 := LData[29 - 15];
  LT1 := LData[29 - 2];
  LData[29] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[29 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[29 - 16];
  LT0 := LData[30 - 15];
  LT1 := LData[30 - 2];
  LData[30] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[30 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[30 - 16];
  LT0 := LData[31 - 15];
  LT1 := LData[31 - 2];
  LData[31] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[31 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[31 - 16];
  LT0 := LData[32 - 15];
  LT1 := LData[32 - 2];
  LData[32] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[32 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[32 - 16];
  LT0 := LData[33 - 15];
  LT1 := LData[33 - 2];
  LData[33] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[33 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[33 - 16];
  LT0 := LData[34 - 15];
  LT1 := LData[34 - 2];
  LData[34] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[34 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[34 - 16];
  LT0 := LData[35 - 15];
  LT1 := LData[35 - 2];
  LData[35] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[35 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[35 - 16];
  LT0 := LData[36 - 15];
  LT1 := LData[36 - 2];
  LData[36] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[36 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[36 - 16];
  LT0 := LData[37 - 15];
  LT1 := LData[37 - 2];
  LData[37] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[37 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[37 - 16];
  LT0 := LData[38 - 15];
  LT1 := LData[38 - 2];
  LData[38] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[38 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[38 - 16];
  LT0 := LData[39 - 15];
  LT1 := LData[39 - 2];
  LData[39] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[39 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[39 - 16];
  LT0 := LData[40 - 15];
  LT1 := LData[40 - 2];
  LData[40] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[40 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[40 - 16];
  LT0 := LData[41 - 15];
  LT1 := LData[41 - 2];
  LData[41] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[41 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[41 - 16];
  LT0 := LData[42 - 15];
  LT1 := LData[42 - 2];
  LData[42] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[42 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[42 - 16];
  LT0 := LData[43 - 15];
  LT1 := LData[43 - 2];
  LData[43] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[43 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[43 - 16];
  LT0 := LData[44 - 15];
  LT1 := LData[44 - 2];
  LData[44] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[44 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[44 - 16];
  LT0 := LData[45 - 15];
  LT1 := LData[45 - 2];
  LData[45] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[45 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[45 - 16];
  LT0 := LData[46 - 15];
  LT1 := LData[46 - 2];
  LData[46] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[46 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[46 - 16];
  LT0 := LData[47 - 15];
  LT1 := LData[47 - 2];
  LData[47] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[47 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[47 - 16];
  LT0 := LData[48 - 15];
  LT1 := LData[48 - 2];
  LData[48] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[48 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[48 - 16];
  LT0 := LData[49 - 15];
  LT1 := LData[49 - 2];
  LData[49] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[49 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[49 - 16];
  LT0 := LData[50 - 15];
  LT1 := LData[50 - 2];
  LData[50] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[50 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[50 - 16];
  LT0 := LData[51 - 15];
  LT1 := LData[51 - 2];
  LData[51] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[51 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[51 - 16];
  LT0 := LData[52 - 15];
  LT1 := LData[52 - 2];
  LData[52] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[52 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[52 - 16];
  LT0 := LData[53 - 15];
  LT1 := LData[53 - 2];
  LData[53] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[53 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[53 - 16];
  LT0 := LData[54 - 15];
  LT1 := LData[54 - 2];
  LData[54] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[54 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[54 - 16];
  LT0 := LData[55 - 15];
  LT1 := LData[55 - 2];
  LData[55] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[55 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[55 - 16];
  LT0 := LData[56 - 15];
  LT1 := LData[56 - 2];
  LData[56] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[56 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[56 - 16];
  LT0 := LData[57 - 15];
  LT1 := LData[57 - 2];
  LData[57] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[57 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[57 - 16];
  LT0 := LData[58 - 15];
  LT1 := LData[58 - 2];
  LData[58] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[58 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[58 - 16];
  LT0 := LData[59 - 15];
  LT1 := LData[59 - 2];
  LData[59] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[59 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[59 - 16];
  LT0 := LData[60 - 15];
  LT1 := LData[60 - 2];
  LData[60] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[60 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[60 - 16];
  LT0 := LData[61 - 15];
  LT1 := LData[61 - 2];
  LData[61] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[61 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[61 - 16];
  LT0 := LData[62 - 15];
  LT1 := LData[62 - 2];
  LData[62] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[62 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[62 - 16];
  LT0 := LData[63 - 15];
  LT1 := LData[63 - 2];
  LData[63] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[63 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[63 - 16];
  LT0 := LData[64 - 15];
  LT1 := LData[64 - 2];
  LData[64] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[64 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[64 - 16];
  LT0 := LData[65 - 15];
  LT1 := LData[65 - 2];
  LData[65] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[65 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[65 - 16];
  LT0 := LData[66 - 15];
  LT1 := LData[66 - 2];
  LData[66] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[66 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[66 - 16];
  LT0 := LData[67 - 15];
  LT1 := LData[67 - 2];
  LData[67] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[67 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[67 - 16];
  LT0 := LData[68 - 15];
  LT1 := LData[68 - 2];
  LData[68] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[68 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[68 - 16];
  LT0 := LData[69 - 15];
  LT1 := LData[69 - 2];
  LData[69] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[69 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[69 - 16];
  LT0 := LData[70 - 15];
  LT1 := LData[70 - 2];
  LData[70] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[70 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[70 - 16];
  LT0 := LData[71 - 15];
  LT1 := LData[71 - 2];
  LData[71] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[71 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[71 - 16];
  LT0 := LData[72 - 15];
  LT1 := LData[72 - 2];
  LData[72] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[72 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[72 - 16];
  LT0 := LData[73 - 15];
  LT1 := LData[73 - 2];
  LData[73] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[73 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[73 - 16];
  LT0 := LData[74 - 15];
  LT1 := LData[74 - 2];
  LData[74] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[74 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[74 - 16];
  LT0 := LData[75 - 15];
  LT1 := LData[75 - 2];
  LData[75] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[75 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[75 - 16];
  LT0 := LData[76 - 15];
  LT1 := LData[76 - 2];
  LData[76] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[76 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[76 - 16];
  LT0 := LData[77 - 15];
  LT1 := LData[77 - 2];
  LData[77] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[77 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[77 - 16];
  LT0 := LData[78 - 15];
  LT1 := LData[78 - 2];
  LData[78] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[78 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[78 - 16];
  LT0 := LData[79 - 15];
  LT1 := LData[79 - 2];
  LData[79] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
    xor (LT1 shr 6)) + LData[79 - 7] +
    ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
    xor (LT0 shr 7)) + LData[79 - 16];

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];
  LRegE := FState[4];
  LRegF := FState[5];
  LRegG := FState[6];
  LRegH := FState[7];

  // Step 2

  // R0
  LRegH := LRegH + (UInt64($428A2F98D728AE22) + LData[0] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($7137449123EF65CD) + LData[1] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($B5C0FBCFEC4D3B2F) + LData[2] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($E9B5DBA58189DBBC) + LData[3] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($3956C25BF348B538) + LData[4] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($59F111F1B605D019) + LData[5] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($923F82A4AF194F9B) + LData[6] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($AB1C5ED5DA6D8118) + LData[7] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R1
  LRegH := LRegH + (UInt64($D807AA98A3030242) + LData[8] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($12835B0145706FBE) + LData[9] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($243185BE4EE4B28C) + LData[10] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($550C7DC3D5FFB4E2) + LData[11] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($72BE5D74F27B896F) + LData[12] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($80DEB1FE3B1696B1) + LData[13] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($9BDC06A725C71235) + LData[14] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($C19BF174CF692694) + LData[15] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R2

  LRegH := LRegH + (UInt64($E49B69C19EF14AD2) + LData[16] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($EFBE4786384F25E3) + LData[17] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($0FC19DC68B8CD5B5) + LData[18] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($240CA1CC77AC9C65) + LData[19] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($2DE92C6F592B0275) + LData[20] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($4A7484AA6EA6E483) + LData[21] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($5CB0A9DCBD41FBD4) + LData[22] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($76F988DA831153B5) + LData[23] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R3

  LRegH := LRegH + (UInt64($983E5152EE66DFAB) + LData[24] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($A831C66D2DB43210) + LData[25] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($B00327C898FB213F) + LData[26] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($BF597FC7BEEF0EE4) + LData[27] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($C6E00BF33DA88FC2) + LData[28] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($D5A79147930AA725) + LData[29] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($06CA6351E003826F) + LData[30] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($142929670A0E6E70) + LData[31] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R4

  LRegH := LRegH + (UInt64($27B70A8546D22FFC) + LData[32] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($2E1B21385C26C926) + LData[33] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($4D2C6DFC5AC42AED) + LData[34] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($53380D139D95B3DF) + LData[35] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($650A73548BAF63DE) + LData[36] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($766A0ABB3C77B2A8) + LData[37] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($81C2C92E47EDAEE6) + LData[38] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($92722C851482353B) + LData[39] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R5

  LRegH := LRegH + (UInt64($A2BFE8A14CF10364) + LData[40] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($A81A664BBC423001) + LData[41] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($C24B8B70D0F89791) + LData[42] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($C76C51A30654BE30) + LData[43] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($D192E819D6EF5218) + LData[44] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($D69906245565A910) + LData[45] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($F40E35855771202A) + LData[46] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($106AA07032BBD1B8) + LData[47] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R6

  LRegH := LRegH + (UInt64($19A4C116B8D2D0C8) + LData[48] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($1E376C085141AB53) + LData[49] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($2748774CDF8EEB99) + LData[50] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($34B0BCB5E19B48A8) + LData[51] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($391C0CB3C5C95A63) + LData[52] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($4ED8AA4AE3418ACB) + LData[53] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($5B9CCA4F7763E373) + LData[54] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($682E6FF3D6B2B8A3) + LData[55] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R7

  LRegH := LRegH + (UInt64($748F82EE5DEFB2FC) + LData[56] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($78A5636F43172F60) + LData[57] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($84C87814A1F0AB72) + LData[58] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($8CC702081A6439EC) + LData[59] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($90BEFFFA23631E28) + LData[60] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($A4506CEBDE82BDE9) + LData[61] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($BEF9A3F7B2C67915) + LData[62] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($C67178F2E372532B) + LData[63] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R8

  LRegH := LRegH + (UInt64($CA273ECEEA26619C) + LData[64] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($D186B8C721C0C207) + LData[65] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($EADA7DD6CDE0EB1E) + LData[66] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($F57D4F7FEE6ED178) + LData[67] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($06F067AA72176FBA) + LData[68] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($0A637DC5A2C898A6) + LData[69] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($113F9804BEF90DAE) + LData[70] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($1B710B35131C471B) + LData[71] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

  // R9

  LRegH := LRegH + (UInt64($28DB77F523047D84) + LData[72] + ((TBits.RotateLeft64(LRegE, 50))
    xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
    ((LRegE and LRegF) xor (not LRegE and LRegG)));

  LRegD := LRegD + LRegH;
  LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
    xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC)));

  LRegG := LRegG + (UInt64($32CAAB7B40C72493) + LData[73] + ((TBits.RotateLeft64(LRegD, 50))
    xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
    ((LRegD and LRegE) xor (not LRegD and LRegF)));

  LRegC := LRegC + LRegG;
  LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
    xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB)));

  LRegF := LRegF + (UInt64($3C9EBE0A15C9BEBC) + LData[74] + ((TBits.RotateLeft64(LRegC, 50))
    xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
    ((LRegC and LRegD) xor (not LRegC and LRegE)));

  LRegB := LRegB + LRegF;
  LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
    xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA)));

  LRegE := LRegE + (UInt64($431D67C49C100D4C) + LData[75] + ((TBits.RotateLeft64(LRegB, 50))
    xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
    ((LRegB and LRegC) xor (not LRegB and LRegD)));

  LRegA := LRegA + LRegE;
  LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
    xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH)));

  LRegD := LRegD + (UInt64($4CC5D4BECB3E42B6) + LData[76] + ((TBits.RotateLeft64(LRegA, 50))
    xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
    ((LRegA and LRegB) xor (not LRegA and LRegC)));

  LRegH := LRegH + LRegD;
  LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
    xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG)));

  LRegC := LRegC + (UInt64($597F299CFC657E2A) + LData[77] + ((TBits.RotateLeft64(LRegH, 50))
    xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
    ((LRegH and LRegA) xor (not LRegH and LRegB)));

  LRegG := LRegG + LRegC;
  LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
    xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF)));

  LRegB := LRegB + (UInt64($5FCB6FAB3AD6FAEC) + LData[78] + ((TBits.RotateLeft64(LRegG, 50))
    xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
    ((LRegG and LRegH) xor (not LRegG and LRegA)));

  LRegF := LRegF + LRegB;
  LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
    xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE)));

  LRegA := LRegA + (UInt64($6C44198C4A475817) + LData[79] + ((TBits.RotateLeft64(LRegF, 50))
    xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
    ((LRegF and LRegG) xor (not LRegF and LRegH)));

  LRegE := LRegE + LRegA;
  LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
    xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD)));

{$ELSE}
  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];
  LRegE := FState[4];
  LRegF := FState[5];
  LRegG := FState[6];
  LRegH := FState[7];

  // Step 1

  for LScheduleIdx := 16 to 79 do
  begin
    LT0 := LData[LScheduleIdx - 15];
    LT1 := LData[LScheduleIdx - 2];
    LData[LScheduleIdx] := ((TBits.RotateLeft64(LT1, 45)) xor (TBits.RotateLeft64(LT1, 3))
      xor (LT1 shr 6)) + LData[LScheduleIdx - 7] +
      ((TBits.RotateLeft64(LT0, 63)) xor (TBits.RotateLeft64(LT0, 56))
      xor (LT0 shr 7)) + LData[LScheduleIdx - 16];
  end;


  // Step 2

  LSkIndex := 0;
  LBatchIdx := 0;

  while LBatchIdx <= 9 do

  begin

    LRegH := LRegH + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegE, 50))
      xor (TBits.RotateLeft64(LRegE, 46)) xor (TBits.RotateLeft64(LRegE, 23))) +
      ((LRegE and LRegF) xor (not LRegE and LRegG)));
    System.Inc(LSkIndex);
    LRegD := LRegD + LRegH;
    LRegH := LRegH + (((TBits.RotateLeft64(LRegA, 36)) xor (TBits.RotateLeft64(LRegA, 30))
      xor (TBits.RotateLeft64(LRegA, 25))) + ((LRegA and LRegB) xor (LRegA and LRegC)
      xor (LRegB and LRegC)));

    LRegG := LRegG + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegD, 50))
      xor (TBits.RotateLeft64(LRegD, 46)) xor (TBits.RotateLeft64(LRegD, 23))) +
      ((LRegD and LRegE) xor (not LRegD and LRegF)));
    System.Inc(LSkIndex);
    LRegC := LRegC + LRegG;
    LRegG := LRegG + (((TBits.RotateLeft64(LRegH, 36)) xor (TBits.RotateLeft64(LRegH, 30))
      xor (TBits.RotateLeft64(LRegH, 25))) + ((LRegH and LRegA) xor (LRegH and LRegB)
      xor (LRegA and LRegB)));

    LRegF := LRegF + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegC, 50))
      xor (TBits.RotateLeft64(LRegC, 46)) xor (TBits.RotateLeft64(LRegC, 23))) +
      ((LRegC and LRegD) xor (not LRegC and LRegE)));
    System.Inc(LSkIndex);
    LRegB := LRegB + LRegF;
    LRegF := LRegF + (((TBits.RotateLeft64(LRegG, 36)) xor (TBits.RotateLeft64(LRegG, 30))
      xor (TBits.RotateLeft64(LRegG, 25))) + ((LRegG and LRegH) xor (LRegG and LRegA)
      xor (LRegH and LRegA)));

    LRegE := LRegE + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegB, 50))
      xor (TBits.RotateLeft64(LRegB, 46)) xor (TBits.RotateLeft64(LRegB, 23))) +
      ((LRegB and LRegC) xor (not LRegB and LRegD)));
    System.Inc(LSkIndex);
    LRegA := LRegA + LRegE;
    LRegE := LRegE + (((TBits.RotateLeft64(LRegF, 36)) xor (TBits.RotateLeft64(LRegF, 30))
      xor (TBits.RotateLeft64(LRegF, 25))) + ((LRegF and LRegG) xor (LRegF and LRegH)
      xor (LRegG and LRegH)));

    LRegD := LRegD + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegA, 50))
      xor (TBits.RotateLeft64(LRegA, 46)) xor (TBits.RotateLeft64(LRegA, 23))) +
      ((LRegA and LRegB) xor (not LRegA and LRegC)));
    System.Inc(LSkIndex);
    LRegH := LRegH + LRegD;
    LRegD := LRegD + (((TBits.RotateLeft64(LRegE, 36)) xor (TBits.RotateLeft64(LRegE, 30))
      xor (TBits.RotateLeft64(LRegE, 25))) + ((LRegE and LRegF) xor (LRegE and LRegG)
      xor (LRegF and LRegG)));

    LRegC := LRegC + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegH, 50))
      xor (TBits.RotateLeft64(LRegH, 46)) xor (TBits.RotateLeft64(LRegH, 23))) +
      ((LRegH and LRegA) xor (not LRegH and LRegB)));
    System.Inc(LSkIndex);
    LRegG := LRegG + LRegC;
    LRegC := LRegC + (((TBits.RotateLeft64(LRegD, 36)) xor (TBits.RotateLeft64(LRegD, 30))
      xor (TBits.RotateLeft64(LRegD, 25))) + ((LRegD and LRegE) xor (LRegD and LRegF)
      xor (LRegE and LRegF)));

    LRegB := LRegB + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegG, 50))
      xor (TBits.RotateLeft64(LRegG, 46)) xor (TBits.RotateLeft64(LRegG, 23))) +
      ((LRegG and LRegH) xor (not LRegG and LRegA)));
    System.Inc(LSkIndex);
    LRegF := LRegF + LRegB;
    LRegB := LRegB + (((TBits.RotateLeft64(LRegC, 36)) xor (TBits.RotateLeft64(LRegC, 30))
      xor (TBits.RotateLeft64(LRegC, 25))) + ((LRegC and LRegD) xor (LRegC and LRegE)
      xor (LRegD and LRegE)));

    LRegA := LRegA + (SK[LSkIndex] + LData[LSkIndex] + ((TBits.RotateLeft64(LRegF, 50))
      xor (TBits.RotateLeft64(LRegF, 46)) xor (TBits.RotateLeft64(LRegF, 23))) +
      ((LRegF and LRegG) xor (not LRegF and LRegH)));
    System.Inc(LSkIndex);
    LRegE := LRegE + LRegA;
    LRegA := LRegA + (((TBits.RotateLeft64(LRegB, 36)) xor (TBits.RotateLeft64(LRegB, 30))
      xor (TBits.RotateLeft64(LRegB, 25))) + ((LRegB and LRegC) xor (LRegB and LRegD)
      xor (LRegC and LRegD)));

    System.Inc(LBatchIdx);
  end;

{$ENDIF USE_UNROLLED_VARIANT}
  FState[0] := FState[0] + LRegA;
  FState[1] := FState[1] + LRegB;
  FState[2] := FState[2] + LRegC;
  FState[3] := FState[3] + LRegD;
  FState[4] := FState[4] + LRegE;
  FState[5] := FState[5] + LRegF;
  FState[6] := FState[6] + LRegG;
  FState[7] := FState[7] + LRegH;

  System.FillChar(LData, System.SizeOf(LData), UInt64(0));
end;

end.
