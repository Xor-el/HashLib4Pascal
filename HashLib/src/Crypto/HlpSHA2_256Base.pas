unit HlpSHA2_256Base;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA2_256Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$IFNDEF USE_UNROLLED_VARIANT}
{$REGION 'Consts'}
  const
    SK: array [0 .. 63] of UInt32 = ($428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
      $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5, $D807AA98, $12835B01,
      $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
      $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA,
      $5CB0A9DC, $76F988DA, $983E5152, $A831C66D, $B00327C8, $BF597FC7,
      $C6E00BF3, $D5A79147, $06CA6351, $14292967, $27B70A85, $2E1B2138,
      $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85,
      $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819, $D6990624,
      $F40E3585, $106AA070, $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
      $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3, $748F82EE, $78A5636F,
      $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

{$ENDREGION}
{$ENDIF USE_UNROLLED_VARIANT}
  strict protected
  var
    FState: THashLibUInt32Array;

    constructor Create(AHashSize: Int32);

    procedure Finish(); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  end;

implementation

{ TSHA2_256Base }

constructor TSHA2_256Base.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 64);
  System.SetLength(FState, 8);
end;

procedure TSHA2_256Base.Finish;
var
  LBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LBits := FProcessedBytesCount * 8;
  if (FBuffer.Position < 56) then
  begin
    LPadIndex := (56 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (120 - FBuffer.Position);
  end;
  System.SetLength(LPad, LPadIndex + 8);
  LPad[0] := $80;

  LBits := TConverters.be2me_64(LBits);

  TConverters.ReadUInt64AsBytesLE(LBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

procedure TSHA2_256Base.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegE, LRegF, LRegG, LRegH, LT1, LT2: UInt32;
{$IFNDEF USE_UNROLLED_VARIANT}
  LRound: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
  LData: array [0 .. 63] of UInt32;
begin
  TConverters.be32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];
  LRegE := FState[4];
  LRegF := FState[5];
  LRegG := FState[6];
  LRegH := FState[7];

  // Step 1

{$IFDEF USE_UNROLLED_VARIANT}
  LT1 := LData[14];
  LT2 := LData[1];
  LData[16] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[9] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[0];

  LT1 := LData[15];
  LT2 := LData[2];
  LData[17] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[10] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[1];

  LT1 := LData[16];
  LT2 := LData[3];
  LData[18] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[11] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[2];

  LT1 := LData[17];
  LT2 := LData[4];
  LData[19] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[12] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[3];

  LT1 := LData[18];
  LT2 := LData[5];
  LData[20] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[13] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[4];

  LT1 := LData[19];
  LT2 := LData[6];
  LData[21] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[14] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[5];

  LT1 := LData[20];
  LT2 := LData[7];
  LData[22] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[15] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[6];

  LT1 := LData[21];
  LT2 := LData[8];
  LData[23] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[16] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[7];

  LT1 := LData[22];
  LT2 := LData[9];
  LData[24] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[17] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[8];

  LT1 := LData[23];
  LT2 := LData[10];
  LData[25] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[18] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[9];

  LT1 := LData[24];
  LT2 := LData[11];
  LData[26] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[19] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[10];

  LT1 := LData[25];
  LT2 := LData[12];
  LData[27] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[20] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[11];

  LT1 := LData[26];
  LT2 := LData[13];
  LData[28] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[21] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[12];

  LT1 := LData[27];
  LT2 := LData[14];
  LData[29] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[22] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[13];

  LT1 := LData[28];
  LT2 := LData[15];
  LData[30] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[23] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[14];

  LT1 := LData[29];
  LT2 := LData[16];
  LData[31] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[24] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[15];

  LT1 := LData[30];
  LT2 := LData[17];
  LData[32] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[25] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[16];

  LT1 := LData[31];
  LT2 := LData[18];
  LData[33] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[26] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[17];

  LT1 := LData[32];
  LT2 := LData[19];
  LData[34] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[27] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[18];

  LT1 := LData[33];
  LT2 := LData[20];
  LData[35] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[28] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[19];

  LT1 := LData[34];
  LT2 := LData[21];
  LData[36] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[29] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[20];

  LT1 := LData[35];
  LT2 := LData[22];
  LData[37] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[30] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[21];

  LT1 := LData[36];
  LT2 := LData[23];
  LData[38] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[31] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[22];

  LT1 := LData[37];
  LT2 := LData[24];
  LData[39] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[32] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[23];

  LT1 := LData[38];
  LT2 := LData[25];
  LData[40] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[33] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[24];

  LT1 := LData[39];
  LT2 := LData[26];
  LData[41] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[34] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[25];

  LT1 := LData[40];
  LT2 := LData[27];
  LData[42] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[35] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[26];

  LT1 := LData[41];
  LT2 := LData[28];
  LData[43] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[36] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[27];

  LT1 := LData[42];
  LT2 := LData[29];
  LData[44] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[37] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[28];

  LT1 := LData[43];
  LT2 := LData[30];
  LData[45] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[38] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[29];

  LT1 := LData[44];
  LT2 := LData[31];
  LData[46] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[39] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[30];

  LT1 := LData[45];
  LT2 := LData[32];
  LData[47] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[40] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[31];

  LT1 := LData[46];
  LT2 := LData[33];
  LData[48] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[41] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[32];

  LT1 := LData[47];
  LT2 := LData[34];
  LData[49] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[42] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[33];

  LT1 := LData[48];
  LT2 := LData[35];
  LData[50] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[43] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[34];

  LT1 := LData[49];
  LT2 := LData[36];
  LData[51] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[44] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[35];

  LT1 := LData[50];
  LT2 := LData[37];
  LData[52] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[45] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[36];

  LT1 := LData[51];
  LT2 := LData[38];
  LData[53] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[46] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[37];

  LT1 := LData[52];
  LT2 := LData[39];
  LData[54] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[47] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[38];

  LT1 := LData[53];
  LT2 := LData[40];
  LData[55] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[48] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[39];

  LT1 := LData[54];
  LT2 := LData[41];
  LData[56] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[49] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[40];

  LT1 := LData[55];
  LT2 := LData[42];
  LData[57] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[50] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[41];

  LT1 := LData[56];
  LT2 := LData[43];
  LData[58] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[51] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[42];

  LT1 := LData[57];
  LT2 := LData[44];
  LData[59] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[52] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[43];

  LT1 := LData[58];
  LT2 := LData[45];
  LData[60] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[53] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[44];

  LT1 := LData[59];
  LT2 := LData[46];
  LData[61] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[54] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[45];

  LT1 := LData[60];
  LT2 := LData[47];
  LData[62] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[55] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[46];

  LT1 := LData[61];
  LT2 := LData[48];
  LData[63] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
    xor (LT1 shr 10)) + LData[56] +
    ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
    xor (LT2 shr 3)) + LData[47];

  // Step 2

  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $428A2F98 + LData[0];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $71374491 + LData[1];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $B5C0FBCF + LData[2];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $E9B5DBA5 + LData[3];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $3956C25B + LData[4];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $59F111F1 + LData[5];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $923F82A4 + LData[6];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $AB1C5ED5 + LData[7];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $D807AA98 + LData[8];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $12835B01 + LData[9];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $243185BE + LData[10];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $550C7DC3 + LData[11];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $72BE5D74 + LData[12];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $80DEB1FE + LData[13];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $9BDC06A7 + LData[14];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $C19BF174 + LData[15];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $E49B69C1 + LData[16];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $EFBE4786 + LData[17];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $0FC19DC6 + LData[18];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $240CA1CC + LData[19];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $2DE92C6F + LData[20];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $4A7484AA + LData[21];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $5CB0A9DC + LData[22];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $76F988DA + LData[23];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $983E5152 + LData[24];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $A831C66D + LData[25];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $B00327C8 + LData[26];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $BF597FC7 + LData[27];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $C6E00BF3 + LData[28];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $D5A79147 + LData[29];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $06CA6351 + LData[30];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $14292967 + LData[31];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $27B70A85 + LData[32];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $2E1B2138 + LData[33];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $4D2C6DFC + LData[34];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $53380D13 + LData[35];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $650A7354 + LData[36];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $766A0ABB + LData[37];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $81C2C92E + LData[38];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $92722C85 + LData[39];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $A2BFE8A1 + LData[40];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $A81A664B + LData[41];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $C24B8B70 + LData[42];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $C76C51A3 + LData[43];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $D192E819 + LData[44];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $D6990624 + LData[45];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $F40E3585 + LData[46];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $106AA070 + LData[47];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $19A4C116 + LData[48];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $1E376C08 + LData[49];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $2748774C + LData[50];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $34B0BCB5 + LData[51];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $391C0CB3 + LData[52];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $4ED8AA4A + LData[53];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $5B9CCA4F + LData[54];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $682E6FF3 + LData[55];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;
  LT1 := LRegH + ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
    xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG)) +
    $748F82EE + LData[56];
  LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
    xor ((LRegA shr 22) xor (LRegA shl 10))) + ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));
  LRegH := LT1 + LT2;
  LRegD := LRegD + LT1;
  LT1 := LRegG + ((TBits.RotateRight32(LRegD, 6)) xor (TBits.RotateRight32(LRegD, 11))
    xor (TBits.RotateRight32(LRegD, 25))) + ((LRegD and LRegE) xor (not LRegD and LRegF)) +
    $78A5636F + LData[57];
  LT2 := ((TBits.RotateRight32(LRegH, 2)) xor (TBits.RotateRight32(LRegH, 13))
    xor ((LRegH shr 22) xor (LRegH shl 10))) + ((LRegH and LRegA) xor (LRegH and LRegB) xor (LRegA and LRegB));
  LRegG := LT1 + LT2;
  LRegC := LRegC + LT1;
  LT1 := LRegF + ((TBits.RotateRight32(LRegC, 6)) xor (TBits.RotateRight32(LRegC, 11))
    xor (TBits.RotateRight32(LRegC, 25))) + ((LRegC and LRegD) xor (not LRegC and LRegE)) +
    $84C87814 + LData[58];
  LT2 := ((TBits.RotateRight32(LRegG, 2)) xor (TBits.RotateRight32(LRegG, 13))
    xor ((LRegG shr 22) xor (LRegG shl 10))) + ((LRegG and LRegH) xor (LRegG and LRegA) xor (LRegH and LRegA));
  LRegF := LT1 + LT2;
  LRegB := LRegB + LT1;
  LT1 := LRegE + ((TBits.RotateRight32(LRegB, 6)) xor (TBits.RotateRight32(LRegB, 11))
    xor (TBits.RotateRight32(LRegB, 25))) + ((LRegB and LRegC) xor (not LRegB and LRegD)) +
    $8CC70208 + LData[59];
  LT2 := ((TBits.RotateRight32(LRegF, 2)) xor (TBits.RotateRight32(LRegF, 13))
    xor ((LRegF shr 22) xor (LRegF shl 10))) + ((LRegF and LRegG) xor (LRegF and LRegH) xor (LRegG and LRegH));
  LRegE := LT1 + LT2;
  LRegA := LRegA + LT1;
  LT1 := LRegD + ((TBits.RotateRight32(LRegA, 6)) xor (TBits.RotateRight32(LRegA, 11))
    xor (TBits.RotateRight32(LRegA, 25))) + ((LRegA and LRegB) xor (not LRegA and LRegC)) +
    $90BEFFFA + LData[60];
  LT2 := ((TBits.RotateRight32(LRegE, 2)) xor (TBits.RotateRight32(LRegE, 13))
    xor ((LRegE shr 22) xor (LRegE shl 10))) + ((LRegE and LRegF) xor (LRegE and LRegG) xor (LRegF and LRegG));
  LRegD := LT1 + LT2;
  LRegH := LRegH + LT1;
  LT1 := LRegC + ((TBits.RotateRight32(LRegH, 6)) xor (TBits.RotateRight32(LRegH, 11))
    xor (TBits.RotateRight32(LRegH, 25))) + ((LRegH and LRegA) xor (not LRegH and LRegB)) +
    $A4506CEB + LData[61];
  LT2 := ((TBits.RotateRight32(LRegD, 2)) xor (TBits.RotateRight32(LRegD, 13))
    xor ((LRegD shr 22) xor (LRegD shl 10))) + ((LRegD and LRegE) xor (LRegD and LRegF) xor (LRegE and LRegF));
  LRegC := LT1 + LT2;
  LRegG := LRegG + LT1;
  LT1 := LRegB + ((TBits.RotateRight32(LRegG, 6)) xor (TBits.RotateRight32(LRegG, 11))
    xor (TBits.RotateRight32(LRegG, 25))) + ((LRegG and LRegH) xor (not LRegG and LRegA)) +
    $BEF9A3F7 + LData[62];
  LT2 := ((TBits.RotateRight32(LRegC, 2)) xor (TBits.RotateRight32(LRegC, 13))
    xor ((LRegC shr 22) xor (LRegC shl 10))) + ((LRegC and LRegD) xor (LRegC and LRegE) xor (LRegD and LRegE));
  LRegB := LT1 + LT2;
  LRegF := LRegF + LT1;
  LT1 := LRegA + ((TBits.RotateRight32(LRegF, 6)) xor (TBits.RotateRight32(LRegF, 11))
    xor (TBits.RotateRight32(LRegF, 25))) + ((LRegF and LRegG) xor (not LRegF and LRegH)) +
    $C67178F2 + LData[63];
  LT2 := ((TBits.RotateRight32(LRegB, 2)) xor (TBits.RotateRight32(LRegB, 13))
    xor ((LRegB shr 22) xor (LRegB shl 10))) + ((LRegB and LRegC) xor (LRegB and LRegD) xor (LRegC and LRegD));
  LRegA := LT1 + LT2;
  LRegE := LRegE + LT1;

{$ELSE}
  // Step 1
  for LRound := 16 to 63 do
  begin
    LT1 := LData[LRound - 2];
    LT2 := LData[LRound - 15];
    LData[LRound] := ((TBits.RotateRight32(LT1, 17)) xor (TBits.RotateRight32(LT1, 19))
      xor (LT1 shr 10)) + LData[LRound - 7] +
      ((TBits.RotateRight32(LT2, 7)) xor (TBits.RotateRight32(LT2, 18))
      xor (LT2 shr 3)) + LData[LRound - 16];
  end;

  // Step 2

  for LRound := 0 to 63 do
  begin

    LT1 := SK[LRound] + LData[LRound] + LRegH +
      ((TBits.RotateRight32(LRegE, 6)) xor (TBits.RotateRight32(LRegE, 11))
      xor (TBits.RotateRight32(LRegE, 25))) + ((LRegE and LRegF) xor (not LRegE and LRegG));
    LT2 := ((TBits.RotateRight32(LRegA, 2)) xor (TBits.RotateRight32(LRegA, 13))
      xor (TBits.RotateRight32(LRegA, 22))) +
      ((LRegA and LRegB) xor (LRegA and LRegC) xor (LRegB and LRegC));

    LRegH := LRegG;
    LRegG := LRegF;
    LRegF := LRegE;
    LRegE := LRegD + LT1;
    LRegD := LRegC;
    LRegC := LRegB;
    LRegB := LRegA;
    LRegA := LT1 + LT2;
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

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
