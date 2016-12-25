unit HlpSHA2_256Base;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashLibTypes,
{$IFDEF DELPHI}
  HlpHashBuffer,
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA2_256Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$IFNDEF USE_UNROLLED_VARIANT}
{$REGION 'Consts'}
  const

    s_K: array [0 .. 63] of UInt32 = ($428A2F98, $71374491, $B5C0FBCF,
      $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5, $D807AA98,
      $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7,
      $C19BF174, $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F,
      $4A7484AA, $5CB0A9DC, $76F988DA, $983E5152, $A831C66D, $B00327C8,
      $BF597FC7, $C6E00BF3, $D5A79147, $06CA6351, $14292967, $27B70A85,
      $2E1B2138, $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E,
      $92722C85, $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819,
      $D6990624, $F40E3585, $106AA070, $19A4C116, $1E376C08, $2748774C,
      $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3, $748F82EE,
      $78A5636F, $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7,
      $C67178F2);

{$ENDREGION}
{$ENDIF USE_UNROLLED_VARIANT}
  strict protected
    Fm_state: THashLibUInt32Array;
    Fptr_Fm_state: PCardinal;

    constructor Create(a_hash_size: Int32);

    procedure Finish(); override;
    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
      a_index: Int32); override;

  end;

implementation

{ TSHA2_256Base }

constructor TSHA2_256Base.Create(a_hash_size: Int32);
begin
  Inherited Create(a_hash_size, 64);
  System.SetLength(Fm_state, 8);
  Fptr_Fm_state := PCardinal(Fm_state);
end;

procedure TSHA2_256Base.Finish;
var
  bits: UInt64;
  padindex: Int32;
  pad: THashLibByteArray;
begin
  bits := Fm_processed_bytes * 8;
  if (Fm_buffer.Pos < 56) then

    padindex := (56 - Fm_buffer.Pos)
  else
    padindex := (120 - Fm_buffer.Pos);
  System.SetLength(pad, padindex + 8);
  pad[0] := $80;

  bits := TConverters.be2me_64(bits);

  TConverters.ReadUInt64AsBytesLE(bits, pad, padindex);

  padindex := padindex + 8;

  TransformBytes(pad, 0, padindex);

end;

procedure TSHA2_256Base.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  A, B, C, D, E, F, G, H, T, T2: UInt32;
{$IFNDEF USE_UNROLLED_VARIANT}
  r: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
  data: array [0 .. 63] of UInt32;
  ptr_data: PCardinal;
begin

  ptr_data := @(data[0]);

  TConverters.be32_copy(a_data, a_index, ptr_data, 0, 64);

  A := Fptr_Fm_state[0];
  B := Fptr_Fm_state[1];
  C := Fptr_Fm_state[2];
  D := Fptr_Fm_state[3];
  E := Fptr_Fm_state[4];
  F := Fptr_Fm_state[5];
  G := Fptr_Fm_state[6];
  H := Fptr_Fm_state[7];

  // Step 1

{$IFDEF USE_UNROLLED_VARIANT}
  T := ptr_data[14];
  T2 := ptr_data[1];
  ptr_data[16] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[9] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[0];

  T := ptr_data[15];
  T2 := ptr_data[2];
  ptr_data[17] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[10] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[1];

  T := ptr_data[16];
  T2 := ptr_data[3];
  ptr_data[18] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[11] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[2];

  T := ptr_data[17];
  T2 := ptr_data[4];
  ptr_data[19] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[12] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[3];

  T := ptr_data[18];
  T2 := ptr_data[5];
  ptr_data[20] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[13] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[4];

  T := ptr_data[19];
  T2 := ptr_data[6];
  ptr_data[21] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[14] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[5];

  T := ptr_data[20];
  T2 := ptr_data[7];
  ptr_data[22] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[15] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[6];

  T := ptr_data[21];
  T2 := ptr_data[8];
  ptr_data[23] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[16] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[7];

  T := ptr_data[22];
  T2 := ptr_data[9];
  ptr_data[24] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[17] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[8];

  T := ptr_data[23];
  T2 := ptr_data[10];
  ptr_data[25] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[18] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[9];

  T := ptr_data[24];
  T2 := ptr_data[11];
  ptr_data[26] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[19] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[10];

  T := ptr_data[25];
  T2 := ptr_data[12];
  ptr_data[27] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[20] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[11];

  T := ptr_data[26];
  T2 := ptr_data[13];
  ptr_data[28] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[21] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[12];

  T := ptr_data[27];
  T2 := ptr_data[14];
  ptr_data[29] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[22] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[13];

  T := ptr_data[28];
  T2 := ptr_data[15];
  ptr_data[30] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[23] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[14];

  T := ptr_data[29];
  T2 := ptr_data[16];
  ptr_data[31] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[24] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[15];

  T := ptr_data[30];
  T2 := ptr_data[17];
  ptr_data[32] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[25] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[16];

  T := ptr_data[31];
  T2 := ptr_data[18];
  ptr_data[33] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[26] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[17];

  T := ptr_data[32];
  T2 := ptr_data[19];
  ptr_data[34] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[27] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[18];

  T := ptr_data[33];
  T2 := ptr_data[20];
  ptr_data[35] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[28] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[19];

  T := ptr_data[34];
  T2 := ptr_data[21];
  ptr_data[36] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[29] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[20];

  T := ptr_data[35];
  T2 := ptr_data[22];
  ptr_data[37] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[30] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[21];

  T := ptr_data[36];
  T2 := ptr_data[23];
  ptr_data[38] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[31] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[22];

  T := ptr_data[37];
  T2 := ptr_data[24];
  ptr_data[39] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[32] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[23];

  T := ptr_data[38];
  T2 := ptr_data[25];
  ptr_data[40] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[33] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[24];

  T := ptr_data[39];
  T2 := ptr_data[26];
  ptr_data[41] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[34] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[25];

  T := ptr_data[40];
  T2 := ptr_data[27];
  ptr_data[42] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[35] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[26];

  T := ptr_data[41];
  T2 := ptr_data[28];
  ptr_data[43] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[36] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[27];

  T := ptr_data[42];
  T2 := ptr_data[29];
  ptr_data[44] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[37] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[28];

  T := ptr_data[43];
  T2 := ptr_data[30];
  ptr_data[45] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[38] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[29];

  T := ptr_data[44];
  T2 := ptr_data[31];
  ptr_data[46] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[39] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[30];

  T := ptr_data[45];
  T2 := ptr_data[32];
  ptr_data[47] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[40] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[31];

  T := ptr_data[46];
  T2 := ptr_data[33];
  ptr_data[48] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[41] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[32];

  T := ptr_data[47];
  T2 := ptr_data[34];
  ptr_data[49] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[42] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[33];

  T := ptr_data[48];
  T2 := ptr_data[35];
  ptr_data[50] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[43] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[34];

  T := ptr_data[49];
  T2 := ptr_data[36];
  ptr_data[51] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[44] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[35];

  T := ptr_data[50];
  T2 := ptr_data[37];
  ptr_data[52] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[45] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[36];

  T := ptr_data[51];
  T2 := ptr_data[38];
  ptr_data[53] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[46] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[37];

  T := ptr_data[52];
  T2 := ptr_data[39];
  ptr_data[54] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[47] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[38];

  T := ptr_data[53];
  T2 := ptr_data[40];
  ptr_data[55] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[48] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[39];

  T := ptr_data[54];
  T2 := ptr_data[41];
  ptr_data[56] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[49] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[40];

  T := ptr_data[55];
  T2 := ptr_data[42];
  ptr_data[57] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[50] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[41];

  T := ptr_data[56];
  T2 := ptr_data[43];
  ptr_data[58] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[51] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[42];

  T := ptr_data[57];
  T2 := ptr_data[44];
  ptr_data[59] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[52] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[43];

  T := ptr_data[58];
  T2 := ptr_data[45];
  ptr_data[60] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[53] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[44];

  T := ptr_data[59];
  T2 := ptr_data[46];
  ptr_data[61] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[54] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[45];

  T := ptr_data[60];
  T2 := ptr_data[47];
  ptr_data[62] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[55] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[46];

  T := ptr_data[61];
  T2 := ptr_data[48];
  ptr_data[63] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19))
    xor (T shr 10)) + ptr_data[56] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + ptr_data[47];

  // Step 2

  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $428A2F98 + ptr_data[0];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $71374491 + ptr_data[1];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $B5C0FBCF + ptr_data[2];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $E9B5DBA5 + ptr_data[3];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $3956C25B + ptr_data[4];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $59F111F1 + ptr_data[5];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $923F82A4 + ptr_data[6];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $AB1C5ED5 + ptr_data[7];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $D807AA98 + ptr_data[8];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $12835B01 + ptr_data[9];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $243185BE + ptr_data[10];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $550C7DC3 + ptr_data[11];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $72BE5D74 + ptr_data[12];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $80DEB1FE + ptr_data[13];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $9BDC06A7 + ptr_data[14];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $C19BF174 + ptr_data[15];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $E49B69C1 + ptr_data[16];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $EFBE4786 + ptr_data[17];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $0FC19DC6 + ptr_data[18];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $240CA1CC + ptr_data[19];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $2DE92C6F + ptr_data[20];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $4A7484AA + ptr_data[21];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $5CB0A9DC + ptr_data[22];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $76F988DA + ptr_data[23];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $983E5152 + ptr_data[24];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $A831C66D + ptr_data[25];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $B00327C8 + ptr_data[26];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $BF597FC7 + ptr_data[27];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $C6E00BF3 + ptr_data[28];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $D5A79147 + ptr_data[29];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $06CA6351 + ptr_data[30];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $14292967 + ptr_data[31];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $27B70A85 + ptr_data[32];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $2E1B2138 + ptr_data[33];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $4D2C6DFC + ptr_data[34];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $53380D13 + ptr_data[35];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $650A7354 + ptr_data[36];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $766A0ABB + ptr_data[37];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $81C2C92E + ptr_data[38];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $92722C85 + ptr_data[39];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $A2BFE8A1 + ptr_data[40];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $A81A664B + ptr_data[41];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $C24B8B70 + ptr_data[42];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $C76C51A3 + ptr_data[43];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $D192E819 + ptr_data[44];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $D6990624 + ptr_data[45];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $F40E3585 + ptr_data[46];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $106AA070 + ptr_data[47];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $19A4C116 + ptr_data[48];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $1E376C08 + ptr_data[49];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $2748774C + ptr_data[50];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $34B0BCB5 + ptr_data[51];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $391C0CB3 + ptr_data[52];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $4ED8AA4A + ptr_data[53];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $5B9CCA4F + ptr_data[54];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $682E6FF3 + ptr_data[55];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;
  T := H + ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G)) +
    $748F82EE + ptr_data[56];
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor ((A shr 22) xor (A shl 10))) + ((A and B) xor (A and C) xor (B and C));
  H := T + T2;
  D := D + T;
  T := G + ((TBits.RotateRight32(D, 6)) xor (TBits.RotateRight32(D, 11))
    xor (TBits.RotateRight32(D, 25))) + ((D and E) xor (not D and F)) +
    $78A5636F + ptr_data[57];
  T2 := ((TBits.RotateRight32(H, 2)) xor (TBits.RotateRight32(H, 13))
    xor ((H shr 22) xor (H shl 10))) + ((H and A) xor (H and B) xor (A and B));
  G := T + T2;
  C := C + T;
  T := F + ((TBits.RotateRight32(C, 6)) xor (TBits.RotateRight32(C, 11))
    xor (TBits.RotateRight32(C, 25))) + ((C and D) xor (not C and E)) +
    $84C87814 + ptr_data[58];
  T2 := ((TBits.RotateRight32(G, 2)) xor (TBits.RotateRight32(G, 13))
    xor ((G shr 22) xor (G shl 10))) + ((G and H) xor (G and A) xor (H and A));
  F := T + T2;
  B := B + T;
  T := E + ((TBits.RotateRight32(B, 6)) xor (TBits.RotateRight32(B, 11))
    xor (TBits.RotateRight32(B, 25))) + ((B and C) xor (not B and D)) +
    $8CC70208 + ptr_data[59];
  T2 := ((TBits.RotateRight32(F, 2)) xor (TBits.RotateRight32(F, 13))
    xor ((F shr 22) xor (F shl 10))) + ((F and G) xor (F and H) xor (G and H));
  E := T + T2;
  A := A + T;
  T := D + ((TBits.RotateRight32(A, 6)) xor (TBits.RotateRight32(A, 11))
    xor (TBits.RotateRight32(A, 25))) + ((A and B) xor (not A and C)) +
    $90BEFFFA + ptr_data[60];
  T2 := ((TBits.RotateRight32(E, 2)) xor (TBits.RotateRight32(E, 13))
    xor ((E shr 22) xor (E shl 10))) + ((E and F) xor (E and G) xor (F and G));
  D := T + T2;
  H := H + T;
  T := C + ((TBits.RotateRight32(H, 6)) xor (TBits.RotateRight32(H, 11))
    xor (TBits.RotateRight32(H, 25))) + ((H and A) xor (not H and B)) +
    $A4506CEB + ptr_data[61];
  T2 := ((TBits.RotateRight32(D, 2)) xor (TBits.RotateRight32(D, 13))
    xor ((D shr 22) xor (D shl 10))) + ((D and E) xor (D and F) xor (E and F));
  C := T + T2;
  G := G + T;
  T := B + ((TBits.RotateRight32(G, 6)) xor (TBits.RotateRight32(G, 11))
    xor (TBits.RotateRight32(G, 25))) + ((G and H) xor (not G and A)) +
    $BEF9A3F7 + ptr_data[62];
  T2 := ((TBits.RotateRight32(C, 2)) xor (TBits.RotateRight32(C, 13))
    xor ((C shr 22) xor (C shl 10))) + ((C and D) xor (C and E) xor (D and E));
  B := T + T2;
  F := F + T;
  T := A + ((TBits.RotateRight32(F, 6)) xor (TBits.RotateRight32(F, 11))
    xor (TBits.RotateRight32(F, 25))) + ((F and G) xor (not F and H)) +
    $C67178F2 + ptr_data[63];
  T2 := ((TBits.RotateRight32(B, 2)) xor (TBits.RotateRight32(B, 13))
    xor ((B shr 22) xor (B shl 10))) + ((B and C) xor (B and D) xor (C and D));
  A := T + T2;
  E := E + T;

{$ELSE}
  // Step 1
  for r := 16 to 63 do
  begin
    T := ptr_data[r - 2];
    T2 := ptr_data[r - 15];
    ptr_data[r] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T, 19)
      ) xor (T shr 10)) + ptr_data[r - 7] +
      ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
      xor (T2 shr 3)) + ptr_data[r - 16];
  end;

  // Step 2

  for r := 0 to 63 do
  begin

    T := s_K[r] + ptr_data[r] + H +
      ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
      xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
    T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
      xor (TBits.RotateRight32(A, 22))) +
      ((A and B) xor (A and C) xor (B and C));

    H := G;
    G := F;
    F := E;
    E := D + T;
    D := C;
    C := B;
    B := A;
    A := T + T2;
  end;

{$ENDIF USE_UNROLLED_VARIANT}
  Fptr_Fm_state[0] := Fptr_Fm_state[0] + A;
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + B;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + C;
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + D;
  Fptr_Fm_state[4] := Fptr_Fm_state[4] + E;
  Fptr_Fm_state[5] := Fptr_Fm_state[5] + F;
  Fptr_Fm_state[6] := Fptr_Fm_state[6] + G;
  Fptr_Fm_state[7] := Fptr_Fm_state[7] + H;

  System.FillChar(data, System.SizeOf(data), 0);

end;

end.
