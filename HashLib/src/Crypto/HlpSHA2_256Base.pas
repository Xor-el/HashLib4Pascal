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

  T := $428A2F98 + ptr_data[0] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $71374491 + ptr_data[1] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $B5C0FBCF + ptr_data[2] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $E9B5DBA5 + ptr_data[3] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $3956C25B + ptr_data[4] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $59F111F1 + ptr_data[5] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $923F82A4 + ptr_data[6] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $AB1C5ED5 + ptr_data[7] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $D807AA98 + ptr_data[8] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $12835B01 + ptr_data[9] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $243185BE + ptr_data[10] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $550C7DC3 + ptr_data[11] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $72BE5D74 + ptr_data[12] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $80DEB1FE + ptr_data[13] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $9BDC06A7 + ptr_data[14] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $C19BF174 + ptr_data[15] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $E49B69C1 + ptr_data[16] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $EFBE4786 + ptr_data[17] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $0FC19DC6 + ptr_data[18] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $240CA1CC + ptr_data[19] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $2DE92C6F + ptr_data[20] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $4A7484AA + ptr_data[21] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $5CB0A9DC + ptr_data[22] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $76F988DA + ptr_data[23] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $983E5152 + ptr_data[24] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $A831C66D + ptr_data[25] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $B00327C8 + ptr_data[26] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $BF597FC7 + ptr_data[27] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $C6E00BF3 + ptr_data[28] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $D5A79147 + ptr_data[29] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $06CA6351 + ptr_data[30] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $14292967 + ptr_data[31] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $27B70A85 + ptr_data[32] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $2E1B2138 + ptr_data[33] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $4D2C6DFC + ptr_data[34] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $53380D13 + ptr_data[35] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $650A7354 + ptr_data[36] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $766A0ABB + ptr_data[37] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $81C2C92E + ptr_data[38] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $92722C85 + ptr_data[39] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $A2BFE8A1 + ptr_data[40] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $A81A664B + ptr_data[41] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $C24B8B70 + ptr_data[42] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $C76C51A3 + ptr_data[43] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $D192E819 + ptr_data[44] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $D6990624 + ptr_data[45] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $F40E3585 + ptr_data[46] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $106AA070 + ptr_data[47] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $19A4C116 + ptr_data[48] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $1E376C08 + ptr_data[49] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $2748774C + ptr_data[50] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $34B0BCB5 + ptr_data[51] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $391C0CB3 + ptr_data[52] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $4ED8AA4A + ptr_data[53] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $5B9CCA4F + ptr_data[54] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $682E6FF3 + ptr_data[55] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $748F82EE + ptr_data[56] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $78A5636F + ptr_data[57] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $84C87814 + ptr_data[58] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $8CC70208 + ptr_data[59] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $90BEFFFA + ptr_data[60] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $A4506CEB + ptr_data[61] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $BEF9A3F7 + ptr_data[62] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;
  T := $C67178F2 + ptr_data[63] + H +
    ((TBits.RotateRight32(E, 6)) xor (TBits.RotateRight32(E, 11))
    xor (TBits.RotateRight32(E, 25))) + ((E and F) xor (not E and G));
  T2 := ((TBits.RotateRight32(A, 2)) xor (TBits.RotateRight32(A, 13))
    xor (TBits.RotateRight32(A, 22))) + ((A and B) xor (A and C) xor (B and C));
  H := G;
  G := F;
  F := E;
  E := D + T;
  D := C;
  C := B;
  B := A;
  A := T + T2;

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
