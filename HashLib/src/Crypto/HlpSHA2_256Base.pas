unit HlpSHA2_256Base;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashLibTypes,
  HlpHashBuffer,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA2_256Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private
    Fdata: THashLibUInt32Array;
    Fptr_Fdata: PCardinal;
    (*
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
    *)
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
  System.SetLength(Fdata, 64);
  Fptr_Fdata := PCardinal(Fdata);
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

  TConverters.ConvertUInt64ToBytesSwapOrder(bits, pad, padindex);
  padindex := padindex + 8;

  TransformBytes(pad, 0, padindex);

end;

procedure TSHA2_256Base.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  A, B, C, D, E, F, G, H, T, T2: UInt32;
  // r: Int32;
begin

  TConverters.ConvertBytesToUInt32SwapOrder(a_data, a_index, 64, Fptr_Fdata, 0);

  A := Fptr_Fm_state[0];
  B := Fptr_Fm_state[1];
  C := Fptr_Fm_state[2];
  D := Fptr_Fm_state[3];
  E := Fptr_Fm_state[4];
  F := Fptr_Fm_state[5];
  G := Fptr_Fm_state[6];
  H := Fptr_Fm_state[7];

  { for r := 16 to 63 do
    begin
    T := Fptr_Fdata[r - 2];
    T2 := Fptr_Fdata[r - 15];
    Fptr_Fdata[r] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[r - 7] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[r - 16];
    end;
  }

  T := Fptr_Fdata[14];
  T2 := Fptr_Fdata[1];
  Fptr_Fdata[16] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[9] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[0];

  T := Fptr_Fdata[15];
  T2 := Fptr_Fdata[2];
  Fptr_Fdata[17] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[10] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[1];

  T := Fptr_Fdata[16];
  T2 := Fptr_Fdata[3];
  Fptr_Fdata[18] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[11] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[2];

  T := Fptr_Fdata[17];
  T2 := Fptr_Fdata[4];
  Fptr_Fdata[19] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[12] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[3];

  T := Fptr_Fdata[18];
  T2 := Fptr_Fdata[5];
  Fptr_Fdata[20] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[13] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[4];

  T := Fptr_Fdata[19];
  T2 := Fptr_Fdata[6];
  Fptr_Fdata[21] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[14] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[5];

  T := Fptr_Fdata[20];
  T2 := Fptr_Fdata[7];
  Fptr_Fdata[22] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[15] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[6];

  T := Fptr_Fdata[21];
  T2 := Fptr_Fdata[8];
  Fptr_Fdata[23] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[16] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[7];

  T := Fptr_Fdata[22];
  T2 := Fptr_Fdata[9];
  Fptr_Fdata[24] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[17] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[8];

  T := Fptr_Fdata[23];
  T2 := Fptr_Fdata[10];
  Fptr_Fdata[25] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[18] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[9];

  T := Fptr_Fdata[24];
  T2 := Fptr_Fdata[11];
  Fptr_Fdata[26] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[19] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[10];

  T := Fptr_Fdata[25];
  T2 := Fptr_Fdata[12];
  Fptr_Fdata[27] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[20] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[11];

  T := Fptr_Fdata[26];
  T2 := Fptr_Fdata[13];
  Fptr_Fdata[28] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[21] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[12];

  T := Fptr_Fdata[27];
  T2 := Fptr_Fdata[14];
  Fptr_Fdata[29] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[22] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[13];

  T := Fptr_Fdata[28];
  T2 := Fptr_Fdata[15];
  Fptr_Fdata[30] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[23] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[14];

  T := Fptr_Fdata[29];
  T2 := Fptr_Fdata[16];
  Fptr_Fdata[31] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[24] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[15];

  T := Fptr_Fdata[30];
  T2 := Fptr_Fdata[17];
  Fptr_Fdata[32] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[25] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[16];

  T := Fptr_Fdata[31];
  T2 := Fptr_Fdata[18];
  Fptr_Fdata[33] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[26] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[17];

  T := Fptr_Fdata[32];
  T2 := Fptr_Fdata[19];
  Fptr_Fdata[34] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[27] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[18];

  T := Fptr_Fdata[33];
  T2 := Fptr_Fdata[20];
  Fptr_Fdata[35] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[28] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[19];

  T := Fptr_Fdata[34];
  T2 := Fptr_Fdata[21];
  Fptr_Fdata[36] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[29] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[20];

  T := Fptr_Fdata[35];
  T2 := Fptr_Fdata[22];
  Fptr_Fdata[37] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[30] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[21];

  T := Fptr_Fdata[36];
  T2 := Fptr_Fdata[23];
  Fptr_Fdata[38] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[31] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[22];

  T := Fptr_Fdata[37];
  T2 := Fptr_Fdata[24];
  Fptr_Fdata[39] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[32] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[23];

  T := Fptr_Fdata[38];
  T2 := Fptr_Fdata[25];
  Fptr_Fdata[40] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[33] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[24];

  T := Fptr_Fdata[39];
  T2 := Fptr_Fdata[26];
  Fptr_Fdata[41] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[34] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[25];

  T := Fptr_Fdata[40];
  T2 := Fptr_Fdata[27];
  Fptr_Fdata[42] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[35] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[26];

  T := Fptr_Fdata[41];
  T2 := Fptr_Fdata[28];
  Fptr_Fdata[43] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[36] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[27];

  T := Fptr_Fdata[42];
  T2 := Fptr_Fdata[29];
  Fptr_Fdata[44] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[37] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[28];

  T := Fptr_Fdata[43];
  T2 := Fptr_Fdata[30];
  Fptr_Fdata[45] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[38] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[29];

  T := Fptr_Fdata[44];
  T2 := Fptr_Fdata[31];
  Fptr_Fdata[46] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[39] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[30];

  T := Fptr_Fdata[45];
  T2 := Fptr_Fdata[32];
  Fptr_Fdata[47] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[40] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[31];

  T := Fptr_Fdata[46];
  T2 := Fptr_Fdata[33];
  Fptr_Fdata[48] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[41] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[32];

  T := Fptr_Fdata[47];
  T2 := Fptr_Fdata[34];
  Fptr_Fdata[49] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[42] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[33];

  T := Fptr_Fdata[48];
  T2 := Fptr_Fdata[35];
  Fptr_Fdata[50] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[43] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[34];

  T := Fptr_Fdata[49];
  T2 := Fptr_Fdata[36];
  Fptr_Fdata[51] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[44] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[35];

  T := Fptr_Fdata[50];
  T2 := Fptr_Fdata[37];
  Fptr_Fdata[52] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[45] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[36];

  T := Fptr_Fdata[51];
  T2 := Fptr_Fdata[38];
  Fptr_Fdata[53] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[46] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[37];

  T := Fptr_Fdata[52];
  T2 := Fptr_Fdata[39];
  Fptr_Fdata[54] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[47] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[38];

  T := Fptr_Fdata[53];
  T2 := Fptr_Fdata[40];
  Fptr_Fdata[55] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[48] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[39];

  T := Fptr_Fdata[54];
  T2 := Fptr_Fdata[41];
  Fptr_Fdata[56] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[49] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[40];

  T := Fptr_Fdata[55];
  T2 := Fptr_Fdata[42];
  Fptr_Fdata[57] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[50] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[41];

  T := Fptr_Fdata[56];
  T2 := Fptr_Fdata[43];
  Fptr_Fdata[58] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[51] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[42];

  T := Fptr_Fdata[57];
  T2 := Fptr_Fdata[44];
  Fptr_Fdata[59] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[52] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[43];

  T := Fptr_Fdata[58];
  T2 := Fptr_Fdata[45];
  Fptr_Fdata[60] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[53] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[44];

  T := Fptr_Fdata[59];
  T2 := Fptr_Fdata[46];
  Fptr_Fdata[61] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[54] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[45];

  T := Fptr_Fdata[60];
  T2 := Fptr_Fdata[47];
  Fptr_Fdata[62] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[55] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[46];

  T := Fptr_Fdata[61];
  T2 := Fptr_Fdata[48];
  Fptr_Fdata[63] := ((TBits.RotateRight32(T, 17)) xor (TBits.RotateRight32(T,
    19)) xor (T shr 10)) + Fptr_Fdata[56] +
    ((TBits.RotateRight32(T2, 7)) xor (TBits.RotateRight32(T2, 18))
    xor (T2 shr 3)) + Fptr_Fdata[47];

  {
    for r := 0 to 63 do
    begin

    T := s_K[r] + Fptr_Fdata[r] + H +
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
    end; }

  T := $428A2F98 + Fptr_Fdata[0] + H +
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
  T := $71374491 + Fptr_Fdata[1] + H +
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
  T := $B5C0FBCF + Fptr_Fdata[2] + H +
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
  T := $E9B5DBA5 + Fptr_Fdata[3] + H +
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
  T := $3956C25B + Fptr_Fdata[4] + H +
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
  T := $59F111F1 + Fptr_Fdata[5] + H +
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
  T := $923F82A4 + Fptr_Fdata[6] + H +
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
  T := $AB1C5ED5 + Fptr_Fdata[7] + H +
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
  T := $D807AA98 + Fptr_Fdata[8] + H +
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
  T := $12835B01 + Fptr_Fdata[9] + H +
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
  T := $243185BE + Fptr_Fdata[10] + H +
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
  T := $550C7DC3 + Fptr_Fdata[11] + H +
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
  T := $72BE5D74 + Fptr_Fdata[12] + H +
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
  T := $80DEB1FE + Fptr_Fdata[13] + H +
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
  T := $9BDC06A7 + Fptr_Fdata[14] + H +
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
  T := $C19BF174 + Fptr_Fdata[15] + H +
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
  T := $E49B69C1 + Fptr_Fdata[16] + H +
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
  T := $EFBE4786 + Fptr_Fdata[17] + H +
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
  T := $0FC19DC6 + Fptr_Fdata[18] + H +
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
  T := $240CA1CC + Fptr_Fdata[19] + H +
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
  T := $2DE92C6F + Fptr_Fdata[20] + H +
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
  T := $4A7484AA + Fptr_Fdata[21] + H +
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
  T := $5CB0A9DC + Fptr_Fdata[22] + H +
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
  T := $76F988DA + Fptr_Fdata[23] + H +
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
  T := $983E5152 + Fptr_Fdata[24] + H +
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
  T := $A831C66D + Fptr_Fdata[25] + H +
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
  T := $B00327C8 + Fptr_Fdata[26] + H +
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
  T := $BF597FC7 + Fptr_Fdata[27] + H +
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
  T := $C6E00BF3 + Fptr_Fdata[28] + H +
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
  T := $D5A79147 + Fptr_Fdata[29] + H +
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
  T := $06CA6351 + Fptr_Fdata[30] + H +
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
  T := $14292967 + Fptr_Fdata[31] + H +
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
  T := $27B70A85 + Fptr_Fdata[32] + H +
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
  T := $2E1B2138 + Fptr_Fdata[33] + H +
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
  T := $4D2C6DFC + Fptr_Fdata[34] + H +
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
  T := $53380D13 + Fptr_Fdata[35] + H +
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
  T := $650A7354 + Fptr_Fdata[36] + H +
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
  T := $766A0ABB + Fptr_Fdata[37] + H +
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
  T := $81C2C92E + Fptr_Fdata[38] + H +
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
  T := $92722C85 + Fptr_Fdata[39] + H +
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
  T := $A2BFE8A1 + Fptr_Fdata[40] + H +
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
  T := $A81A664B + Fptr_Fdata[41] + H +
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
  T := $C24B8B70 + Fptr_Fdata[42] + H +
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
  T := $C76C51A3 + Fptr_Fdata[43] + H +
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
  T := $D192E819 + Fptr_Fdata[44] + H +
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
  T := $D6990624 + Fptr_Fdata[45] + H +
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
  T := $F40E3585 + Fptr_Fdata[46] + H +
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
  T := $106AA070 + Fptr_Fdata[47] + H +
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
  T := $19A4C116 + Fptr_Fdata[48] + H +
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
  T := $1E376C08 + Fptr_Fdata[49] + H +
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
  T := $2748774C + Fptr_Fdata[50] + H +
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
  T := $34B0BCB5 + Fptr_Fdata[51] + H +
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
  T := $391C0CB3 + Fptr_Fdata[52] + H +
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
  T := $4ED8AA4A + Fptr_Fdata[53] + H +
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
  T := $5B9CCA4F + Fptr_Fdata[54] + H +
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
  T := $682E6FF3 + Fptr_Fdata[55] + H +
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
  T := $748F82EE + Fptr_Fdata[56] + H +
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
  T := $78A5636F + Fptr_Fdata[57] + H +
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
  T := $84C87814 + Fptr_Fdata[58] + H +
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
  T := $8CC70208 + Fptr_Fdata[59] + H +
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
  T := $90BEFFFA + Fptr_Fdata[60] + H +
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
  T := $A4506CEB + Fptr_Fdata[61] + H +
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
  T := $BEF9A3F7 + Fptr_Fdata[62] + H +
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
  T := $C67178F2 + Fptr_Fdata[63] + H +
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

  Fptr_Fm_state[0] := Fptr_Fm_state[0] + A;
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + B;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + C;
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + D;
  Fptr_Fm_state[4] := Fptr_Fm_state[4] + E;
  Fptr_Fm_state[5] := Fptr_Fm_state[5] + F;
  Fptr_Fm_state[6] := Fptr_Fm_state[6] + G;
  Fptr_Fm_state[7] := Fptr_Fm_state[7] + H;

end;

end.
