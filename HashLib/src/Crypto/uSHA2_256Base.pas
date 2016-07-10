unit uSHA2_256Base;

interface

uses
  uHashLibTypes,
  uConverters,
  uIHashInfo,
  uHashCryptoNotBuildIn;

type
  TSHA2_256Base = class(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$REGION 'Consts'}
  strict private
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
{$WARNINGS OFF}
  strict protected
    Fm_state: THashLibUInt32Array;

    constructor Create(a_hash_size: Int32);
    {$WARNINGS ON}
    procedure Finish(); override;
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  end;

implementation

{ TSHA2_256Base }

constructor TSHA2_256Base.Create(a_hash_size: Int32);
begin
  Inherited Create(a_hash_size, 64);
  System.SetLength(Fm_state, 8);
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

procedure TSHA2_256Base.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  A, B, C, D, E, F, G, H, T, T2: UInt32;
  data: THashLibUInt32Array;
  r: Int32;
begin
  System.SetLength(data, 64);
  TConverters.ConvertBytesToUInt32SwapOrder(a_data, a_index, BlockSize,
    data, 0);

  A := Fm_state[0];
  B := Fm_state[1];
  C := Fm_state[2];
  D := Fm_state[3];
  E := Fm_state[4];
  F := Fm_state[5];
  G := Fm_state[6];
  H := Fm_state[7];

  r := 16;

  while r < 64 do
  begin
    T := data[r - 2];
    T2 := data[r - 15];
    data[r] := (((T shr 17) or (T shl 15)) xor ((T shr 19) or (T shl 13))
      xor (T shr 10)) + data[r - 7] +
      (((T2 shr 7) or (T2 shl 25)) xor ((T2 shr 18) or (T2 shl 14))
      xor (T2 shr 3)) + data[r - 16];
    System.Inc(r);
  end;

  r := 0;

  while r < 64 do
  begin

    T := s_K[r] + data[r] + H +
      (((E shr 6) or (E shl 26)) xor ((E shr 11) or (E shl 21))
      xor ((E shr 25) or (E shl 7))) + ((E and F) xor (not E and G));
    T2 := (((A shr 2) or (A shl 30)) xor ((A shr 13) or (A shl 19))
      xor ((A shr 22) or (A shl 10))) + ((A and B) xor (A and C) xor (B and C));

    H := G;
    G := F;
    F := E;
    E := D + T;
    D := C;
    C := B;
    B := A;
    A := T + T2;
    System.Inc(r);
  end;

  Fm_state[0] := Fm_state[0] + A;
  Fm_state[1] := Fm_state[1] + B;
  Fm_state[2] := Fm_state[2] + C;
  Fm_state[3] := Fm_state[3] + D;
  Fm_state[4] := Fm_state[4] + E;
  Fm_state[5] := Fm_state[5] + F;
  Fm_state[6] := Fm_state[6] + G;
  Fm_state[7] := Fm_state[7] + H;

end;

end.
