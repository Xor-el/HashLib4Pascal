unit HlpSHA2_512Base;

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
  TSHA2_512Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private
    Fptrdata: PUInt64;
    Fdata: THashLibUInt64Array;

    (*
      {$REGION 'Consts'}

      const

      s_K: array [0 .. 79] of UInt64 = ($428A2F98D728AE22, $7137449123EF65CD,
      $B5C0FBCFEC4D3B2F, $E9B5DBA58189DBBC, $3956C25BF348B538,
      $59F111F1B605D019, $923F82A4AF194F9B, $AB1C5ED5DA6D8118,
      $D807AA98A3030242, $12835B0145706FBE, $243185BE4EE4B28C,
      $550C7DC3D5FFB4E2, $72BE5D74F27B896F, $80DEB1FE3B1696B1,
      $9BDC06A725C71235, $C19BF174CF692694, $E49B69C19EF14AD2,
      $EFBE4786384F25E3, $0FC19DC68B8CD5B5, $240CA1CC77AC9C65,
      $2DE92C6F592B0275, $4A7484AA6EA6E483, $5CB0A9DCBD41FBD4,
      $76F988DA831153B5, $983E5152EE66DFAB, $A831C66D2DB43210,
      $B00327C898FB213F, $BF597FC7BEEF0EE4, $C6E00BF33DA88FC2,
      $D5A79147930AA725, $06CA6351E003826F, $142929670A0E6E70,
      $27B70A8546D22FFC, $2E1B21385C26C926, $4D2C6DFC5AC42AED,
      $53380D139D95B3DF, $650A73548BAF63DE, $766A0ABB3C77B2A8,
      $81C2C92E47EDAEE6, $92722C851482353B, $A2BFE8A14CF10364,
      $A81A664BBC423001, $C24B8B70D0F89791, $C76C51A30654BE30,
      $D192E819D6EF5218, $D69906245565A910, $F40E35855771202A,
      $106AA07032BBD1B8, $19A4C116B8D2D0C8, $1E376C085141AB53,
      $2748774CDF8EEB99, $34B0BCB5E19B48A8, $391C0CB3C5C95A63,
      $4ED8AA4AE3418ACB, $5B9CCA4F7763E373, $682E6FF3D6B2B8A3,
      $748F82EE5DEFB2FC, $78A5636F43172F60, $84C87814A1F0AB72,
      $8CC702081A6439EC, $90BEFFFA23631E28, $A4506CEBDE82BDE9,
      $BEF9A3F7B2C67915, $C67178F2E372532B, $CA273ECEEA26619C,
      $D186B8C721C0C207, $EADA7DD6CDE0EB1E, $F57D4F7FEE6ED178,
      $06F067AA72176FBA, $0A637DC5A2C898A6, $113F9804BEF90DAE,
      $1B710B35131C471B, $28DB77F523047D84, $32CAAB7B40C72493,
      $3C9EBE0A15C9BEBC, $431D67C49C100D4C, $4CC5D4BECB3E42B6,
      $597F299CFC657E2A, $5FCB6FAB3AD6FAEC, $6C44198C4A475817);

      {$ENDREGION}
    *)
  strict protected
    Fm_state: THashLibUInt64Array;
    Fptr_Fm_state: PUInt64;

    constructor Create(a_hash_size: Int32);

    procedure Finish(); override;
    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
      a_index: Int32); override;
  end;

implementation

{ TSHA2_512Base }

constructor TSHA2_512Base.Create(a_hash_size: Int32);
begin
  Inherited Create(a_hash_size, 128);
  System.SetLength(Fm_state, 8);
  Fptr_Fm_state := PUInt64(Fm_state);
  System.SetLength(Fdata, 80);
  Fptrdata := PUInt64(Fdata);
end;

procedure TSHA2_512Base.Finish;
var
  lowBits, hiBits: UInt64;
  padindex: Int32;
  pad: THashLibByteArray;
begin
  lowBits := Fm_processed_bytes shl 3;
  hiBits := Fm_processed_bytes shr 61;

  if (Fm_buffer.Pos < 112) then

    padindex := (111 - Fm_buffer.Pos)
  else
    padindex := (239 - Fm_buffer.Pos);

  System.Inc(padindex);
  System.SetLength(pad, padindex + 16);
  pad[0] := $80;

  TConverters.ConvertUInt64ToBytesSwapOrder(hiBits, pad, padindex);
  padindex := padindex + 8;

  TConverters.ConvertUInt64ToBytesSwapOrder(lowBits, pad, padindex);
  padindex := padindex + 8;

  TransformBytes(pad, 0, padindex);

end;

procedure TSHA2_512Base.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  // i, t: Int32;
  T0, T1, a, b, c, d, e, f, g, h: UInt64;
begin

  TConverters.ConvertBytesToUInt64SwapOrder(a_data, a_index, 128, Fptrdata);
  {
    for i := 16 to 79 do
    begin
    T0 := Fptrdata[i - 15];
    T1 := Fptrdata[i - 2];
    Fptrdata[i] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[i - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[i - 16];
    end;
  }

  T0 := Fptrdata[16 - 15];
  T1 := Fptrdata[16 - 2];
  Fptrdata[16] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[16 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[16 - 16];
  T0 := Fptrdata[17 - 15];
  T1 := Fptrdata[17 - 2];
  Fptrdata[17] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[17 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[17 - 16];
  T0 := Fptrdata[18 - 15];
  T1 := Fptrdata[18 - 2];
  Fptrdata[18] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[18 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[18 - 16];
  T0 := Fptrdata[19 - 15];
  T1 := Fptrdata[19 - 2];
  Fptrdata[19] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[19 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[19 - 16];
  T0 := Fptrdata[20 - 15];
  T1 := Fptrdata[20 - 2];
  Fptrdata[20] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[20 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[20 - 16];
  T0 := Fptrdata[21 - 15];
  T1 := Fptrdata[21 - 2];
  Fptrdata[21] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[21 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[21 - 16];
  T0 := Fptrdata[22 - 15];
  T1 := Fptrdata[22 - 2];
  Fptrdata[22] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[22 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[22 - 16];
  T0 := Fptrdata[23 - 15];
  T1 := Fptrdata[23 - 2];
  Fptrdata[23] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[23 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[23 - 16];
  T0 := Fptrdata[24 - 15];
  T1 := Fptrdata[24 - 2];
  Fptrdata[24] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[24 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[24 - 16];
  T0 := Fptrdata[25 - 15];
  T1 := Fptrdata[25 - 2];
  Fptrdata[25] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[25 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[25 - 16];
  T0 := Fptrdata[26 - 15];
  T1 := Fptrdata[26 - 2];
  Fptrdata[26] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[26 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[26 - 16];
  T0 := Fptrdata[27 - 15];
  T1 := Fptrdata[27 - 2];
  Fptrdata[27] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[27 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[27 - 16];
  T0 := Fptrdata[28 - 15];
  T1 := Fptrdata[28 - 2];
  Fptrdata[28] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[28 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[28 - 16];
  T0 := Fptrdata[29 - 15];
  T1 := Fptrdata[29 - 2];
  Fptrdata[29] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[29 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[29 - 16];
  T0 := Fptrdata[30 - 15];
  T1 := Fptrdata[30 - 2];
  Fptrdata[30] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[30 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[30 - 16];
  T0 := Fptrdata[31 - 15];
  T1 := Fptrdata[31 - 2];
  Fptrdata[31] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[31 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[31 - 16];
  T0 := Fptrdata[32 - 15];
  T1 := Fptrdata[32 - 2];
  Fptrdata[32] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[32 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[32 - 16];
  T0 := Fptrdata[33 - 15];
  T1 := Fptrdata[33 - 2];
  Fptrdata[33] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[33 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[33 - 16];
  T0 := Fptrdata[34 - 15];
  T1 := Fptrdata[34 - 2];
  Fptrdata[34] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[34 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[34 - 16];
  T0 := Fptrdata[35 - 15];
  T1 := Fptrdata[35 - 2];
  Fptrdata[35] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[35 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[35 - 16];
  T0 := Fptrdata[36 - 15];
  T1 := Fptrdata[36 - 2];
  Fptrdata[36] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[36 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[36 - 16];
  T0 := Fptrdata[37 - 15];
  T1 := Fptrdata[37 - 2];
  Fptrdata[37] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[37 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[37 - 16];
  T0 := Fptrdata[38 - 15];
  T1 := Fptrdata[38 - 2];
  Fptrdata[38] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[38 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[38 - 16];
  T0 := Fptrdata[39 - 15];
  T1 := Fptrdata[39 - 2];
  Fptrdata[39] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[39 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[39 - 16];
  T0 := Fptrdata[40 - 15];
  T1 := Fptrdata[40 - 2];
  Fptrdata[40] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[40 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[40 - 16];
  T0 := Fptrdata[41 - 15];
  T1 := Fptrdata[41 - 2];
  Fptrdata[41] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[41 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[41 - 16];
  T0 := Fptrdata[42 - 15];
  T1 := Fptrdata[42 - 2];
  Fptrdata[42] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[42 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[42 - 16];
  T0 := Fptrdata[43 - 15];
  T1 := Fptrdata[43 - 2];
  Fptrdata[43] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[43 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[43 - 16];
  T0 := Fptrdata[44 - 15];
  T1 := Fptrdata[44 - 2];
  Fptrdata[44] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[44 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[44 - 16];
  T0 := Fptrdata[45 - 15];
  T1 := Fptrdata[45 - 2];
  Fptrdata[45] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[45 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[45 - 16];
  T0 := Fptrdata[46 - 15];
  T1 := Fptrdata[46 - 2];
  Fptrdata[46] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[46 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[46 - 16];
  T0 := Fptrdata[47 - 15];
  T1 := Fptrdata[47 - 2];
  Fptrdata[47] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[47 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[47 - 16];
  T0 := Fptrdata[48 - 15];
  T1 := Fptrdata[48 - 2];
  Fptrdata[48] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[48 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[48 - 16];
  T0 := Fptrdata[49 - 15];
  T1 := Fptrdata[49 - 2];
  Fptrdata[49] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[49 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[49 - 16];
  T0 := Fptrdata[50 - 15];
  T1 := Fptrdata[50 - 2];
  Fptrdata[50] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[50 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[50 - 16];
  T0 := Fptrdata[51 - 15];
  T1 := Fptrdata[51 - 2];
  Fptrdata[51] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[51 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[51 - 16];
  T0 := Fptrdata[52 - 15];
  T1 := Fptrdata[52 - 2];
  Fptrdata[52] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[52 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[52 - 16];
  T0 := Fptrdata[53 - 15];
  T1 := Fptrdata[53 - 2];
  Fptrdata[53] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[53 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[53 - 16];
  T0 := Fptrdata[54 - 15];
  T1 := Fptrdata[54 - 2];
  Fptrdata[54] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[54 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[54 - 16];
  T0 := Fptrdata[55 - 15];
  T1 := Fptrdata[55 - 2];
  Fptrdata[55] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[55 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[55 - 16];
  T0 := Fptrdata[56 - 15];
  T1 := Fptrdata[56 - 2];
  Fptrdata[56] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[56 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[56 - 16];
  T0 := Fptrdata[57 - 15];
  T1 := Fptrdata[57 - 2];
  Fptrdata[57] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[57 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[57 - 16];
  T0 := Fptrdata[58 - 15];
  T1 := Fptrdata[58 - 2];
  Fptrdata[58] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[58 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[58 - 16];
  T0 := Fptrdata[59 - 15];
  T1 := Fptrdata[59 - 2];
  Fptrdata[59] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[59 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[59 - 16];
  T0 := Fptrdata[60 - 15];
  T1 := Fptrdata[60 - 2];
  Fptrdata[60] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[60 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[60 - 16];
  T0 := Fptrdata[61 - 15];
  T1 := Fptrdata[61 - 2];
  Fptrdata[61] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[61 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[61 - 16];
  T0 := Fptrdata[62 - 15];
  T1 := Fptrdata[62 - 2];
  Fptrdata[62] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[62 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[62 - 16];
  T0 := Fptrdata[63 - 15];
  T1 := Fptrdata[63 - 2];
  Fptrdata[63] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[63 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[63 - 16];
  T0 := Fptrdata[64 - 15];
  T1 := Fptrdata[64 - 2];
  Fptrdata[64] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[64 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[64 - 16];
  T0 := Fptrdata[65 - 15];
  T1 := Fptrdata[65 - 2];
  Fptrdata[65] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[65 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[65 - 16];
  T0 := Fptrdata[66 - 15];
  T1 := Fptrdata[66 - 2];
  Fptrdata[66] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[66 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[66 - 16];
  T0 := Fptrdata[67 - 15];
  T1 := Fptrdata[67 - 2];
  Fptrdata[67] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[67 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[67 - 16];
  T0 := Fptrdata[68 - 15];
  T1 := Fptrdata[68 - 2];
  Fptrdata[68] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[68 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[68 - 16];
  T0 := Fptrdata[69 - 15];
  T1 := Fptrdata[69 - 2];
  Fptrdata[69] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[69 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[69 - 16];
  T0 := Fptrdata[70 - 15];
  T1 := Fptrdata[70 - 2];
  Fptrdata[70] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[70 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[70 - 16];
  T0 := Fptrdata[71 - 15];
  T1 := Fptrdata[71 - 2];
  Fptrdata[71] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[71 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[71 - 16];
  T0 := Fptrdata[72 - 15];
  T1 := Fptrdata[72 - 2];
  Fptrdata[72] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[72 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[72 - 16];
  T0 := Fptrdata[73 - 15];
  T1 := Fptrdata[73 - 2];
  Fptrdata[73] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[73 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[73 - 16];
  T0 := Fptrdata[74 - 15];
  T1 := Fptrdata[74 - 2];
  Fptrdata[74] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[74 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[74 - 16];
  T0 := Fptrdata[75 - 15];
  T1 := Fptrdata[75 - 2];
  Fptrdata[75] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[75 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[75 - 16];
  T0 := Fptrdata[76 - 15];
  T1 := Fptrdata[76 - 2];
  Fptrdata[76] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[76 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[76 - 16];
  T0 := Fptrdata[77 - 15];
  T1 := Fptrdata[77 - 2];
  Fptrdata[77] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[77 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[77 - 16];
  T0 := Fptrdata[78 - 15];
  T1 := Fptrdata[78 - 2];
  Fptrdata[78] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[78 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[78 - 16];
  T0 := Fptrdata[79 - 15];
  T1 := Fptrdata[79 - 2];
  Fptrdata[79] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + Fptrdata[79 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + Fptrdata[79 - 16];

  a := Fptr_Fm_state[0];
  b := Fptr_Fm_state[1];
  c := Fptr_Fm_state[2];
  d := Fptr_Fm_state[3];
  e := Fptr_Fm_state[4];
  f := Fptr_Fm_state[5];
  g := Fptr_Fm_state[6];
  h := Fptr_Fm_state[7];

  // t := 0;
  // i := 0;

  {
    while i <= 9 do

    begin

    h := h + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));
    System.Inc(t);
    d := d + h;
    h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c)
    xor (b and c)));

    g := g + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));
    System.Inc(t);
    c := c + g;
    g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b)
    xor (a and b)));

    f := f + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));
    System.Inc(t);
    b := b + f;
    f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a)
    xor (h and a)));

    e := e + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));
    System.Inc(t);
    a := a + e;
    e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h)
    xor (g and h)));

    d := d + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));
    System.Inc(t);
    h := h + d;
    d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g)
    xor (f and g)));

    c := c + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));
    System.Inc(t);
    g := g + c;
    c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f)
    xor (e and f)));

    b := b + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));
    System.Inc(t);
    f := f + b;
    b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e)
    xor (d and e)));

    a := a + (s_K[t] + Fptrdata[t] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));
    System.Inc(t);
    e := e + a;
    a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d)
    xor (c and d)));

    System.Inc(i);
    end;
  }

  // R0
  h := h + ($428A2F98D728AE22 + Fptrdata[0] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($7137449123EF65CD + Fptrdata[1] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($B5C0FBCFEC4D3B2F + Fptrdata[2] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($E9B5DBA58189DBBC + Fptrdata[3] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($3956C25BF348B538 + Fptrdata[4] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($59F111F1B605D019 + Fptrdata[5] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($923F82A4AF194F9B + Fptrdata[6] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($AB1C5ED5DA6D8118 + Fptrdata[7] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R1
  h := h + ($D807AA98A3030242 + Fptrdata[8] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($12835B0145706FBE + Fptrdata[9] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($243185BE4EE4B28C + Fptrdata[10] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($550C7DC3D5FFB4E2 + Fptrdata[11] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($72BE5D74F27B896F + Fptrdata[12] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($80DEB1FE3B1696B1 + Fptrdata[13] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($9BDC06A725C71235 + Fptrdata[14] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($C19BF174CF692694 + Fptrdata[15] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R2

  h := h + ($E49B69C19EF14AD2 + Fptrdata[16] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($EFBE4786384F25E3 + Fptrdata[17] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($0FC19DC68B8CD5B5 + Fptrdata[18] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($240CA1CC77AC9C65 + Fptrdata[19] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($2DE92C6F592B0275 + Fptrdata[20] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($4A7484AA6EA6E483 + Fptrdata[21] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5CB0A9DCBD41FBD4 + Fptrdata[22] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($76F988DA831153B5 + Fptrdata[23] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R3

  h := h + ($983E5152EE66DFAB + Fptrdata[24] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($A831C66D2DB43210 + Fptrdata[25] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($B00327C898FB213F + Fptrdata[26] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($BF597FC7BEEF0EE4 + Fptrdata[27] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($C6E00BF33DA88FC2 + Fptrdata[28] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($D5A79147930AA725 + Fptrdata[29] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($06CA6351E003826F + Fptrdata[30] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($142929670A0E6E70 + Fptrdata[31] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R4

  h := h + ($27B70A8546D22FFC + Fptrdata[32] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($2E1B21385C26C926 + Fptrdata[33] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($4D2C6DFC5AC42AED + Fptrdata[34] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($53380D139D95B3DF + Fptrdata[35] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($650A73548BAF63DE + Fptrdata[36] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($766A0ABB3C77B2A8 + Fptrdata[37] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($81C2C92E47EDAEE6 + Fptrdata[38] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($92722C851482353B + Fptrdata[39] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R5

  h := h + ($A2BFE8A14CF10364 + Fptrdata[40] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($A81A664BBC423001 + Fptrdata[41] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($C24B8B70D0F89791 + Fptrdata[42] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($C76C51A30654BE30 + Fptrdata[43] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($D192E819D6EF5218 + Fptrdata[44] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($D69906245565A910 + Fptrdata[45] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($F40E35855771202A + Fptrdata[46] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($106AA07032BBD1B8 + Fptrdata[47] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R6

  h := h + ($19A4C116B8D2D0C8 + Fptrdata[48] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($1E376C085141AB53 + Fptrdata[49] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($2748774CDF8EEB99 + Fptrdata[50] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($34B0BCB5E19B48A8 + Fptrdata[51] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($391C0CB3C5C95A63 + Fptrdata[52] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($4ED8AA4AE3418ACB + Fptrdata[53] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5B9CCA4F7763E373 + Fptrdata[54] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($682E6FF3D6B2B8A3 + Fptrdata[55] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R7

  h := h + ($748F82EE5DEFB2FC + Fptrdata[56] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($78A5636F43172F60 + Fptrdata[57] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($84C87814A1F0AB72 + Fptrdata[58] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($8CC702081A6439EC + Fptrdata[59] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($90BEFFFA23631E28 + Fptrdata[60] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($A4506CEBDE82BDE9 + Fptrdata[61] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($BEF9A3F7B2C67915 + Fptrdata[62] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($C67178F2E372532B + Fptrdata[63] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R8

  h := h + ($CA273ECEEA26619C + Fptrdata[64] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($D186B8C721C0C207 + Fptrdata[65] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($EADA7DD6CDE0EB1E + Fptrdata[66] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($F57D4F7FEE6ED178 + Fptrdata[67] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($06F067AA72176FBA + Fptrdata[68] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($0A637DC5A2C898A6 + Fptrdata[69] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($113F9804BEF90DAE + Fptrdata[70] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($1B710B35131C471B + Fptrdata[71] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R9

  h := h + ($28DB77F523047D84 + Fptrdata[72] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($32CAAB7B40C72493 + Fptrdata[73] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($3C9EBE0A15C9BEBC + Fptrdata[74] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($431D67C49C100D4C + Fptrdata[75] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($4CC5D4BECB3E42B6 + Fptrdata[76] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($597F299CFC657E2A + Fptrdata[77] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5FCB6FAB3AD6FAEC + Fptrdata[78] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($6C44198C4A475817 + Fptrdata[79] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  Fptr_Fm_state[0] := Fptr_Fm_state[0] + a;
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + b;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + c;
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + d;
  Fptr_Fm_state[4] := Fptr_Fm_state[4] + e;
  Fptr_Fm_state[5] := Fptr_Fm_state[5] + f;
  Fptr_Fm_state[6] := Fptr_Fm_state[6] + g;
  Fptr_Fm_state[7] := Fptr_Fm_state[7] + h;

end;

end.
