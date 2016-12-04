unit HlpSHA2_512Base;

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
  TSHA2_512Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$IFNDEF USE_UNROLLED_VARIANT}
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
{$ENDIF USE_UNROLLED_VARIANT}
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

  hiBits := TConverters.be2me_64(hiBits);

  TConverters.ReadUInt64AsBytesLE(hiBits, pad, padindex);

  padindex := padindex + 8;

  lowBits := TConverters.be2me_64(lowBits);

  TConverters.ReadUInt64AsBytesLE(lowBits, pad, padindex);

  padindex := padindex + 8;

  TransformBytes(pad, 0, padindex);

end;

procedure TSHA2_512Base.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
{$IFNDEF USE_UNROLLED_VARIANT}
  i, t: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
  T0, T1, a, b, c, d, e, f, g, h: UInt64;
  data: array [0 .. 79] of UInt64;
  ptr_data: PUInt64;
begin

  ptr_data := @(data[0]);

  TConverters.be64_copy(a_data, a_index, ptr_data, 0, 128);

  // Step 1

{$IFDEF USE_UNROLLED_VARIANT}
  T0 := ptr_data[16 - 15];
  T1 := ptr_data[16 - 2];
  ptr_data[16] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[16 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[16 - 16];
  T0 := ptr_data[17 - 15];
  T1 := ptr_data[17 - 2];
  ptr_data[17] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[17 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[17 - 16];
  T0 := ptr_data[18 - 15];
  T1 := ptr_data[18 - 2];
  ptr_data[18] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[18 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[18 - 16];
  T0 := ptr_data[19 - 15];
  T1 := ptr_data[19 - 2];
  ptr_data[19] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[19 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[19 - 16];
  T0 := ptr_data[20 - 15];
  T1 := ptr_data[20 - 2];
  ptr_data[20] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[20 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[20 - 16];
  T0 := ptr_data[21 - 15];
  T1 := ptr_data[21 - 2];
  ptr_data[21] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[21 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[21 - 16];
  T0 := ptr_data[22 - 15];
  T1 := ptr_data[22 - 2];
  ptr_data[22] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[22 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[22 - 16];
  T0 := ptr_data[23 - 15];
  T1 := ptr_data[23 - 2];
  ptr_data[23] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[23 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[23 - 16];
  T0 := ptr_data[24 - 15];
  T1 := ptr_data[24 - 2];
  ptr_data[24] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[24 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[24 - 16];
  T0 := ptr_data[25 - 15];
  T1 := ptr_data[25 - 2];
  ptr_data[25] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[25 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[25 - 16];
  T0 := ptr_data[26 - 15];
  T1 := ptr_data[26 - 2];
  ptr_data[26] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[26 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[26 - 16];
  T0 := ptr_data[27 - 15];
  T1 := ptr_data[27 - 2];
  ptr_data[27] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[27 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[27 - 16];
  T0 := ptr_data[28 - 15];
  T1 := ptr_data[28 - 2];
  ptr_data[28] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[28 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[28 - 16];
  T0 := ptr_data[29 - 15];
  T1 := ptr_data[29 - 2];
  ptr_data[29] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[29 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[29 - 16];
  T0 := ptr_data[30 - 15];
  T1 := ptr_data[30 - 2];
  ptr_data[30] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[30 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[30 - 16];
  T0 := ptr_data[31 - 15];
  T1 := ptr_data[31 - 2];
  ptr_data[31] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[31 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[31 - 16];
  T0 := ptr_data[32 - 15];
  T1 := ptr_data[32 - 2];
  ptr_data[32] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[32 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[32 - 16];
  T0 := ptr_data[33 - 15];
  T1 := ptr_data[33 - 2];
  ptr_data[33] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[33 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[33 - 16];
  T0 := ptr_data[34 - 15];
  T1 := ptr_data[34 - 2];
  ptr_data[34] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[34 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[34 - 16];
  T0 := ptr_data[35 - 15];
  T1 := ptr_data[35 - 2];
  ptr_data[35] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[35 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[35 - 16];
  T0 := ptr_data[36 - 15];
  T1 := ptr_data[36 - 2];
  ptr_data[36] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[36 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[36 - 16];
  T0 := ptr_data[37 - 15];
  T1 := ptr_data[37 - 2];
  ptr_data[37] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[37 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[37 - 16];
  T0 := ptr_data[38 - 15];
  T1 := ptr_data[38 - 2];
  ptr_data[38] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[38 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[38 - 16];
  T0 := ptr_data[39 - 15];
  T1 := ptr_data[39 - 2];
  ptr_data[39] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[39 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[39 - 16];
  T0 := ptr_data[40 - 15];
  T1 := ptr_data[40 - 2];
  ptr_data[40] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[40 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[40 - 16];
  T0 := ptr_data[41 - 15];
  T1 := ptr_data[41 - 2];
  ptr_data[41] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[41 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[41 - 16];
  T0 := ptr_data[42 - 15];
  T1 := ptr_data[42 - 2];
  ptr_data[42] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[42 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[42 - 16];
  T0 := ptr_data[43 - 15];
  T1 := ptr_data[43 - 2];
  ptr_data[43] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[43 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[43 - 16];
  T0 := ptr_data[44 - 15];
  T1 := ptr_data[44 - 2];
  ptr_data[44] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[44 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[44 - 16];
  T0 := ptr_data[45 - 15];
  T1 := ptr_data[45 - 2];
  ptr_data[45] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[45 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[45 - 16];
  T0 := ptr_data[46 - 15];
  T1 := ptr_data[46 - 2];
  ptr_data[46] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[46 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[46 - 16];
  T0 := ptr_data[47 - 15];
  T1 := ptr_data[47 - 2];
  ptr_data[47] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[47 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[47 - 16];
  T0 := ptr_data[48 - 15];
  T1 := ptr_data[48 - 2];
  ptr_data[48] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[48 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[48 - 16];
  T0 := ptr_data[49 - 15];
  T1 := ptr_data[49 - 2];
  ptr_data[49] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[49 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[49 - 16];
  T0 := ptr_data[50 - 15];
  T1 := ptr_data[50 - 2];
  ptr_data[50] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[50 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[50 - 16];
  T0 := ptr_data[51 - 15];
  T1 := ptr_data[51 - 2];
  ptr_data[51] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[51 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[51 - 16];
  T0 := ptr_data[52 - 15];
  T1 := ptr_data[52 - 2];
  ptr_data[52] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[52 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[52 - 16];
  T0 := ptr_data[53 - 15];
  T1 := ptr_data[53 - 2];
  ptr_data[53] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[53 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[53 - 16];
  T0 := ptr_data[54 - 15];
  T1 := ptr_data[54 - 2];
  ptr_data[54] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[54 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[54 - 16];
  T0 := ptr_data[55 - 15];
  T1 := ptr_data[55 - 2];
  ptr_data[55] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[55 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[55 - 16];
  T0 := ptr_data[56 - 15];
  T1 := ptr_data[56 - 2];
  ptr_data[56] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[56 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[56 - 16];
  T0 := ptr_data[57 - 15];
  T1 := ptr_data[57 - 2];
  ptr_data[57] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[57 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[57 - 16];
  T0 := ptr_data[58 - 15];
  T1 := ptr_data[58 - 2];
  ptr_data[58] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[58 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[58 - 16];
  T0 := ptr_data[59 - 15];
  T1 := ptr_data[59 - 2];
  ptr_data[59] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[59 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[59 - 16];
  T0 := ptr_data[60 - 15];
  T1 := ptr_data[60 - 2];
  ptr_data[60] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[60 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[60 - 16];
  T0 := ptr_data[61 - 15];
  T1 := ptr_data[61 - 2];
  ptr_data[61] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[61 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[61 - 16];
  T0 := ptr_data[62 - 15];
  T1 := ptr_data[62 - 2];
  ptr_data[62] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[62 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[62 - 16];
  T0 := ptr_data[63 - 15];
  T1 := ptr_data[63 - 2];
  ptr_data[63] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[63 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[63 - 16];
  T0 := ptr_data[64 - 15];
  T1 := ptr_data[64 - 2];
  ptr_data[64] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[64 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[64 - 16];
  T0 := ptr_data[65 - 15];
  T1 := ptr_data[65 - 2];
  ptr_data[65] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[65 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[65 - 16];
  T0 := ptr_data[66 - 15];
  T1 := ptr_data[66 - 2];
  ptr_data[66] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[66 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[66 - 16];
  T0 := ptr_data[67 - 15];
  T1 := ptr_data[67 - 2];
  ptr_data[67] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[67 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[67 - 16];
  T0 := ptr_data[68 - 15];
  T1 := ptr_data[68 - 2];
  ptr_data[68] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[68 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[68 - 16];
  T0 := ptr_data[69 - 15];
  T1 := ptr_data[69 - 2];
  ptr_data[69] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[69 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[69 - 16];
  T0 := ptr_data[70 - 15];
  T1 := ptr_data[70 - 2];
  ptr_data[70] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[70 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[70 - 16];
  T0 := ptr_data[71 - 15];
  T1 := ptr_data[71 - 2];
  ptr_data[71] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[71 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[71 - 16];
  T0 := ptr_data[72 - 15];
  T1 := ptr_data[72 - 2];
  ptr_data[72] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[72 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[72 - 16];
  T0 := ptr_data[73 - 15];
  T1 := ptr_data[73 - 2];
  ptr_data[73] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[73 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[73 - 16];
  T0 := ptr_data[74 - 15];
  T1 := ptr_data[74 - 2];
  ptr_data[74] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[74 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[74 - 16];
  T0 := ptr_data[75 - 15];
  T1 := ptr_data[75 - 2];
  ptr_data[75] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[75 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[75 - 16];
  T0 := ptr_data[76 - 15];
  T1 := ptr_data[76 - 2];
  ptr_data[76] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[76 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[76 - 16];
  T0 := ptr_data[77 - 15];
  T1 := ptr_data[77 - 2];
  ptr_data[77] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[77 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[77 - 16];
  T0 := ptr_data[78 - 15];
  T1 := ptr_data[78 - 2];
  ptr_data[78] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[78 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[78 - 16];
  T0 := ptr_data[79 - 15];
  T1 := ptr_data[79 - 2];
  ptr_data[79] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
    xor (T1 shr 6)) + ptr_data[79 - 7] +
    ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
    xor (T0 shr 7)) + ptr_data[79 - 16];

  a := Fptr_Fm_state[0];
  b := Fptr_Fm_state[1];
  c := Fptr_Fm_state[2];
  d := Fptr_Fm_state[3];
  e := Fptr_Fm_state[4];
  f := Fptr_Fm_state[5];
  g := Fptr_Fm_state[6];
  h := Fptr_Fm_state[7];

  // Step 2

  // R0
  h := h + ($428A2F98D728AE22 + ptr_data[0] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($7137449123EF65CD + ptr_data[1] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($B5C0FBCFEC4D3B2F + ptr_data[2] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($E9B5DBA58189DBBC + ptr_data[3] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($3956C25BF348B538 + ptr_data[4] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($59F111F1B605D019 + ptr_data[5] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($923F82A4AF194F9B + ptr_data[6] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($AB1C5ED5DA6D8118 + ptr_data[7] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R1
  h := h + ($D807AA98A3030242 + ptr_data[8] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($12835B0145706FBE + ptr_data[9] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($243185BE4EE4B28C + ptr_data[10] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($550C7DC3D5FFB4E2 + ptr_data[11] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($72BE5D74F27B896F + ptr_data[12] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($80DEB1FE3B1696B1 + ptr_data[13] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($9BDC06A725C71235 + ptr_data[14] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($C19BF174CF692694 + ptr_data[15] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R2

  h := h + ($E49B69C19EF14AD2 + ptr_data[16] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($EFBE4786384F25E3 + ptr_data[17] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($0FC19DC68B8CD5B5 + ptr_data[18] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($240CA1CC77AC9C65 + ptr_data[19] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($2DE92C6F592B0275 + ptr_data[20] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($4A7484AA6EA6E483 + ptr_data[21] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5CB0A9DCBD41FBD4 + ptr_data[22] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($76F988DA831153B5 + ptr_data[23] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R3

  h := h + ($983E5152EE66DFAB + ptr_data[24] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($A831C66D2DB43210 + ptr_data[25] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($B00327C898FB213F + ptr_data[26] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($BF597FC7BEEF0EE4 + ptr_data[27] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($C6E00BF33DA88FC2 + ptr_data[28] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($D5A79147930AA725 + ptr_data[29] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($06CA6351E003826F + ptr_data[30] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($142929670A0E6E70 + ptr_data[31] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R4

  h := h + ($27B70A8546D22FFC + ptr_data[32] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($2E1B21385C26C926 + ptr_data[33] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($4D2C6DFC5AC42AED + ptr_data[34] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($53380D139D95B3DF + ptr_data[35] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($650A73548BAF63DE + ptr_data[36] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($766A0ABB3C77B2A8 + ptr_data[37] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($81C2C92E47EDAEE6 + ptr_data[38] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($92722C851482353B + ptr_data[39] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R5

  h := h + ($A2BFE8A14CF10364 + ptr_data[40] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($A81A664BBC423001 + ptr_data[41] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($C24B8B70D0F89791 + ptr_data[42] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($C76C51A30654BE30 + ptr_data[43] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($D192E819D6EF5218 + ptr_data[44] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($D69906245565A910 + ptr_data[45] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($F40E35855771202A + ptr_data[46] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($106AA07032BBD1B8 + ptr_data[47] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R6

  h := h + ($19A4C116B8D2D0C8 + ptr_data[48] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($1E376C085141AB53 + ptr_data[49] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($2748774CDF8EEB99 + ptr_data[50] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($34B0BCB5E19B48A8 + ptr_data[51] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($391C0CB3C5C95A63 + ptr_data[52] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($4ED8AA4AE3418ACB + ptr_data[53] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5B9CCA4F7763E373 + ptr_data[54] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($682E6FF3D6B2B8A3 + ptr_data[55] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R7

  h := h + ($748F82EE5DEFB2FC + ptr_data[56] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($78A5636F43172F60 + ptr_data[57] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($84C87814A1F0AB72 + ptr_data[58] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($8CC702081A6439EC + ptr_data[59] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($90BEFFFA23631E28 + ptr_data[60] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($A4506CEBDE82BDE9 + ptr_data[61] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($BEF9A3F7B2C67915 + ptr_data[62] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($C67178F2E372532B + ptr_data[63] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R8

  h := h + ($CA273ECEEA26619C + ptr_data[64] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($D186B8C721C0C207 + ptr_data[65] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($EADA7DD6CDE0EB1E + ptr_data[66] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($F57D4F7FEE6ED178 + ptr_data[67] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($06F067AA72176FBA + ptr_data[68] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($0A637DC5A2C898A6 + ptr_data[69] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($113F9804BEF90DAE + ptr_data[70] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($1B710B35131C471B + ptr_data[71] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

  // R9

  h := h + ($28DB77F523047D84 + ptr_data[72] + ((TBits.RotateLeft64(e, 50))
    xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
    ((e and f) xor (not e and g)));

  d := d + h;
  h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
    xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c) xor (b and c)));

  g := g + ($32CAAB7B40C72493 + ptr_data[73] + ((TBits.RotateLeft64(d, 50))
    xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
    ((d and e) xor (not d and f)));

  c := c + g;
  g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
    xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b) xor (a and b)));

  f := f + ($3C9EBE0A15C9BEBC + ptr_data[74] + ((TBits.RotateLeft64(c, 50))
    xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
    ((c and d) xor (not c and e)));

  b := b + f;
  f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
    xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a) xor (h and a)));

  e := e + ($431D67C49C100D4C + ptr_data[75] + ((TBits.RotateLeft64(b, 50))
    xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
    ((b and c) xor (not b and d)));

  a := a + e;
  e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
    xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h) xor (g and h)));

  d := d + ($4CC5D4BECB3E42B6 + ptr_data[76] + ((TBits.RotateLeft64(a, 50))
    xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
    ((a and b) xor (not a and c)));

  h := h + d;
  d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
    xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g) xor (f and g)));

  c := c + ($597F299CFC657E2A + ptr_data[77] + ((TBits.RotateLeft64(h, 50))
    xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
    ((h and a) xor (not h and b)));

  g := g + c;
  c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
    xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f) xor (e and f)));

  b := b + ($5FCB6FAB3AD6FAEC + ptr_data[78] + ((TBits.RotateLeft64(g, 50))
    xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
    ((g and h) xor (not g and a)));

  f := f + b;
  b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
    xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e) xor (d and e)));

  a := a + ($6C44198C4A475817 + ptr_data[79] + ((TBits.RotateLeft64(f, 50))
    xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
    ((f and g) xor (not f and h)));

  e := e + a;
  a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
    xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d) xor (c and d)));

{$ELSE}
  a := Fptr_Fm_state[0];
  b := Fptr_Fm_state[1];
  c := Fptr_Fm_state[2];
  d := Fptr_Fm_state[3];
  e := Fptr_Fm_state[4];
  f := Fptr_Fm_state[5];
  g := Fptr_Fm_state[6];
  h := Fptr_Fm_state[7];

  // Step 1

  for i := 16 to 79 do
  begin
    T0 := ptr_data[i - 15];
    T1 := ptr_data[i - 2];
    ptr_data[i] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
      xor (T1 shr 6)) + ptr_data[i - 7] +
      ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
      xor (T0 shr 7)) + ptr_data[i - 16];
  end;


  // Step 2

  t := 0;
  i := 0;

  while i <= 9 do

  begin

    h := h + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(e, 50))
      xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
      ((e and f) xor (not e and g)));
    System.Inc(t);
    d := d + h;
    h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
      xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c)
      xor (b and c)));

    g := g + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(d, 50))
      xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
      ((d and e) xor (not d and f)));
    System.Inc(t);
    c := c + g;
    g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
      xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b)
      xor (a and b)));

    f := f + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(c, 50))
      xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
      ((c and d) xor (not c and e)));
    System.Inc(t);
    b := b + f;
    f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
      xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a)
      xor (h and a)));

    e := e + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(b, 50))
      xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
      ((b and c) xor (not b and d)));
    System.Inc(t);
    a := a + e;
    e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
      xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h)
      xor (g and h)));

    d := d + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(a, 50))
      xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
      ((a and b) xor (not a and c)));
    System.Inc(t);
    h := h + d;
    d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
      xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g)
      xor (f and g)));

    c := c + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(h, 50))
      xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
      ((h and a) xor (not h and b)));
    System.Inc(t);
    g := g + c;
    c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
      xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f)
      xor (e and f)));

    b := b + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(g, 50))
      xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
      ((g and h) xor (not g and a)));
    System.Inc(t);
    f := f + b;
    b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
      xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e)
      xor (d and e)));

    a := a + (s_K[t] + ptr_data[t] + ((TBits.RotateLeft64(f, 50))
      xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
      ((f and g) xor (not f and h)));
    System.Inc(t);
    e := e + a;
    a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
      xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d)
      xor (c and d)));

    System.Inc(i);
  end;

{$ENDIF USE_UNROLLED_VARIANT}
  Fptr_Fm_state[0] := Fptr_Fm_state[0] + a;
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + b;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + c;
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + d;
  Fptr_Fm_state[4] := Fptr_Fm_state[4] + e;
  Fptr_Fm_state[5] := Fptr_Fm_state[5] + f;
  Fptr_Fm_state[6] := Fptr_Fm_state[6] + g;
  Fptr_Fm_state[7] := Fptr_Fm_state[7] + h;

  System.FillChar(data, System.SizeOf(data), 0);

end;

end.
