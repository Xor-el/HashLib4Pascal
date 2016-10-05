unit HlpSHA2_512Base;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashLibTypes,
  HlpBits,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  TSHA2_512Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

{$REGION 'Consts'}
  strict private
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
  strict protected
    Fm_state: THashLibUInt64Array;

    constructor Create(a_hash_size: Int32);

    procedure Finish(); override;
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;
  end;

implementation

{ TSHA2_512Base }

constructor TSHA2_512Base.Create(a_hash_size: Int32);
begin
  Inherited Create(a_hash_size, 128);
  System.SetLength(Fm_state, 8);
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

procedure TSHA2_512Base.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  data: THashLibUInt64Array;
  i, t: Int32;
  T0, T1, a, b, c, d, e, f, g, h: UInt64;
begin
  System.SetLength(data, 80);
  TConverters.ConvertBytesToUInt64SwapOrder(a_data, a_index, BlockSize, data);
  i := $10;
  while i <= 79 do
  begin
    T0 := data[i - 15];
    T1 := data[i - 2];
    data[i] := ((TBits.RotateLeft64(T1, 45)) xor (TBits.RotateLeft64(T1, 3))
      xor (T1 shr 6)) + data[i - 7] +
      ((TBits.RotateLeft64(T0, 63)) xor (TBits.RotateLeft64(T0, 56))
      xor (T0 shr 7)) + data[i - 16];
    System.Inc(i);
  end;

  a := Fm_state[0];
  b := Fm_state[1];
  c := Fm_state[2];
  d := Fm_state[3];
  e := Fm_state[4];
  f := Fm_state[5];
  g := Fm_state[6];
  h := Fm_state[7];

  i := 0;
  t := 0;

  while i < 10 do
  begin

    h := h + (s_K[t] + data[t] + ((TBits.RotateLeft64(e, 50))
      xor (TBits.RotateLeft64(e, 46)) xor (TBits.RotateLeft64(e, 23))) +
      ((e and f) xor (not e and g)));
    System.Inc(t);
    d := d + h;
    h := h + (((TBits.RotateLeft64(a, 36)) xor (TBits.RotateLeft64(a, 30))
      xor (TBits.RotateLeft64(a, 25))) + ((a and b) xor (a and c)
      xor (b and c)));

    g := g + (s_K[t] + data[t] + ((TBits.RotateLeft64(d, 50))
      xor (TBits.RotateLeft64(d, 46)) xor (TBits.RotateLeft64(d, 23))) +
      ((d and e) xor (not d and f)));
    System.Inc(t);
    c := c + g;
    g := g + (((TBits.RotateLeft64(h, 36)) xor (TBits.RotateLeft64(h, 30))
      xor (TBits.RotateLeft64(h, 25))) + ((h and a) xor (h and b)
      xor (a and b)));

    f := f + (s_K[t] + data[t] + ((TBits.RotateLeft64(c, 50))
      xor (TBits.RotateLeft64(c, 46)) xor (TBits.RotateLeft64(c, 23))) +
      ((c and d) xor (not c and e)));
    System.Inc(t);
    b := b + f;
    f := f + (((TBits.RotateLeft64(g, 36)) xor (TBits.RotateLeft64(g, 30))
      xor (TBits.RotateLeft64(g, 25))) + ((g and h) xor (g and a)
      xor (h and a)));

    e := e + (s_K[t] + data[t] + ((TBits.RotateLeft64(b, 50))
      xor (TBits.RotateLeft64(b, 46)) xor (TBits.RotateLeft64(b, 23))) +
      ((b and c) xor (not b and d)));
    System.Inc(t);
    a := a + e;
    e := e + (((TBits.RotateLeft64(f, 36)) xor (TBits.RotateLeft64(f, 30))
      xor (TBits.RotateLeft64(f, 25))) + ((f and g) xor (f and h)
      xor (g and h)));

    d := d + (s_K[t] + data[t] + ((TBits.RotateLeft64(a, 50))
      xor (TBits.RotateLeft64(a, 46)) xor (TBits.RotateLeft64(a, 23))) +
      ((a and b) xor (not a and c)));
    System.Inc(t);
    h := h + d;
    d := d + (((TBits.RotateLeft64(e, 36)) xor (TBits.RotateLeft64(e, 30))
      xor (TBits.RotateLeft64(e, 25))) + ((e and f) xor (e and g)
      xor (f and g)));

    c := c + (s_K[t] + data[t] + ((TBits.RotateLeft64(h, 50))
      xor (TBits.RotateLeft64(h, 46)) xor (TBits.RotateLeft64(h, 23))) +
      ((h and a) xor (not h and b)));
    System.Inc(t);
    g := g + c;
    c := c + (((TBits.RotateLeft64(d, 36)) xor (TBits.RotateLeft64(d, 30))
      xor (TBits.RotateLeft64(d, 25))) + ((d and e) xor (d and f)
      xor (e and f)));

    b := b + (s_K[t] + data[t] + ((TBits.RotateLeft64(g, 50))
      xor (TBits.RotateLeft64(g, 46)) xor (TBits.RotateLeft64(g, 23))) +
      ((g and h) xor (not g and a)));
    System.Inc(t);
    f := f + b;
    b := b + (((TBits.RotateLeft64(c, 36)) xor (TBits.RotateLeft64(c, 30))
      xor (TBits.RotateLeft64(c, 25))) + ((c and d) xor (c and e)
      xor (d and e)));

    a := a + (s_K[t] + data[t] + ((TBits.RotateLeft64(f, 50))
      xor (TBits.RotateLeft64(f, 46)) xor (TBits.RotateLeft64(f, 23))) +
      ((f and g) xor (not f and h)));
    System.Inc(t);
    e := e + a;
    a := a + (((TBits.RotateLeft64(b, 36)) xor (TBits.RotateLeft64(b, 30))
      xor (TBits.RotateLeft64(b, 25))) + ((b and c) xor (b and d)
      xor (c and d)));

    System.Inc(i);
  end;

  Fm_state[0] := Fm_state[0] + a;
  Fm_state[1] := Fm_state[1] + b;
  Fm_state[2] := Fm_state[2] + c;
  Fm_state[3] := Fm_state[3] + d;
  Fm_state[4] := Fm_state[4] + e;
  Fm_state[5] := Fm_state[5] + f;
  Fm_state[6] := Fm_state[6] + g;
  Fm_state[7] := Fm_state[7] + h;

end;

end.
