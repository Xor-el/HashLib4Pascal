unit HlpRIPEMD256;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashLibTypes,
  HlpMDBase,
{$IFDEF DELPHI}
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpBits,
  HlpConverters,
  HlpIHashInfo;

type
  TRIPEMD256 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TRIPEMD256 }

constructor TRIPEMD256.Create;
begin
  Inherited Create(8, 32);
end;

procedure TRIPEMD256.Initialize;
begin
  Fm_state[4] := $76543210;
  Fm_state[5] := $FEDCBA98;
  Fm_state[6] := $89ABCDEF;
  Fm_state[7] := $01234567;

  Inherited Initialize();

end;

procedure TRIPEMD256.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  data0, data1, data2, data3, data4, data5, data6, data7, data8, data9, data10,
    data11, data12, data13, data14, data15, a, b, c, d, aa, bb, cc, dd: UInt32;
begin
  data0 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 0);
  data1 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 1);
  data2 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 2);
  data3 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 3);
  data4 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 4);
  data5 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 5);
  data6 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 6);
  data7 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 7);
  data8 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 8);
  data9 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 9);
  data10 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 10);
  data11 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 11);
  data12 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 12);
  data13 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 13);
  data14 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 14);
  data15 := TConverters.ConvertBytesToUInt32a2(a_data, a_index + 4 * 15);

  a := Fm_state[0];
  b := Fm_state[1];
  c := Fm_state[2];
  d := Fm_state[3];
  aa := Fm_state[4];
  bb := Fm_state[5];
  cc := Fm_state[6];
  dd := Fm_state[7];

  a := a + (data0 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 11);
  d := d + (data1 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 14);
  c := c + (data2 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 15);
  b := b + (data3 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 12);
  a := a + (data4 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 5);
  d := d + (data5 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 8);
  c := c + (data6 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 7);
  b := b + (data7 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 9);
  a := a + (data8 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 11);
  d := d + (data9 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 13);
  c := c + (data10 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 14);
  b := b + (data11 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 15);
  a := a + (data12 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 6);
  d := d + (data13 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 7);
  c := c + (data14 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 9);
  b := b + (data15 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 8);

  aa := aa + (data5 + C1 + ((bb and dd) or (cc and not dd)));
  aa := TBits.RotateLeft32(aa, 8);
  dd := dd + (data14 + C1 + ((aa and cc) or (bb and not cc)));
  dd := TBits.RotateLeft32(dd, 9);
  cc := cc + (data7 + C1 + ((dd and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 9);
  bb := bb + (data0 + C1 + ((cc and aa) or (dd and not aa)));
  bb := TBits.RotateLeft32(bb, 11);
  aa := aa + (data9 + C1 + ((bb and dd) or (cc and not dd)));
  aa := TBits.RotateLeft32(aa, 13);
  dd := dd + (data2 + C1 + ((aa and cc) or (bb and not cc)));
  dd := TBits.RotateLeft32(dd, 15);
  cc := cc + (data11 + C1 + ((dd and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 15);
  bb := bb + (data4 + C1 + ((cc and aa) or (dd and not aa)));
  bb := TBits.RotateLeft32(bb, 5);
  aa := aa + (data13 + C1 + ((bb and dd) or (cc and not dd)));
  aa := TBits.RotateLeft32(aa, 7);
  dd := dd + (data6 + C1 + ((aa and cc) or (bb and not cc)));
  dd := TBits.RotateLeft32(dd, 7);
  cc := cc + (data15 + C1 + ((dd and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 8);
  bb := bb + (data8 + C1 + ((cc and aa) or (dd and not aa)));
  bb := TBits.RotateLeft32(bb, 11);
  aa := aa + (data1 + C1 + ((bb and dd) or (cc and not dd)));
  aa := TBits.RotateLeft32(aa, 14);
  dd := dd + (data10 + C1 + ((aa and cc) or (bb and not cc)));
  dd := TBits.RotateLeft32(dd, 14);
  cc := cc + (data3 + C1 + ((dd and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 12);
  bb := bb + (data12 + C1 + ((cc and aa) or (dd and not aa)));
  bb := TBits.RotateLeft32(bb, 6);

  aa := aa + (data7 + C2 + ((b and c) or (not b and d)));
  aa := TBits.RotateLeft32(aa, 7);
  d := d + (data4 + C2 + ((aa and b) or (not aa and c)));
  d := TBits.RotateLeft32(d, 6);
  c := c + (data13 + C2 + ((d and aa) or (not d and b)));
  c := TBits.RotateLeft32(c, 8);
  b := b + (data1 + C2 + ((c and d) or (not c and aa)));
  b := TBits.RotateLeft32(b, 13);
  aa := aa + (data10 + C2 + ((b and c) or (not b and d)));
  aa := TBits.RotateLeft32(aa, 11);
  d := d + (data6 + C2 + ((aa and b) or (not aa and c)));
  d := TBits.RotateLeft32(d, 9);
  c := c + (data15 + C2 + ((d and aa) or (not d and b)));
  c := TBits.RotateLeft32(c, 7);
  b := b + (data3 + C2 + ((c and d) or (not c and aa)));
  b := TBits.RotateLeft32(b, 15);
  aa := aa + (data12 + C2 + ((b and c) or (not b and d)));
  aa := TBits.RotateLeft32(aa, 7);
  d := d + (data0 + C2 + ((aa and b) or (not aa and c)));
  d := TBits.RotateLeft32(d, 12);
  c := c + (data9 + C2 + ((d and aa) or (not d and b)));
  c := TBits.RotateLeft32(c, 15);
  b := b + (data5 + C2 + ((c and d) or (not c and aa)));
  b := TBits.RotateLeft32(b, 9);
  aa := aa + (data2 + C2 + ((b and c) or (not b and d)));
  aa := TBits.RotateLeft32(aa, 11);
  d := d + (data14 + C2 + ((aa and b) or (not aa and c)));
  d := TBits.RotateLeft32(d, 7);
  c := c + (data11 + C2 + ((d and aa) or (not d and b)));
  c := TBits.RotateLeft32(c, 13);
  b := b + (data8 + C2 + ((c and d) or (not c and aa)));
  b := TBits.RotateLeft32(b, 12);

  a := a + (data6 + C3 + ((bb or not cc) xor dd));
  a := TBits.RotateLeft32(a, 9);
  dd := dd + (data11 + C3 + ((a or not bb) xor cc));
  dd := TBits.RotateLeft32(dd, 13);
  cc := cc + (data3 + C3 + ((dd or not a) xor bb));
  cc := TBits.RotateLeft32(cc, 15);
  bb := bb + (data7 + C3 + ((cc or not dd) xor a));
  bb := TBits.RotateLeft32(bb, 7);
  a := a + (data0 + C3 + ((bb or not cc) xor dd));
  a := TBits.RotateLeft32(a, 12);
  dd := dd + (data13 + C3 + ((a or not bb) xor cc));
  dd := TBits.RotateLeft32(dd, 8);
  cc := cc + (data5 + C3 + ((dd or not a) xor bb));
  cc := TBits.RotateLeft32(cc, 9);
  bb := bb + (data10 + C3 + ((cc or not dd) xor a));
  bb := TBits.RotateLeft32(bb, 11);
  a := a + (data14 + C3 + ((bb or not cc) xor dd));
  a := TBits.RotateLeft32(a, 7);
  dd := dd + (data15 + C3 + ((a or not bb) xor cc));
  dd := TBits.RotateLeft32(dd, 7);
  cc := cc + (data8 + C3 + ((dd or not a) xor bb));
  cc := TBits.RotateLeft32(cc, 12);
  bb := bb + (data12 + C3 + ((cc or not dd) xor a));
  bb := TBits.RotateLeft32(bb, 7);
  a := a + (data4 + C3 + ((bb or not cc) xor dd));
  a := TBits.RotateLeft32(a, 6);
  dd := dd + (data9 + C3 + ((a or not bb) xor cc));
  dd := TBits.RotateLeft32(dd, 15);
  cc := cc + (data1 + C3 + ((dd or not a) xor bb));
  cc := TBits.RotateLeft32(cc, 13);
  bb := bb + (data2 + C3 + ((cc or not dd) xor a));
  bb := TBits.RotateLeft32(bb, 11);

  aa := aa + (data3 + C4 + ((bb or not c) xor d));
  aa := TBits.RotateLeft32(aa, 11);
  d := d + (data10 + C4 + ((aa or not bb) xor c));
  d := TBits.RotateLeft32(d, 13);
  c := c + (data14 + C4 + ((d or not aa) xor bb));
  c := TBits.RotateLeft32(c, 6);
  bb := bb + (data4 + C4 + ((c or not d) xor aa));
  bb := TBits.RotateLeft32(bb, 7);
  aa := aa + (data9 + C4 + ((bb or not c) xor d));
  aa := TBits.RotateLeft32(aa, 14);
  d := d + (data15 + C4 + ((aa or not bb) xor c));
  d := TBits.RotateLeft32(d, 9);
  c := c + (data8 + C4 + ((d or not aa) xor bb));
  c := TBits.RotateLeft32(c, 13);
  bb := bb + (data1 + C4 + ((c or not d) xor aa));
  bb := TBits.RotateLeft32(bb, 15);
  aa := aa + (data2 + C4 + ((bb or not c) xor d));
  aa := TBits.RotateLeft32(aa, 14);
  d := d + (data7 + C4 + ((aa or not bb) xor c));
  d := TBits.RotateLeft32(d, 8);
  c := c + (data0 + C4 + ((d or not aa) xor bb));
  c := TBits.RotateLeft32(c, 13);
  bb := bb + (data6 + C4 + ((c or not d) xor aa));
  bb := TBits.RotateLeft32(bb, 6);
  aa := aa + (data13 + C4 + ((bb or not c) xor d));
  aa := TBits.RotateLeft32(aa, 5);
  d := d + (data11 + C4 + ((aa or not bb) xor c));
  d := TBits.RotateLeft32(d, 12);
  c := c + (data5 + C4 + ((d or not aa) xor bb));
  c := TBits.RotateLeft32(c, 7);
  bb := bb + (data12 + C4 + ((c or not d) xor aa));
  bb := TBits.RotateLeft32(bb, 5);

  a := a + (data15 + C5 + ((b and cc) or (not b and dd)));
  a := TBits.RotateLeft32(a, 9);
  dd := dd + (data5 + C5 + ((a and b) or (not a and cc)));
  dd := TBits.RotateLeft32(dd, 7);
  cc := cc + (data1 + C5 + ((dd and a) or (not dd and b)));
  cc := TBits.RotateLeft32(cc, 15);
  b := b + (data3 + C5 + ((cc and dd) or (not cc and a)));
  b := TBits.RotateLeft32(b, 11);
  a := a + (data7 + C5 + ((b and cc) or (not b and dd)));
  a := TBits.RotateLeft32(a, 8);
  dd := dd + (data14 + C5 + ((a and b) or (not a and cc)));
  dd := TBits.RotateLeft32(dd, 6);
  cc := cc + (data6 + C5 + ((dd and a) or (not dd and b)));
  cc := TBits.RotateLeft32(cc, 6);
  b := b + (data9 + C5 + ((cc and dd) or (not cc and a)));
  b := TBits.RotateLeft32(b, 14);
  a := a + (data11 + C5 + ((b and cc) or (not b and dd)));
  a := TBits.RotateLeft32(a, 12);
  dd := dd + (data8 + C5 + ((a and b) or (not a and cc)));
  dd := TBits.RotateLeft32(dd, 13);
  cc := cc + (data12 + C5 + ((dd and a) or (not dd and b)));
  cc := TBits.RotateLeft32(cc, 5);
  b := b + (data2 + C5 + ((cc and dd) or (not cc and a)));
  b := TBits.RotateLeft32(b, 14);
  a := a + (data10 + C5 + ((b and cc) or (not b and dd)));
  a := TBits.RotateLeft32(a, 13);
  dd := dd + (data0 + C5 + ((a and b) or (not a and cc)));
  dd := TBits.RotateLeft32(dd, 13);
  cc := cc + (data4 + C5 + ((dd and a) or (not dd and b)));
  cc := TBits.RotateLeft32(cc, 7);
  b := b + (data13 + C5 + ((cc and dd) or (not cc and a)));
  b := TBits.RotateLeft32(b, 5);

  aa := aa + (data1 + C6 + ((bb and d) or (cc and not d)));
  aa := TBits.RotateLeft32(aa, 11);
  d := d + (data9 + C6 + ((aa and cc) or (bb and not cc)));
  d := TBits.RotateLeft32(d, 12);
  cc := cc + (data11 + C6 + ((d and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 14);
  bb := bb + (data10 + C6 + ((cc and aa) or (d and not aa)));
  bb := TBits.RotateLeft32(bb, 15);
  aa := aa + (data0 + C6 + ((bb and d) or (cc and not d)));
  aa := TBits.RotateLeft32(aa, 14);
  d := d + (data8 + C6 + ((aa and cc) or (bb and not cc)));
  d := TBits.RotateLeft32(d, 15);
  cc := cc + (data12 + C6 + ((d and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 9);
  bb := bb + (data4 + C6 + ((cc and aa) or (d and not aa)));
  bb := TBits.RotateLeft32(bb, 8);
  aa := aa + (data13 + C6 + ((bb and d) or (cc and not d)));
  aa := TBits.RotateLeft32(aa, 9);
  d := d + (data3 + C6 + ((aa and cc) or (bb and not cc)));
  d := TBits.RotateLeft32(d, 14);
  cc := cc + (data7 + C6 + ((d and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 5);
  bb := bb + (data15 + C6 + ((cc and aa) or (d and not aa)));
  bb := TBits.RotateLeft32(bb, 6);
  aa := aa + (data14 + C6 + ((bb and d) or (cc and not d)));
  aa := TBits.RotateLeft32(aa, 8);
  d := d + (data5 + C6 + ((aa and cc) or (bb and not cc)));
  d := TBits.RotateLeft32(d, 6);
  cc := cc + (data6 + C6 + ((d and bb) or (aa and not bb)));
  cc := TBits.RotateLeft32(cc, 5);
  bb := bb + (data2 + C6 + ((cc and aa) or (d and not aa)));
  bb := TBits.RotateLeft32(bb, 12);

  a := a + (data8 + (b xor c xor dd));
  a := TBits.RotateLeft32(a, 15);
  dd := dd + (data6 + (a xor b xor c));
  dd := TBits.RotateLeft32(dd, 5);
  c := c + (data4 + (dd xor a xor b));
  c := TBits.RotateLeft32(c, 8);
  b := b + (data1 + (c xor dd xor a));
  b := TBits.RotateLeft32(b, 11);
  a := a + (data3 + (b xor c xor dd));
  a := TBits.RotateLeft32(a, 14);
  dd := dd + (data11 + (a xor b xor c));
  dd := TBits.RotateLeft32(dd, 14);
  c := c + (data15 + (dd xor a xor b));
  c := TBits.RotateLeft32(c, 6);
  b := b + (data0 + (c xor dd xor a));
  b := TBits.RotateLeft32(b, 14);
  a := a + (data5 + (b xor c xor dd));
  a := TBits.RotateLeft32(a, 6);
  dd := dd + (data12 + (a xor b xor c));
  dd := TBits.RotateLeft32(dd, 9);
  c := c + (data2 + (dd xor a xor b));
  c := TBits.RotateLeft32(c, 12);
  b := b + (data13 + (c xor dd xor a));
  b := TBits.RotateLeft32(b, 9);
  a := a + (data9 + (b xor c xor dd));
  a := TBits.RotateLeft32(a, 12);
  dd := dd + (data7 + (a xor b xor c));
  dd := TBits.RotateLeft32(dd, 5);
  c := c + (data10 + (dd xor a xor b));
  c := TBits.RotateLeft32(c, 15);
  b := b + (data14 + (c xor dd xor a));
  b := TBits.RotateLeft32(b, 8);

  Fm_state[0] := Fm_state[0] + aa;
  Fm_state[1] := Fm_state[1] + bb;
  Fm_state[2] := Fm_state[2] + cc;
  Fm_state[3] := Fm_state[3] + dd;
  Fm_state[4] := Fm_state[4] + a;
  Fm_state[5] := Fm_state[5] + b;
  Fm_state[6] := Fm_state[6] + c;
  Fm_state[7] := Fm_state[7] + d;

end;

end.
