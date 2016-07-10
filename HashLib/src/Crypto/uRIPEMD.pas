unit uRIPEMD;

interface

uses
  uHashLibTypes,
  uBits,
  uMDBase,
  uConverters,
  uIHashInfo;

type
  TRIPEMD = class sealed(TMDBase, ITransformBlock)

  strict private
    class function P1(a, b, c: UInt32): UInt32; static; inline;
    class function P2(a, b, c: UInt32): UInt32; static; inline;
    class function P3(a, b, c: UInt32): UInt32; static; inline;

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  public
    constructor Create();

  end;

implementation

{ TRIPEMD }

constructor TRIPEMD.Create;
begin
  Inherited Create(4, 16);
end;

class function TRIPEMD.P1(a, b, c: UInt32): UInt32;
begin
  result := (a and b) or (not a and c);
end;

class function TRIPEMD.P2(a, b, c: UInt32): UInt32;
begin
  result := (a and b) or (a and c) or (b and c);
end;

class function TRIPEMD.P3(a, b, c: UInt32): UInt32;
begin
  result := a xor b xor c;
end;

procedure TRIPEMD.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
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
  aa := a;
  bb := b;
  cc := c;
  dd := d;

  a := TBits.RotateLeft32(P1(b, c, d) + a + data0, 11);
  d := TBits.RotateLeft32(P1(a, b, c) + d + data1, 14);
  c := TBits.RotateLeft32(P1(d, a, b) + c + data2, 15);
  b := TBits.RotateLeft32(P1(c, d, a) + b + data3, 12);
  a := TBits.RotateLeft32(P1(b, c, d) + a + data4, 5);
  d := TBits.RotateLeft32(P1(a, b, c) + d + data5, 8);
  c := TBits.RotateLeft32(P1(d, a, b) + c + data6, 7);
  b := TBits.RotateLeft32(P1(c, d, a) + b + data7, 9);
  a := TBits.RotateLeft32(P1(b, c, d) + a + data8, 11);
  d := TBits.RotateLeft32(P1(a, b, c) + d + data9, 13);
  c := TBits.RotateLeft32(P1(d, a, b) + c + data10, 14);
  b := TBits.RotateLeft32(P1(c, d, a) + b + data11, 15);
  a := TBits.RotateLeft32(P1(b, c, d) + a + data12, 6);
  d := TBits.RotateLeft32(P1(a, b, c) + d + data13, 7);
  c := TBits.RotateLeft32(P1(d, a, b) + c + data14, 9);
  b := TBits.RotateLeft32(P1(c, d, a) + b + data15, 8);

  a := TBits.RotateLeft32(P2(b, c, d) + a + data7 + C2, 7);
  d := TBits.RotateLeft32(P2(a, b, c) + d + data4 + C2, 6);
  c := TBits.RotateLeft32(P2(d, a, b) + c + data13 + C2, 8);
  b := TBits.RotateLeft32(P2(c, d, a) + b + data1 + C2, 13);
  a := TBits.RotateLeft32(P2(b, c, d) + a + data10 + C2, 11);
  d := TBits.RotateLeft32(P2(a, b, c) + d + data6 + C2, 9);
  c := TBits.RotateLeft32(P2(d, a, b) + c + data15 + C2, 7);
  b := TBits.RotateLeft32(P2(c, d, a) + b + data3 + C2, 15);
  a := TBits.RotateLeft32(P2(b, c, d) + a + data12 + C2, 7);
  d := TBits.RotateLeft32(P2(a, b, c) + d + data0 + C2, 12);
  c := TBits.RotateLeft32(P2(d, a, b) + c + data9 + C2, 15);
  b := TBits.RotateLeft32(P2(c, d, a) + b + data5 + C2, 9);
  a := TBits.RotateLeft32(P2(b, c, d) + a + data14 + C2, 7);
  d := TBits.RotateLeft32(P2(a, b, c) + d + data2 + C2, 11);
  c := TBits.RotateLeft32(P2(d, a, b) + c + data11 + C2, 13);
  b := TBits.RotateLeft32(P2(c, d, a) + b + data8 + C2, 12);

  a := TBits.RotateLeft32(P3(b, c, d) + a + data3 + C4, 11);
  d := TBits.RotateLeft32(P3(a, b, c) + d + data10 + C4, 13);
  c := TBits.RotateLeft32(P3(d, a, b) + c + data2 + C4, 14);
  b := TBits.RotateLeft32(P3(c, d, a) + b + data4 + C4, 7);
  a := TBits.RotateLeft32(P3(b, c, d) + a + data9 + C4, 14);
  d := TBits.RotateLeft32(P3(a, b, c) + d + data15 + C4, 9);
  c := TBits.RotateLeft32(P3(d, a, b) + c + data8 + C4, 13);
  b := TBits.RotateLeft32(P3(c, d, a) + b + data1 + C4, 15);
  a := TBits.RotateLeft32(P3(b, c, d) + a + data14 + C4, 6);
  d := TBits.RotateLeft32(P3(a, b, c) + d + data7 + C4, 8);
  c := TBits.RotateLeft32(P3(d, a, b) + c + data0 + C4, 13);
  b := TBits.RotateLeft32(P3(c, d, a) + b + data6 + C4, 6);
  a := TBits.RotateLeft32(P3(b, c, d) + a + data11 + C4, 12);
  d := TBits.RotateLeft32(P3(a, b, c) + d + data13 + C4, 5);
  c := TBits.RotateLeft32(P3(d, a, b) + c + data5 + C4, 7);
  b := TBits.RotateLeft32(P3(c, d, a) + b + data12 + C4, 5);

  aa := TBits.RotateLeft32(P1(bb, cc, dd) + aa + data0 + C1, 11);
  dd := TBits.RotateLeft32(P1(aa, bb, cc) + dd + data1 + C1, 14);
  cc := TBits.RotateLeft32(P1(dd, aa, bb) + cc + data2 + C1, 15);
  bb := TBits.RotateLeft32(P1(cc, dd, aa) + bb + data3 + C1, 12);
  aa := TBits.RotateLeft32(P1(bb, cc, dd) + aa + data4 + C1, 5);
  dd := TBits.RotateLeft32(P1(aa, bb, cc) + dd + data5 + C1, 8);
  cc := TBits.RotateLeft32(P1(dd, aa, bb) + cc + data6 + C1, 7);
  bb := TBits.RotateLeft32(P1(cc, dd, aa) + bb + data7 + C1, 9);
  aa := TBits.RotateLeft32(P1(bb, cc, dd) + aa + data8 + C1, 11);
  dd := TBits.RotateLeft32(P1(aa, bb, cc) + dd + data9 + C1, 13);
  cc := TBits.RotateLeft32(P1(dd, aa, bb) + cc + data10 + C1, 14);
  bb := TBits.RotateLeft32(P1(cc, dd, aa) + bb + data11 + C1, 15);
  aa := TBits.RotateLeft32(P1(bb, cc, dd) + aa + data12 + C1, 6);
  dd := TBits.RotateLeft32(P1(aa, bb, cc) + dd + data13 + C1, 7);
  cc := TBits.RotateLeft32(P1(dd, aa, bb) + cc + data14 + C1, 9);
  bb := TBits.RotateLeft32(P1(cc, dd, aa) + bb + data15 + C1, 8);

  aa := TBits.RotateLeft32(P2(bb, cc, dd) + aa + data7, 7);
  dd := TBits.RotateLeft32(P2(aa, bb, cc) + dd + data4, 6);
  cc := TBits.RotateLeft32(P2(dd, aa, bb) + cc + data13, 8);
  bb := TBits.RotateLeft32(P2(cc, dd, aa) + bb + data1, 13);
  aa := TBits.RotateLeft32(P2(bb, cc, dd) + aa + data10, 11);
  dd := TBits.RotateLeft32(P2(aa, bb, cc) + dd + data6, 9);
  cc := TBits.RotateLeft32(P2(dd, aa, bb) + cc + data15, 7);
  bb := TBits.RotateLeft32(P2(cc, dd, aa) + bb + data3, 15);
  aa := TBits.RotateLeft32(P2(bb, cc, dd) + aa + data12, 7);
  dd := TBits.RotateLeft32(P2(aa, bb, cc) + dd + data0, 12);
  cc := TBits.RotateLeft32(P2(dd, aa, bb) + cc + data9, 15);
  bb := TBits.RotateLeft32(P2(cc, dd, aa) + bb + data5, 9);
  aa := TBits.RotateLeft32(P2(bb, cc, dd) + aa + data14, 7);
  dd := TBits.RotateLeft32(P2(aa, bb, cc) + dd + data2, 11);
  cc := TBits.RotateLeft32(P2(dd, aa, bb) + cc + data11, 13);
  bb := TBits.RotateLeft32(P2(cc, dd, aa) + bb + data8, 12);

  aa := TBits.RotateLeft32(P3(bb, cc, dd) + aa + data3 + C3, 11);
  dd := TBits.RotateLeft32(P3(aa, bb, cc) + dd + data10 + C3, 13);
  cc := TBits.RotateLeft32(P3(dd, aa, bb) + cc + data2 + C3, 14);
  bb := TBits.RotateLeft32(P3(cc, dd, aa) + bb + data4 + C3, 7);
  aa := TBits.RotateLeft32(P3(bb, cc, dd) + aa + data9 + C3, 14);
  dd := TBits.RotateLeft32(P3(aa, bb, cc) + dd + data15 + C3, 9);
  cc := TBits.RotateLeft32(P3(dd, aa, bb) + cc + data8 + C3, 13);
  bb := TBits.RotateLeft32(P3(cc, dd, aa) + bb + data1 + C3, 15);
  aa := TBits.RotateLeft32(P3(bb, cc, dd) + aa + data14 + C3, 6);
  dd := TBits.RotateLeft32(P3(aa, bb, cc) + dd + data7 + C3, 8);
  cc := TBits.RotateLeft32(P3(dd, aa, bb) + cc + data0 + C3, 13);
  bb := TBits.RotateLeft32(P3(cc, dd, aa) + bb + data6 + C3, 6);
  aa := TBits.RotateLeft32(P3(bb, cc, dd) + aa + data11 + C3, 12);
  dd := TBits.RotateLeft32(P3(aa, bb, cc) + dd + data13 + C3, 5);
  cc := TBits.RotateLeft32(P3(dd, aa, bb) + cc + data5 + C3, 7);
  bb := TBits.RotateLeft32(P3(cc, dd, aa) + bb + data12 + C3, 5);

  cc := cc + Fm_state[0] + b;
  Fm_state[0] := Fm_state[1] + c + dd;
  Fm_state[1] := Fm_state[2] + d + aa;
  Fm_state[2] := Fm_state[3] + a + bb;
  Fm_state[3] := cc;

end;

end.
