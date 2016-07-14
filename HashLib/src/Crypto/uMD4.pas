unit uMD4;

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  uHashLibTypes,
  uMDBase,
  uConverters,
  uIHashInfo;

type
  TMD4 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  public
    constructor Create();

  end;

implementation

{ TMD4 }

constructor TMD4.Create;
begin
  Inherited Create(4, 16);
end;

procedure TMD4.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  data0, data1, data2, data3, data4, data5, data6, data7, data8, data9, data10,
    data11, data12, data13, data14, data15, a, b, c, d: UInt32;
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

  a := a + (data0 + ((b and c) or ((not b) and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data1 + ((a and b) or ((not a) and c)));
  d := d shl 7 or d shr (32 - 7);
  c := c + (data2 + ((d and a) or ((not d) and b)));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data3 + ((c and d) or ((not c) and a)));
  b := b shl 19 or b shr (32 - 19);
  a := a + (data4 + ((b and c) or ((not b) and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data5 + ((a and b) or ((not a) and c)));
  d := d shl 7 or d shr (32 - 7);
  c := c + (data6 + ((d and a) or ((not d) and b)));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data7 + ((c and d) or ((not c) and a)));
  b := b shl 19 or b shr (32 - 19);
  a := a + (data8 + ((b and c) or ((not b) and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data9 + ((a and b) or ((not a) and c)));
  d := d shl 7 or d shr (32 - 7);
  c := c + (data10 + ((d and a) or ((not d) and b)));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data11 + ((c and d) or ((not c) and a)));
  b := b shl 19 or b shr (32 - 19);
  a := a + (data12 + ((b and c) or ((not b) and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data13 + ((a and b) or ((not a) and c)));
  d := d shl 7 or d shr (32 - 7);
  c := c + (data14 + ((d and a) or ((not d) and b)));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data15 + ((c and d) or ((not c) and a)));
  b := b shl 19 or b shr (32 - 19);

  a := a + (data0 + C2 + ((b and (c or d)) or (c and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data4 + C2 + ((a and (b or c)) or (b and c)));
  d := d shl 5 or d shr (32 - 5);
  c := c + (data8 + C2 + ((d and (a or b)) or (a and b)));
  c := c shl 9 or c shr (32 - 9);
  b := b + (data12 + C2 + ((c and (d or a)) or (d and a)));
  b := b shl 13 or b shr (32 - 13);
  a := a + (data1 + C2 + ((b and (c or d)) or (c and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data5 + C2 + ((a and (b or c)) or (b and c)));
  d := d shl 5 or d shr (32 - 5);
  c := c + (data9 + C2 + ((d and (a or b)) or (a and b)));
  c := c shl 9 or c shr (32 - 9);
  b := b + (data13 + C2 + ((c and (d or a)) or (d and a)));
  b := b shl 13 or b shr (32 - 13);
  a := a + (data2 + C2 + ((b and (c or d)) or (c and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data6 + C2 + ((a and (b or c)) or (b and c)));
  d := d shl 5 or d shr (32 - 5);
  c := c + (data10 + C2 + ((d and (a or b)) or (a and b)));
  c := c shl 9 or c shr (32 - 9);
  b := b + (data14 + C2 + ((c and (d or a)) or (d and a)));
  b := b shl 13 or b shr (32 - 13);
  a := a + (data3 + C2 + ((b and (c or d)) or (c and d)));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data7 + C2 + ((a and (b or c)) or (b and c)));
  d := d shl 5 or d shr (32 - 5);
  c := c + (data11 + C2 + ((d and (a or b)) or (a and b)));
  c := c shl 9 or c shr (32 - 9);
  b := b + (data15 + C2 + ((c and (d or a)) or (d and a)));
  b := b shl 13 or b shr (32 - 13);

  a := a + (data0 + C4 + (b xor c xor d));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data8 + C4 + (a xor b xor c));
  d := d shl 9 or d shr (32 - 9);
  c := c + (data4 + C4 + (d xor a xor b));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data12 + C4 + (c xor d xor a));
  b := b shl 15 or b shr (32 - 15);
  a := a + (data2 + C4 + (b xor c xor d));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data10 + C4 + (a xor b xor c));
  d := d shl 9 or d shr (32 - 9);
  c := c + (data6 + C4 + (d xor a xor b));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data14 + C4 + (c xor d xor a));
  b := b shl 15 or b shr (32 - 15);
  a := a + (data1 + C4 + (b xor c xor d));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data9 + C4 + (a xor b xor c));
  d := d shl 9 or d shr (32 - 9);
  c := c + (data5 + C4 + (d xor a xor b));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data13 + C4 + (c xor d xor a));
  b := b shl 15 or b shr (32 - 15);
  a := a + (data3 + C4 + (b xor c xor d));
  a := a shl 3 or a shr (32 - 3);
  d := d + (data11 + C4 + (a xor b xor c));
  d := d shl 9 or d shr (32 - 9);
  c := c + (data7 + C4 + (d xor a xor b));
  c := c shl 11 or c shr (32 - 11);
  b := b + (data15 + C4 + (c xor d xor a));
  b := b shl 15 or b shr (32 - 15);

  Fm_state[0] := Fm_state[0] + a;
  Fm_state[1] := Fm_state[1] + b;
  Fm_state[2] := Fm_state[2] + c;
  Fm_state[3] := Fm_state[3] + d;
end;

end.
