unit HlpMD4;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpMDBase,
{$IFDEF DELPHI}
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpBits,
  HlpConverters,
  HlpIHashInfo;

type
  TMD4 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
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

procedure TMD4.TransformBlock(a_data: PByte; a_data_length: Int32;
  a_index: Int32);
var
  a, b, c, d: UInt32;
  data: array [0 .. 15] of UInt32;
  ptr_data: PCardinal;
begin

  ptr_data := @(data[0]);
  TConverters.le32_copy(a_data, a_index, ptr_data, 0, 64);

  a := Fptr_Fm_state[0];
  b := Fptr_Fm_state[1];
  c := Fptr_Fm_state[2];
  d := Fptr_Fm_state[3];

  a := a + (ptr_data[0] + ((b and c) or ((not b) and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[1] + ((a and b) or ((not a) and c)));
  d := TBits.RotateLeft32(d, 7);
  c := c + (ptr_data[2] + ((d and a) or ((not d) and b)));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[3] + ((c and d) or ((not c) and a)));
  b := TBits.RotateLeft32(b, 19);
  a := a + (ptr_data[4] + ((b and c) or ((not b) and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[5] + ((a and b) or ((not a) and c)));
  d := TBits.RotateLeft32(d, 7);
  c := c + (ptr_data[6] + ((d and a) or ((not d) and b)));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[7] + ((c and d) or ((not c) and a)));
  b := TBits.RotateLeft32(b, 19);
  a := a + (ptr_data[8] + ((b and c) or ((not b) and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[9] + ((a and b) or ((not a) and c)));
  d := TBits.RotateLeft32(d, 7);
  c := c + (ptr_data[10] + ((d and a) or ((not d) and b)));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[11] + ((c and d) or ((not c) and a)));
  b := TBits.RotateLeft32(b, 19);
  a := a + (ptr_data[12] + ((b and c) or ((not b) and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[13] + ((a and b) or ((not a) and c)));
  d := TBits.RotateLeft32(d, 7);
  c := c + (ptr_data[14] + ((d and a) or ((not d) and b)));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[15] + ((c and d) or ((not c) and a)));
  b := TBits.RotateLeft32(b, 19);

  a := a + (ptr_data[0] + C2 + ((b and (c or d)) or (c and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[4] + C2 + ((a and (b or c)) or (b and c)));
  d := TBits.RotateLeft32(d, 5);
  c := c + (ptr_data[8] + C2 + ((d and (a or b)) or (a and b)));
  c := TBits.RotateLeft32(c, 9);
  b := b + (ptr_data[12] + C2 + ((c and (d or a)) or (d and a)));
  b := TBits.RotateLeft32(b, 13);
  a := a + (ptr_data[1] + C2 + ((b and (c or d)) or (c and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[5] + C2 + ((a and (b or c)) or (b and c)));
  d := TBits.RotateLeft32(d, 5);
  c := c + (ptr_data[9] + C2 + ((d and (a or b)) or (a and b)));
  c := TBits.RotateLeft32(c, 9);
  b := b + (ptr_data[13] + C2 + ((c and (d or a)) or (d and a)));
  b := TBits.RotateLeft32(b, 13);
  a := a + (ptr_data[2] + C2 + ((b and (c or d)) or (c and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[6] + C2 + ((a and (b or c)) or (b and c)));
  d := TBits.RotateLeft32(d, 5);
  c := c + (ptr_data[10] + C2 + ((d and (a or b)) or (a and b)));
  c := TBits.RotateLeft32(c, 9);
  b := b + (ptr_data[14] + C2 + ((c and (d or a)) or (d and a)));
  b := TBits.RotateLeft32(b, 13);
  a := a + (ptr_data[3] + C2 + ((b and (c or d)) or (c and d)));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[7] + C2 + ((a and (b or c)) or (b and c)));
  d := TBits.RotateLeft32(d, 5);
  c := c + (ptr_data[11] + C2 + ((d and (a or b)) or (a and b)));
  c := TBits.RotateLeft32(c, 9);
  b := b + (ptr_data[15] + C2 + ((c and (d or a)) or (d and a)));
  b := TBits.RotateLeft32(b, 13);

  a := a + (ptr_data[0] + C4 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[8] + C4 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 9);
  c := c + (ptr_data[4] + C4 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[12] + C4 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 15);
  a := a + (ptr_data[2] + C4 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[10] + C4 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 9);
  c := c + (ptr_data[6] + C4 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[14] + C4 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 15);
  a := a + (ptr_data[1] + C4 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[9] + C4 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 9);
  c := c + (ptr_data[5] + C4 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[13] + C4 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 15);
  a := a + (ptr_data[3] + C4 + (b xor c xor d));
  a := TBits.RotateLeft32(a, 3);
  d := d + (ptr_data[11] + C4 + (a xor b xor c));
  d := TBits.RotateLeft32(d, 9);
  c := c + (ptr_data[7] + C4 + (d xor a xor b));
  c := TBits.RotateLeft32(c, 11);
  b := b + (ptr_data[15] + C4 + (c xor d xor a));
  b := TBits.RotateLeft32(b, 15);

  Fptr_Fm_state[0] := Fptr_Fm_state[0] + a;
  Fptr_Fm_state[1] := Fptr_Fm_state[1] + b;
  Fptr_Fm_state[2] := Fptr_Fm_state[2] + c;
  Fptr_Fm_state[3] := Fptr_Fm_state[3] + d;

  System.FillChar(data, System.SizeOf(data), 0);
end;

end.
