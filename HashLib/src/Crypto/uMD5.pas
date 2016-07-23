unit uMD5;

{$I ..\Include\HashLib.inc}

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
  TMD5 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;

  public
    constructor Create();

  end;

implementation

{ TMD5 }

constructor TMD5.Create;
begin
  Inherited Create(4, 16);
end;

procedure TMD5.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  data0, data1, data2, data3, data4, data5, data6, data7, data8, data9, data10,
    data11, data12, data13, data14, data15, A, B, C, D: UInt32;
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

  A := Fm_state[0];
  B := Fm_state[1];
  C := Fm_state[2];
  D := Fm_state[3];

  A := data0 + $D76AA478 + A + ((B and C) or (not B and D));
  A := ((A shl 7) or (A shr (32 - 7))) + B;
  D := data1 + $E8C7B756 + D + ((A and B) or (not A and C));
  D := ((D shl 12) or (D shr (32 - 12))) + A;
  C := data2 + $242070DB + C + ((D and A) or (not D and B));
  C := ((C shl 17) or (C shr (32 - 17))) + D;
  B := data3 + $C1BDCEEE + B + ((C and D) or (not C and A));
  B := ((B shl 22) or (B shr (32 - 22))) + C;
  A := data4 + $F57C0FAF + A + ((B and C) or (not B and D));
  A := ((A shl 7) or (A shr (32 - 7))) + B;
  D := data5 + $4787C62A + D + ((A and B) or (not A and C));
  D := ((D shl 12) or (D shr (32 - 12))) + A;
  C := data6 + $A8304613 + C + ((D and A) or (not D and B));
  C := ((C shl 17) or (C shr (32 - 17))) + D;
  B := data7 + $FD469501 + B + ((C and D) or (not C and A));
  B := ((B shl 22) or (B shr (32 - 22))) + C;
  A := data8 + $698098D8 + A + ((B and C) or (not B and D));
  A := ((A shl 7) or (A shr (32 - 7))) + B;
  D := data9 + $8B44F7AF + D + ((A and B) or (not A and C));
  D := ((D shl 12) or (D shr (32 - 12))) + A;
  C := data10 + $FFFF5BB1 + C + ((D and A) or (not D and B));
  C := ((C shl 17) or (C shr (32 - 17))) + D;
  B := data11 + $895CD7BE + B + ((C and D) or (not C and A));
  B := ((B shl 22) or (B shr (32 - 22))) + C;
  A := data12 + $6B901122 + A + ((B and C) or (not B and D));
  A := ((A shl 7) or (A shr (32 - 7))) + B;
  D := data13 + $FD987193 + D + ((A and B) or (not A and C));
  D := ((D shl 12) or (D shr (32 - 12))) + A;
  C := data14 + $A679438E + C + ((D and A) or (not D and B));
  C := ((C shl 17) or (C shr (32 - 17))) + D;
  B := data15 + $49B40821 + B + ((C and D) or (not C and A));
  B := ((B shl 22) or (B shr (32 - 22))) + C;

  A := data1 + $F61E2562 + A + ((B and D) or (C and not D));
  A := ((A shl 5) or (A shr (32 - 5))) + B;
  D := data6 + $C040B340 + D + ((A and C) or (B and not C));
  D := ((D shl 9) or (D shr (32 - 9))) + A;
  C := data11 + $265E5A51 + C + ((D and B) or (A and not B));
  C := ((C shl 14) or (C shr (32 - 14))) + D;
  B := data0 + $E9B6C7AA + B + ((C and A) or (D and not A));
  B := ((B shl 20) or (B shr (32 - 20))) + C;
  A := data5 + $D62F105D + A + ((B and D) or (C and not D));
  A := ((A shl 5) or (A shr (32 - 5))) + B;
  D := data10 + $2441453 + D + ((A and C) or (B and not C));
  D := ((D shl 9) or (D shr (32 - 9))) + A;
  C := data15 + $D8A1E681 + C + ((D and B) or (A and not B));
  C := ((C shl 14) or (C shr (32 - 14))) + D;
  B := data4 + $E7D3FBC8 + B + ((C and A) or (D and not A));
  B := ((B shl 20) or (B shr (32 - 20))) + C;
  A := data9 + $21E1CDE6 + A + ((B and D) or (C and not D));
  A := ((A shl 5) or (A shr (32 - 5))) + B;
  D := data14 + $C33707D6 + D + ((A and C) or (B and not C));
  D := ((D shl 9) or (D shr (32 - 9))) + A;
  C := data3 + $F4D50D87 + C + ((D and B) or (A and not B));
  C := ((C shl 14) or (C shr (32 - 14))) + D;
  B := data8 + $455A14ED + B + ((C and A) or (D and not A));
  B := ((B shl 20) or (B shr (32 - 20))) + C;
  A := data13 + $A9E3E905 + A + ((B and D) or (C and not D));
  A := ((A shl 5) or (A shr (32 - 5))) + B;
  D := data2 + $FCEFA3F8 + D + ((A and C) or (B and not C));
  D := ((D shl 9) or (D shr (32 - 9))) + A;
  C := data7 + $676F02D9 + C + ((D and B) or (A and not B));
  C := ((C shl 14) or (C shr (32 - 14))) + D;
  B := data12 + $8D2A4C8A + B + ((C and A) or (D and not A));
  B := ((B shl 20) or (B shr (32 - 20))) + C;

  A := data5 + $FFFA3942 + A + (B xor C xor D);
  A := ((A shl 4) or (A shr (32 - 4))) + B;
  D := data8 + $8771F681 + D + (A xor B xor C);
  D := ((D shl 11) or (D shr (32 - 11))) + A;
  C := data11 + $6D9D6122 + C + (D xor A xor B);
  C := ((C shl 16) or (C shr (32 - 16))) + D;
  B := data14 + $FDE5380C + B + (C xor D xor A);
  B := ((B shl 23) or (B shr (32 - 23))) + C;
  A := data1 + $A4BEEA44 + A + (B xor C xor D);
  A := ((A shl 4) or (A shr (32 - 4))) + B;
  D := data4 + $4BDECFA9 + D + (A xor B xor C);
  D := ((D shl 11) or (D shr (32 - 11))) + A;
  C := data7 + $F6BB4B60 + C + (D xor A xor B);
  C := ((C shl 16) or (C shr (32 - 16))) + D;
  B := data10 + $BEBFBC70 + B + (C xor D xor A);
  B := ((B shl 23) or (B shr (32 - 23))) + C;
  A := data13 + $289B7EC6 + A + (B xor C xor D);
  A := ((A shl 4) or (A shr (32 - 4))) + B;
  D := data0 + $EAA127FA + D + (A xor B xor C);
  D := ((D shl 11) or (D shr (32 - 11))) + A;
  C := data3 + $D4EF3085 + C + (D xor A xor B);
  C := ((C shl 16) or (C shr (32 - 16))) + D;
  B := data6 + $4881D05 + B + (C xor D xor A);
  B := ((B shl 23) or (B shr (32 - 23))) + C;
  A := data9 + $D9D4D039 + A + (B xor C xor D);
  A := ((A shl 4) or (A shr (32 - 4))) + B;
  D := data12 + $E6DB99E5 + D + (A xor B xor C);
  D := ((D shl 11) or (D shr (32 - 11))) + A;
  C := data15 + $1FA27CF8 + C + (D xor A xor B);
  C := ((C shl 16) or (C shr (32 - 16))) + D;
  B := data2 + $C4AC5665 + B + (C xor D xor A);
  B := ((B shl 23) or (B shr (32 - 23))) + C;

  A := data0 + $F4292244 + A + (C xor (B or not D));
  A := ((A shl 6) or (A shr (32 - 6))) + B;
  D := data7 + $432AFF97 + D + (B xor (A or not C));
  D := ((D shl 10) or (D shr (32 - 10))) + A;
  C := data14 + $AB9423A7 + C + (A xor (D or not B));
  C := ((C shl 15) or (C shr (32 - 15))) + D;
  B := data5 + $FC93A039 + B + (D xor (C or not A));
  B := ((B shl 21) or (B shr (32 - 21))) + C;
  A := data12 + $655B59C3 + A + (C xor (B or not D));
  A := ((A shl 6) or (A shr (32 - 6))) + B;
  D := data3 + $8F0CCC92 + D + (B xor (A or not C));
  D := ((D shl 10) or (D shr (32 - 10))) + A;
  C := data10 + $FFEFF47D + C + (A xor (D or not B));
  C := ((C shl 15) or (C shr (32 - 15))) + D;
  B := data1 + $85845DD1 + B + (D xor (C or not A));
  B := ((B shl 21) or (B shr (32 - 21))) + C;
  A := data8 + $6FA87E4F + A + (C xor (B or not D));
  A := ((A shl 6) or (A shr (32 - 6))) + B;
  D := data15 + $FE2CE6E0 + D + (B xor (A or not C));
  D := ((D shl 10) or (D shr (32 - 10))) + A;
  C := data6 + $A3014314 + C + (A xor (D or not B));
  C := ((C shl 15) or (C shr (32 - 15))) + D;
  B := data13 + $4E0811A1 + B + (D xor (C or not A));
  B := ((B shl 21) or (B shr (32 - 21))) + C;
  A := data4 + $F7537E82 + A + (C xor (B or not D));
  A := ((A shl 6) or (A shr (32 - 6))) + B;
  D := data11 + $BD3AF235 + D + (B xor (A or not C));
  D := ((D shl 10) or (D shr (32 - 10))) + A;
  C := data2 + $2AD7D2BB + C + (A xor (D or not B));
  C := ((C shl 15) or (C shr (32 - 15))) + D;
  B := data9 + $EB86D391 + B + (D xor (C or not A));
  B := ((B shl 21) or (B shr (32 - 21))) + C;

  Fm_state[0] := Fm_state[0] + A;
  Fm_state[1] := Fm_state[1] + B;
  Fm_state[2] := Fm_state[2] + C;
  Fm_state[3] := Fm_state[3] + D;
end;

end.
