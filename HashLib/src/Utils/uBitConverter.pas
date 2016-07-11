unit uBitConverter;

{$I ..\..\Include\HashLib.inc}

interface

uses
  uHashLibTypes;

type

  TBitConverter = class sealed(TObject)

  strict private

    class var

      FIsLittleEndian: Boolean;

    class function GetHexValue(i: Int32): Char; static; inline;
    class constructor BitConverter();

  public

    class property IsLittleEndian: Boolean read FIsLittleEndian;

    { ==================================================================== }

    class function GetBytes(value: Boolean): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Char): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Double): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Int16): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Int32): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Int64): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: Single): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: UInt8): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: UInt16): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: UInt32): THashLibByteArray; overload;
      static; inline;
    class function GetBytes(value: UInt64): THashLibByteArray; overload;
      static; inline;

    { ==================================================================== }

    class function ToBoolean(value: THashLibByteArray; StartIndex: Int32)
      : Boolean; static; inline;
    class function ToChar(value: THashLibByteArray; StartIndex: Int32): Char;
      static; inline;
    class function ToDouble(value: THashLibByteArray; StartIndex: Int32)
      : Double; static; inline;
    class function ToInt16(value: THashLibByteArray; StartIndex: Int32): Int16;
      static; inline;
    class function ToInt32(value: THashLibByteArray; StartIndex: Int32): Int32;
      static; inline;
    class function ToInt64(value: THashLibByteArray; StartIndex: Int32): Int64;
      static; inline;
    class function ToSingle(value: THashLibByteArray; StartIndex: Int32)
      : Single; static; inline;
    class function ToString(value: THashLibByteArray): String; reintroduce;
      overload; static;
    class function ToString(value: THashLibByteArray; StartIndex: Int32)
      : String; reintroduce; overload; static;
    class function ToString(value: THashLibByteArray;
      StartIndex, &Length: Int32): String; reintroduce; overload; static;
    class function ToUInt8(value: THashLibByteArray; StartIndex: Int32): UInt8;
      static; inline;
    class function ToUInt16(value: THashLibByteArray; StartIndex: Int32)
      : UInt16; static; inline;
    class function ToUInt32(value: THashLibByteArray; StartIndex: Int32)
      : UInt32; static; inline;
    class function ToUInt64(value: THashLibByteArray; StartIndex: Int32)
      : UInt64; static; inline;

  end;

implementation

{ TBitConverter }

class constructor TBitConverter.BitConverter;
var
  IntValue: Int32;
  PIIntValueAddress: PInteger;
  PBIntValueAddress: PByte;
  ByteValue: Byte;
begin
  IntValue := 1;
  PIIntValueAddress := @IntValue;
  PBIntValueAddress := PByte(PIIntValueAddress);
  ByteValue := PBIntValueAddress^;
  FIsLittleEndian := ByteValue = 1;
end;

{ ==================================================================== }

class function TBitConverter.GetBytes(value: Int16): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PSmallInt(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: Int32): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PInteger(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));

end;

class function TBitConverter.GetBytes(value: Double): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PDouble(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: Boolean): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PBoolean(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: Char): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PChar(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: UInt8): THashLibByteArray;
begin
  System.SetLength(result, System.SizeOf(value));
  PByte(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: UInt16): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PWord(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: Int64): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PInt64(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: Single): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PSingle(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: UInt32): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PCardinal(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

class function TBitConverter.GetBytes(value: UInt64): THashLibByteArray;
begin

  System.SetLength(result, System.SizeOf(value));
  PUInt64(@result[0])^ := value;
  // System.SetLength(result, System.SizeOf(value));
  // System.Move(value, result[0], System.SizeOf(value));
end;

{ ==================================================================== }

class function TBitConverter.GetHexValue(i: Int32): Char;
begin
  if i < 10 then
    result := Char(i + System.Ord('0'))
  else
    result := Char((i - 10) + System.Ord('A'));
end;

{ ==================================================================== }

class function TBitConverter.ToBoolean(value: THashLibByteArray;
  StartIndex: Int32): Boolean;
begin
  result := PBoolean(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));

end;

class function TBitConverter.ToChar(value: THashLibByteArray;
  StartIndex: Int32): Char;
begin
  result := PChar(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToDouble(value: THashLibByteArray;
  StartIndex: Int32): Double;
begin
  result := PDouble(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));

end;

class function TBitConverter.ToInt16(value: THashLibByteArray;
  StartIndex: Int32): Int16;
begin
  result := PSmallInt(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));

end;

class function TBitConverter.ToInt32(value: THashLibByteArray;
  StartIndex: Int32): Int32;
begin
  result := PInteger(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));

end;

class function TBitConverter.ToInt64(value: THashLibByteArray;
  StartIndex: Int32): Int64;
begin
  result := PInt64(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToSingle(value: THashLibByteArray;
  StartIndex: Int32): Single;
begin
  result := PSingle(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToString(value: THashLibByteArray): String;
var
  LowVal: Int32;
begin

{$IFDEF DELPHIXE2_UP}
  LowVal := System.Low(value);
{$ELSE}
  LowVal := 0;
{$ENDIF DELPHIXE2_UP}
  result := ToString(value, LowVal);
end;

class function TBitConverter.ToString(value: THashLibByteArray;
  StartIndex: Int32): String;
begin
  result := ToString(value, StartIndex, System.Length(value) - StartIndex);
end;

class function TBitConverter.ToString(value: THashLibByteArray;
  StartIndex, &Length: Int32): String;

var
  Idx, Index, chArrayLength, LowVal: Int32;
  chArray: THashLibCharArray;
  b: Byte;

begin
  result := '';

  chArrayLength := Length * 3;

  System.SetLength(chArray, chArrayLength);
  Idx := 0;
  Index := StartIndex;
  while Idx < chArrayLength do
  begin
    b := value[Index];
    System.Inc(Index);

    chArray[Idx] := GetHexValue(b div 16);
    chArray[Idx + 1] := GetHexValue(b mod 16);
    chArray[Idx + 2] := '-';

    System.Inc(Idx, 3);
  end;

{$IFDEF DELPHIXE2_UP}
  LowVal := System.Low(chArray);
{$ELSE}
  LowVal := 0;
{$ENDIF DELPHIXE2_UP}
  System.SetString(result, PChar(@chArray[LowVal]), System.Length(chArray) - 1);

end;

class function TBitConverter.ToUInt8(value: THashLibByteArray;
  StartIndex: Int32): UInt8;
begin
  result := PByte(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToUInt16(value: THashLibByteArray;
  StartIndex: Int32): UInt16;
begin
  result := PWord(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToUInt32(value: THashLibByteArray;
  StartIndex: Int32): UInt32;
begin
  result := PCardinal(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

class function TBitConverter.ToUInt64(value: THashLibByteArray;
  StartIndex: Int32): UInt64;
begin
  result := PUInt64(@value[StartIndex])^;
  // System.Move(value[StartIndex], result, System.SizeOf(result));
end;

end.
