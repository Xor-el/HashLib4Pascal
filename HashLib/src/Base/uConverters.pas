unit uConverters;

{$I ..\..\Include\HashLib.inc}

interface

uses
{$IFNDEF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.TypInfo,
{$ELSE}
  TypInfo,
{$ENDIF HAS_UNITSCOPE}
{$ENDIF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.Classes,
  System.SysUtils,
{$ELSE}
  Classes,
  SysUtils,
{$ENDIF HAS_UNITSCOPE}
  uHashLibTypes,
  uArrayExtensions,
  uBitConverter;

type
  TConverters = class sealed(TObject)

{$IFDEF DEBUG}
    // although the visibility level below is meant to be "strict private",
    // older versions of Delphi (2010 and XE) keeps complaining about some
    // unused methods even though this Hint is false.
  protected
{$IFDEF DELPHI2010}
    // To Bypass a Bug in Delphi 2010 Generics.
    class procedure Check(a_in: THashLibByteArray;
      a_in_size, a_out_size: Int32); overload; static;

    class procedure Check(a_in: THashLibByteArray;
      a_in_size, a_out_size, a_index, a_length: Int32); overload; static;

    class procedure Check(a_in: THashLibUInt32Array;
      a_in_size, a_out_size, a_index, a_length: Int32); overload; static;

    class procedure Check(a_in: THashLibUInt64Array;
      a_in_size, a_out_size, a_index, a_length: Int32); overload; static;

    class procedure Check(a_in: THashLibByteArray; a_in_size: Int32;
      a_result: THashLibUInt32Array; a_out_size, a_index_in, a_length,
      a_index_out: Int32); overload; static;

    class procedure Check(a_in: THashLibByteArray; a_in_size: Int32;
      a_result: THashLibUInt64Array; a_out_size, a_index_in, a_length,
      a_index_out: Int32); overload; static;

{$ELSE}
    class procedure Check<I>(a_in: TArray<I>; a_in_size, a_out_size: Int32);
      overload; static;

    class procedure Check<I>(a_in: TArray<I>; a_in_size, a_out_size, a_index,
      a_length: Int32); overload; static;

    class procedure Check<I, O>(a_in: TArray<I>; a_in_size: Int32;
      a_result: TArray<O>; a_out_size, a_index_in, a_length,
      a_index_out: Int32); overload; static;
{$ENDIF DELPHI2010}
{$ENDIF}
  public

    class function ConvertBytesToUInt32(a_in: THashLibByteArray;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibUInt32Array;
      overload; static;

    class procedure ConvertBytesToUInt32(a_in: THashLibByteArray;
      a_index: Int32; a_length: Int32; a_out: THashLibUInt32Array);
      overload; static;

    class function ConvertBytesToUInt64(a_in: THashLibByteArray;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibUInt64Array;
      overload; static;

    class procedure ConvertBytesToUInt64(a_in: THashLibByteArray;
      a_index_in: Int32; a_length: Int32; a_out: THashLibUInt64Array;
      a_index_out: Int32); overload; static;

    class function ConvertBytesToUInt32SwapOrder(a_in: THashLibByteArray;
      a_index, a_length: Int32): THashLibUInt32Array; overload; static;

    class procedure ConvertBytesToUInt32SwapOrder(a_in: THashLibByteArray;
      a_index: Int32; a_length: Int32; a_result: THashLibUInt32Array;
      a_index_out: Int32); overload; static;

    class function ConvertBytesToUInt64SwapOrder(a_in: THashLibByteArray;
      a_index: Int32): UInt64; overload; static;

    // In order to bypass a compiler error of "Ambiguous overloaded call",
    // I had to rename this method to "ConvertBytesToUInt64a2" where "a2" means
    // that only a maximum of 2 arguments are accepted by the method.
    class function ConvertBytesToUInt64a2(a_in: THashLibByteArray;
      a_index: Int32 = 0): UInt64; overload; static; inline;

    class function ConvertBytesToUInt32SwapOrder(a_in: THashLibByteArray;
      a_index: Int32): UInt32; overload; static;

    // In order to bypass a compiler error of "Ambiguous overloaded call",
    // I had to rename this method to "ConvertBytesToUInt32a2" where "a2" means
    // that only a maximum of 2 arguments are accepted by the method.
    class function ConvertBytesToUInt32a2(a_in: THashLibByteArray;
      a_index: Int32 = 0): UInt32; static; inline;

    class function ConvertBytesToUInt64SwapOrder(a_in: THashLibByteArray;
      a_index, a_length: Int32): THashLibUInt64Array; overload; static;

    class procedure ConvertBytesToUInt64SwapOrder(a_in: THashLibByteArray;
      a_index, a_length: Int32; a_out: THashLibUInt64Array); overload; static;

    class function ConvertUInt32ToBytesSwapOrder(a_in: THashLibUInt32Array;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibByteArray; static;

    class function ConvertUInt32ToBytes(a_in: THashLibUInt32Array;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibByteArray;
      overload; static;

    class function ConvertUInt64ToBytes(a_in: THashLibUInt64Array;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibByteArray;
      overload; static;

    class function ConvertUInt64ToBytesSwapOrder(a_in: THashLibUInt64Array;
      a_index: Int32 = 0; a_length: Int32 = -1): THashLibByteArray;
      overload; static;

    class function ConvertUInt8ToBytes(a_in: UInt8): THashLibByteArray;
      overload; static;

    class function ConvertUInt16ToBytes(a_in: UInt16): THashLibByteArray;
      overload; static;

    class function ConvertUInt32ToBytes(a_in: UInt32): THashLibByteArray;
      overload; static;

    class procedure ConvertUInt8ToBytes(a_in: UInt8; a_out: THashLibByteArray;
      a_index: Int32); overload; static;

    class procedure ConvertUInt16ToBytes(a_in: UInt16; a_out: THashLibByteArray;
      a_index: Int32); overload; static;

    class procedure ConvertUInt32ToBytes(a_in: UInt32; a_out: THashLibByteArray;
      a_index: Int32); overload; static;

    class function ConvertUInt64ToBytes(a_in: UInt64): THashLibByteArray;
      overload; static;

    class procedure ConvertUInt64ToBytes(a_in: UInt64; a_out: THashLibByteArray;
      a_index: Int32); overload; static;

    class procedure ConvertUInt64ToBytesSwapOrder(a_in: UInt64;
      a_out: THashLibByteArray; a_index: Int32); overload; static;

    class function ConvertStringToBytes(const a_in: String;
      a_encoding: TEncoding): THashLibByteArray; overload; static;

    class function ConvertHexStringToBytes(a_in: String)
      : THashLibByteArray; static;

    class function ConvertBytesToHexString(a_in: THashLibByteArray;
      a_group: Boolean): String; static;

  end;

implementation

{ TConverters }

{$IFDEF DEBUG}
{$IFDEF DELPHI2010}

class procedure TConverters.Check(a_in: THashLibByteArray; a_in_size: Int32;
  a_result: THashLibUInt32Array; a_out_size, a_index_in, a_length,
  a_index_out: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0);

  System.Assert(a_index_in >= 0);

  if (a_length > 0) then
    System.Assert(a_index_in < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index_in + a_length) <= System.Length(a_in));
  System.Assert((a_index_in + a_length) <= System.Length(a_in));

  System.Assert((a_index_out + System.Length(a_result)) >=
    (a_length div a_out_size));
end;

class procedure TConverters.Check(a_in: THashLibByteArray; a_in_size: Int32;
  a_result: THashLibUInt64Array; a_out_size, a_index_in, a_length,
  a_index_out: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0);

  System.Assert(a_index_in >= 0);

  if (a_length > 0) then
    System.Assert(a_index_in < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index_in + a_length) <= System.Length(a_in));
  System.Assert((a_index_in + a_length) <= System.Length(a_in));

  System.Assert((a_index_out + System.Length(a_result)) >=
    (a_length div a_out_size));
end;

class procedure TConverters.Check(a_in: THashLibByteArray;
  a_in_size, a_out_size: Int32);
begin
  System.Assert(((System.Length(a_in) * a_in_size) mod a_out_size) = 0);
end;

class procedure TConverters.Check(a_in: THashLibByteArray;
  a_in_size, a_out_size, a_index, a_length: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0)
  else
    System.Assert((a_in_size mod a_out_size) = 0);

  System.Assert(a_index >= 0);

  if (a_length > 0) then
    System.Assert(a_index < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index + a_length) <= System.Length(a_in));
  System.Assert((a_index + a_length) <= System.Length(a_in));
end;

class procedure TConverters.Check(a_in: THashLibUInt32Array;
  a_in_size, a_out_size, a_index, a_length: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0)
  else
    System.Assert((a_in_size mod a_out_size) = 0);

  System.Assert(a_index >= 0);

  if (a_length > 0) then
    System.Assert(a_index < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index + a_length) <= System.Length(a_in));
  System.Assert((a_index + a_length) <= System.Length(a_in));
end;

class procedure TConverters.Check(a_in: THashLibUInt64Array;
  a_in_size, a_out_size, a_index, a_length: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0)
  else
    System.Assert((a_in_size mod a_out_size) = 0);

  System.Assert(a_index >= 0);

  if (a_length > 0) then
    System.Assert(a_index < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index + a_length) <= System.Length(a_in));
  System.Assert((a_index + a_length) <= System.Length(a_in));
end;

{$ELSE}

class procedure TConverters.Check<I, O>(a_in: TArray<I>; a_in_size: Int32;
  a_result: TArray<O>; a_out_size, a_index_in, a_length, a_index_out: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0);

  System.Assert(a_index_in >= 0);

  if (a_length > 0) then
    System.Assert(a_index_in < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index_in + a_length) <= System.Length(a_in));
  System.Assert((a_index_in + a_length) <= System.Length(a_in));

  System.Assert((a_index_out + System.Length(a_result)) >=
    (a_length div a_out_size));
end;

class procedure TConverters.Check<I>(a_in: TArray<I>;
  a_in_size, a_out_size: Int32);
begin
  System.Assert(((System.Length(a_in) * a_in_size) mod a_out_size) = 0);
end;

class procedure TConverters.Check<I>(a_in: TArray<I>;
  a_in_size, a_out_size, a_index, a_length: Int32);
begin
  System.Assert(((a_length * a_in_size) mod a_out_size) = 0);

  if (a_out_size > a_in_size) then
    System.Assert((a_length mod (a_out_size div a_in_size)) = 0)
  else
    System.Assert((a_in_size mod a_out_size) = 0);

  System.Assert(a_index >= 0);

  if (a_length > 0) then
    System.Assert(a_index < System.Length(a_in));

  System.Assert(a_length >= 0);
  System.Assert((a_index + a_length) <= System.Length(a_in));
  System.Assert((a_index + a_length) <= System.Length(a_in));
end;

{$ENDIF DELPHI2010}
{$ENDIF}

class function TConverters.ConvertBytesToHexString(a_in: THashLibByteArray;
  a_group: Boolean): String;
var
  I, LowVal: Int32;
  hex, StrtoProcess: String;
  ar: THashLibStringArray;
  StringList: TStringList;
begin

  hex := AnsiUpperCase(TBitConverter.ToString(a_in));

  if System.Length(a_in) = 1 then
  begin
    result := hex;
    Exit;
  end;

  if System.Length(a_in) = 2 then
  begin
    result := StringReplace(hex, '-', '', [rfIgnoreCase, rfReplaceAll]);
    Exit;
  end;

  if (a_group) then
  begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
    Check(a_in, 1, 4);
{$ELSE}
    Check<Byte>(a_in, 1, 4);
{$ENDIF DELPHI2010}
{$ENDIF}
    StringList := TStringList.Create();
    StringList.StrictDelimiter := True;
    try
      StrtoProcess := AnsiUpperCase(TBitConverter.ToString(a_in));
      StringList.Delimiter := '-';
      StringList.DelimitedText := StrtoProcess;
      System.SetLength(ar, StringList.Count);
      for LowVal := 0 to StringList.Count - 1 do
        ar[LowVal] := StringList.Strings[LowVal];
    finally
      StringList.Free;
    end;

    hex := '';
    I := 0;
    while I < (System.Length(ar) div 4) do
    begin
      if (I <> 0) then
        hex := hex + '-';
      hex := hex + ar[I * 4] + ar[I * 4 + 1] + ar[I * 4 + 2] + ar[I * 4 + 3];

      System.Inc(I);
    end;

  end
  else
  begin
    hex := StringReplace(hex, '-', '', [rfIgnoreCase, rfReplaceAll]);
  end;
  result := hex;
end;

class function TConverters.ConvertBytesToUInt32(a_in: THashLibByteArray;
  a_index, a_length: Int32): THashLibUInt32Array;
begin
  if (a_length = -1) then
    a_length := System.Length(a_in);
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 4, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 4, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length div 4);

  ConvertBytesToUInt32(a_in, a_index, a_length, result);

end;

class procedure TConverters.ConvertBytesToUInt32(a_in: THashLibByteArray;
  a_index, a_length: Int32; a_out: THashLibUInt32Array);
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 4, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 4, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.Move(a_in[a_index], a_out[0], a_length);
end;

class function TConverters.ConvertBytesToUInt32a2(a_in: THashLibByteArray;
  a_index: Int32): UInt32;
var
  u1, u2, u3, u4: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_index + 4 <= System.Length(a_in));
{$ENDIF}
  u1 := (UInt32(a_in[a_index]));
  System.Inc(a_index);
  u2 := (UInt32(a_in[a_index]) shl 8);
  System.Inc(a_index);
  u3 := (UInt32(a_in[a_index]) shl 16);
  System.Inc(a_index);
  u4 := (UInt32(a_in[a_index]) shl 24);

  result := u1 or u2 or u3 or u4;

end;

class function TConverters.ConvertBytesToUInt32SwapOrder
  (a_in: THashLibByteArray; a_index: Int32): UInt32;
var
  u1, u2, u3: UInt32;
  b1: Byte;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_index + 4 <= System.Length(a_in));
{$ENDIF}
  u1 := (UInt32(a_in[a_index]) shl 24);
  System.Inc(a_index);
  u2 := (UInt32(a_in[a_index]) shl 16);
  System.Inc(a_index);
  u3 := (UInt32(a_in[a_index]) shl 8);
  System.Inc(a_index);
  b1 := (a_in[a_index]);
  result := u1 or u2 or u3 or b1;

end;

class procedure TConverters.ConvertBytesToUInt32SwapOrder
  (a_in: THashLibByteArray; a_index, a_length: Int32;
  a_result: THashLibUInt32Array; a_index_out: Int32);
var
  I: Int32;
  u1, u2, u3: UInt32;
  b1: Byte;
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, a_result, 4, a_index, a_length, a_index_out);
{$ELSE}
  Check<Byte, UInt32>(a_in, 1, a_result, 4, a_index, a_length, a_index_out);
{$ENDIF DELPHI2010}
{$ENDIF}
  I := a_index_out;
  while a_length > 0 do
  begin
    u1 := (UInt32(a_in[a_index]) shl 24);
    System.Inc(a_index);
    u2 := (UInt32(a_in[a_index]) shl 16);
    System.Inc(a_index);
    u3 := (UInt32(a_in[a_index]) shl 8);
    System.Inc(a_index);
    b1 := (a_in[a_index]);
    System.Inc(a_index);
    a_result[I] := u1 or u2 or u3 or b1;

    System.Inc(I);

    System.Dec(a_length, 4);
  end;

end;

class function TConverters.ConvertBytesToUInt32SwapOrder
  (a_in: THashLibByteArray; a_index, a_length: Int32): THashLibUInt32Array;
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 4, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 4, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length div 4);
  ConvertBytesToUInt32SwapOrder(a_in, a_index, a_length, result, 0);
end;

class function TConverters.ConvertBytesToUInt64a2(a_in: THashLibByteArray;
  a_index: Int32): UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_index + 8 <= System.Length(a_in));
{$ENDIF}
  result := TBitConverter.ToUInt64(a_in, a_index);
end;

class function TConverters.ConvertBytesToUInt64(a_in: THashLibByteArray;
  a_index, a_length: Int32): THashLibUInt64Array;
begin
  if (a_length = -1) then
    a_length := System.Length(a_in);

{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 8, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 8, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length div 8);
  ConvertBytesToUInt64(a_in, a_index, a_length, result, 0);

end;

class procedure TConverters.ConvertBytesToUInt64(a_in: THashLibByteArray;
  a_index_in, a_length: Int32; a_out: THashLibUInt64Array; a_index_out: Int32);
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, a_out, 8, a_index_in, a_length, a_index_out);
{$ELSE}
  Check<Byte, UInt64>(a_in, 1, a_out, 8, a_index_in, a_length, a_index_out);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.Move(a_in[a_index_in], a_out[a_index_out * 8], a_length);
end;

class function TConverters.ConvertBytesToUInt64SwapOrder
  (a_in: THashLibByteArray; a_index, a_length: Int32): THashLibUInt64Array;
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 8, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 8, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length div 8);
  ConvertBytesToUInt64SwapOrder(a_in, a_index, a_length, result);
end;

class procedure TConverters.ConvertBytesToUInt64SwapOrder
  (a_in: THashLibByteArray; a_index, a_length: Int32;
  a_out: THashLibUInt64Array);
var
  I: Int32;
  u1, u2, u3, u4, u5, u6, u7, u8: UInt64;
begin
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 1, 8, a_index, a_length);
{$ELSE}
  Check<Byte>(a_in, 1, 8, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  I := 0;
  while a_length > 0 do
  begin
    u1 := (UInt64(a_in[a_index]) shl 56);
    System.Inc(a_index);
    u2 := (UInt64(a_in[a_index]) shl 48);
    System.Inc(a_index);
    u3 := (UInt64(a_in[a_index]) shl 40);
    System.Inc(a_index);
    u4 := (UInt64(a_in[a_index]) shl 32);
    System.Inc(a_index);
    u5 := (UInt64(a_in[a_index]) shl 24);
    System.Inc(a_index);
    u6 := (UInt64(a_in[a_index]) shl 16);
    System.Inc(a_index);
    u7 := (UInt64(a_in[a_index]) shl 8);
    System.Inc(a_index);
    u8 := (UInt64(a_in[a_index]));
    System.Inc(a_index);
    a_out[I] := u1 or u2 or u3 or u4 or u5 or u6 or u7 or u8;

    System.Inc(I);

    System.Dec(a_length, 8);
  end;

end;

class function TConverters.ConvertBytesToUInt64SwapOrder
  (a_in: THashLibByteArray; a_index: Int32): UInt64;
var
  u1, u2, u3, u4, u5, u6, u7: UInt64;
  b1: Byte;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_index + 8 <= System.Length(a_in));
{$ENDIF}
  u1 := (UInt64(a_in[a_index]) shl 56);
  System.Inc(a_index);
  u2 := (UInt64(a_in[a_index]) shl 48);
  System.Inc(a_index);
  u3 := (UInt64(a_in[a_index]) shl 40);
  System.Inc(a_index);
  u4 := (UInt64(a_in[a_index]) shl 32);
  System.Inc(a_index);
  u5 := (UInt64(a_in[a_index]) shl 24);
  System.Inc(a_index);
  u6 := (UInt64(a_in[a_index]) shl 16);
  System.Inc(a_index);
  u7 := (UInt64(a_in[a_index]) shl 8);
  System.Inc(a_index);
  b1 := (a_in[a_index]);
  result := u1 or u2 or u3 or u4 or u5 or u6 or u7 or b1;

end;

class function TConverters.ConvertHexStringToBytes(a_in: String)
  : THashLibByteArray;
begin
  a_in := StringReplace(a_in, '-', '', [rfIgnoreCase, rfReplaceAll]);

{$IFDEF DEBUG}
  System.Assert(System.Length(a_in) mod 2 = 0);
{$ENDIF}
  System.SetLength(result, System.Length(a_in) div 2);
  HexToBin(PChar(a_in), @result[0], System.Length(result));

end;

{$WARNINGS OFF}

class function TConverters.ConvertStringToBytes(const a_in: String;
  a_encoding: TEncoding): THashLibByteArray;
begin
  result := a_encoding.GetBytes(a_in);
end;
{$WARNINGS ON}

class procedure TConverters.ConvertUInt8ToBytes(a_in: UInt8;
  a_out: THashLibByteArray; a_index: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(a_index + 1 <= System.Length(a_out));
{$ENDIF}
  THashLibArrayHelper<Byte>.Copy
    (THashLibGenericArray<Byte>(TBitConverter.GetBytes(a_in)), 0,
    THashLibGenericArray<Byte>(a_out), a_index, 1);
end;

class procedure TConverters.ConvertUInt16ToBytes(a_in: UInt16;
  a_out: THashLibByteArray; a_index: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(a_index + 2 <= System.Length(a_out));
{$ENDIF}
  THashLibArrayHelper<Byte>.Copy
    (THashLibGenericArray<Byte>(TBitConverter.GetBytes(a_in)), 0,
    THashLibGenericArray<Byte>(a_out), a_index, 2);
end;

class procedure TConverters.ConvertUInt32ToBytes(a_in: UInt32;
  a_out: THashLibByteArray; a_index: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(a_index + 4 <= System.Length(a_out));
{$ENDIF}
  THashLibArrayHelper<Byte>.Copy
    (THashLibGenericArray<Byte>(TBitConverter.GetBytes(a_in)), 0,
    THashLibGenericArray<Byte>(a_out), a_index, 4);
end;

class function TConverters.ConvertUInt8ToBytes(a_in: UInt8): THashLibByteArray;
begin
  System.SetLength(result, 1);
  ConvertUInt8ToBytes(a_in, result, 0);
end;

class function TConverters.ConvertUInt16ToBytes(a_in: UInt16)
  : THashLibByteArray;
begin
  System.SetLength(result, 2);
  ConvertUInt16ToBytes(a_in, result, 0);
end;

class function TConverters.ConvertUInt32ToBytes(a_in: UInt32)
  : THashLibByteArray;
begin
  System.SetLength(result, 4);
  ConvertUInt32ToBytes(a_in, result, 0);
end;

class function TConverters.ConvertUInt32ToBytes(a_in: THashLibUInt32Array;
  a_index, a_length: Int32): THashLibByteArray;
begin
  if (a_length = -1) then
    a_length := System.Length(a_in);

{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 4, 1, a_index, a_length);
{$ELSE}
  Check<UInt32>(a_in, 4, 1, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length * 4);
  System.Move(a_in[a_index], result[0], a_length * System.SizeOf(UInt32));
end;

class function TConverters.ConvertUInt32ToBytesSwapOrder
  (a_in: THashLibUInt32Array; a_index, a_length: Int32): THashLibByteArray;
var
  j: Int32;
begin
  if (a_length = -1) then
    a_length := System.Length(a_in);
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 4, 1, a_index, a_length);
{$ELSE}
  Check<UInt32>(a_in, 4, 1, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length * 4);
  j := 0;
  while a_length > 0 do
  begin

    result[j] := Byte(a_in[a_index] shr 24);
    System.Inc(j);
    result[j] := Byte(a_in[a_index] shr 16);
    System.Inc(j);
    result[j] := Byte(a_in[a_index] shr 8);
    System.Inc(j);
    result[j] := Byte(a_in[a_index]);
    System.Inc(j);

    System.Dec(a_length);
    System.Inc(a_index);
  end;
end;

class function TConverters.ConvertUInt64ToBytes(a_in: THashLibUInt64Array;
  a_index, a_length: Int32): THashLibByteArray;
begin

  if (a_length = -1) then
    a_length := System.Length(a_in);

{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 8, 1, a_index, a_length);
{$ELSE}
  Check<UInt64>(a_in, 8, 1, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length * 8);
  System.Move(a_in[a_index], result[0], a_length * System.SizeOf(UInt64));
end;

class procedure TConverters.ConvertUInt64ToBytes(a_in: UInt64;
  a_out: THashLibByteArray; a_index: Int32);
begin
  System.Assert(a_index + 8 <= System.Length(a_out));
  THashLibArrayHelper<Byte>.Copy
    (THashLibGenericArray<Byte>(TBitConverter.GetBytes(a_in)), 0,
    THashLibGenericArray<Byte>(a_out), a_index, 8);
end;

class function TConverters.ConvertUInt64ToBytes(a_in: UInt64)
  : THashLibByteArray;
begin
  System.SetLength(result, 8);
  ConvertUInt64ToBytes(a_in, result, 0);
end;

class function TConverters.ConvertUInt64ToBytesSwapOrder
  (a_in: THashLibUInt64Array; a_index, a_length: Int32): THashLibByteArray;
var
  j: Int32;
begin
  if (a_length = -1) then
    a_length := System.Length(a_in);
{$IFDEF DEBUG}
{$IFDEF DELPHI2010}
  Check(a_in, 8, 1, a_index, a_length);
{$ELSE}
  Check<UInt64>(a_in, 8, 1, a_index, a_length);
{$ENDIF DELPHI2010}
{$ENDIF}
  System.SetLength(result, a_length * 8);
  j := 0;
  while a_length > 0 do
  begin
    result[j] := (Byte(a_in[a_index] shr 56));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 48));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 40));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 32));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 24));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 16));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index] shr 8));
    System.Inc(j);
    result[j] := (Byte(a_in[a_index]));
    System.Inc(j);

    System.Dec(a_length);
    System.Inc(a_index);
  end;
end;

class procedure TConverters.ConvertUInt64ToBytesSwapOrder(a_in: UInt64;
  a_out: THashLibByteArray; a_index: Int32);
begin

{$IFDEF DEBUG}
  System.Assert(a_index + 8 <= System.Length(a_out));
{$ENDIF}
  a_out[a_index] := (Byte(a_in shr 56));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 48));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 40));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 32));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 24));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 16));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in shr 8));
  System.Inc(a_index);
  a_out[a_index] := (Byte(a_in));

end;

end.
