unit uArrayExtensions;

{$I ..\..\Include\HashLib.inc}

interface

uses

{$IFDEF DELPHI}
{$IFNDEF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.TypInfo,
{$ELSE}
  TypInfo,
{$ENDIF HAS_UNITSCOPE}
{$ENDIF DELPHIXE7_UP}
{$ELSE}
  TypInfo,
{$ENDIF DELPHI}
{$IFDEF HAS_UNITSCOPE}
  System.SysUtils,
  System.Generics.Collections,
{$ELSE}
  SysUtils,
{$IFDEF DELPHI}
  Generics.Collections,
{$ENDIF DELPHI}
{$ENDIF HAS_UNITSCOPE}
  uHashLibTypes;

resourcestring
  SArgumentOutOfRange = 'Argument out of range';
  SSameArrays = 'Source and Destination arrays must not be the same';
  SArgumentOutOfRange2 =
    'Offset and length were out of bounds for the array or count is greater than the number of elements from index to the end of the source array.';

type

  THashLibArrayHelper<T> = class sealed({$IFDEF DELPHI} TArray {$ELSE} TObject
{$ENDIF DELPHI})

  strict private

    class procedure CheckArrays(Source, Destination: Pointer;
      SourceIndex, SourceLength, DestIndex, DestLength, Count: Int32);
      static; inline;

  public
    // "TArray.Copy<T>" is buggy in at least XE7 so I had to "lift" a fixed version
    // with some little modifications by me from http://stackoverflow.com/questions/27754399
    class procedure Copy(const Source: THashLibGenericArray<T>;
      SourceIndex: Int32; var Destination: THashLibGenericArray<T>;
      DestIndex: Int32; Count: Int32); static; inline;
    /// <summary>
    /// Clear array with specified value.
    /// </summary>
    /// <param name="a_array"></param>
    class procedure Clear(var a_array: THashLibGenericArray<T>; a_value: T);
      overload; static;
    /// <summary>
    /// Clear array with specified value.
    /// </summary>
    /// <param name="a_array"></param>
    class procedure Clear(var a_array: THashLibMatrixGenericArray<T>;
      a_value: T); overload; static;
    /// <summary>
    /// Return array started from a_index and with a_count length.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="a_array"></param>
    /// <param name="a_index"></param>
    /// <param name="a_count"></param>
    /// <returns></returns>
    class function SubArray(a_array: THashLibGenericArray<T>; a_index: Int32;
      a_count: Int32 = -1): THashLibGenericArray<T>; overload; static; inline;
    /// <summary>
    /// Return first occurence of a_sub_array in a_array.
    /// </summary>
    /// <param name="a_array"></param>
    /// <param name="a_sub_array"></param>
    /// <returns></returns>
    class function FindArrayInArray(a_array, a_sub_array: THashLibByteArray)
      : Int32; static;

  end;

implementation

{ THashLibArrayHelper }

class procedure THashLibArrayHelper<T>.CheckArrays(Source, Destination: Pointer;
  SourceIndex, SourceLength, DestIndex, DestLength, Count: Int32);
begin
  if (SourceIndex < 0) or (DestIndex < 0) or (SourceIndex >= SourceLength) or
    (DestIndex >= DestLength) or (SourceIndex + Count > SourceLength) or
    (DestIndex + Count > DestLength) then
    raise EArgumentOutOfRangeException.CreateRes(@SArgumentOutOfRange);
  if Source = Destination then
    raise EArgumentException.CreateRes(@SSameArrays);
end;

class procedure THashLibArrayHelper<T>.Copy(const Source
  : THashLibGenericArray<T>; SourceIndex: Int32;
  var Destination: THashLibGenericArray<T>; DestIndex: Int32; Count: Int32);
var
  ManagedType: Boolean;
{$IFNDEF DELPHIXE7_UP}
  localtypekind: TTypeKind;
{$ENDIF}
begin
  CheckArrays(Pointer(@Source[0]), Pointer(@Destination[0]), SourceIndex,
    Length(Source), DestIndex, Length(Destination), Count);
{$IFDEF DELPHIXE7_UP}
  ManagedType := System.IsManagedType(T);
{$ENDIF}
{$IFNDEF DELPHIXE7_UP}
  localtypekind := PTypeInfo(TypeInfo(T))^.Kind;
  case localtypekind of
    tkString, tkLString, tkWString, tkUString, tkVariant, tkArray, tkDynArray,
      tkRecord, tkInterface:
      ManagedType := true
  else
    ManagedType := false;
  end;
{$ENDIF}
  if ManagedType then
    System.CopyArray(Pointer(@Destination[DestIndex]),
      Pointer(@Source[SourceIndex]), TypeInfo(T), Count)
  else
    System.Move(Pointer(@Source[SourceIndex])^, Pointer(@Destination[DestIndex])
      ^, Count * System.SizeOf(T));
end;

class procedure THashLibArrayHelper<T>.Clear(var a_array
  : THashLibGenericArray<T>; a_value: T);
var
  Idx: Int32;
begin
  // Couldn't use FillChar with a "generic" value parameter, (at least in Delphi)
  // since Default(T) is not allowed as a Default Parameter for methods
  // so I had to use a "For" Loop.
  // FillChar(a_array, System.Length(a_array) * System.SizeOf(T), a_value);
  for Idx := 0 to System.Pred(System.Length(a_array)) do
  begin
    a_array[Idx] := a_value;
  end;

end;

class procedure THashLibArrayHelper<T>.Clear(var a_array
  : THashLibMatrixGenericArray<T>; a_value: T);
var
  x, y: Int32;
begin
  for x := 0 to System.Pred(System.Length(a_array)) do
  begin
    for y := 0 to System.Pred(System.Length(a_array[x])) do
    begin
      a_array[x, y] := a_value;
    end;

  end;

end;

class function THashLibArrayHelper<T>.SubArray(a_array: THashLibGenericArray<T>;
  a_index: Int32; a_count: Int32): THashLibGenericArray<T>;
begin
  if (a_count = -1) then
  begin
    a_count := System.Length(a_array) - a_index;
  end;

  System.SetLength(result, a_count);
  THashLibArrayHelper<T>.Copy(a_array, a_index, result, 0, a_count);

end;

class function THashLibArrayHelper<T>.FindArrayInArray(a_array,
  a_sub_array: THashLibByteArray): Int32;
var
  i, j: Int32;
begin
  j := 0;

  while j < (System.Length(a_array) - System.Length(a_sub_array)) do
  begin
    i := 0;
    while i < System.Length(a_sub_array) do
    begin
      if (a_array[j + i] <> a_sub_array[i]) then
      begin
        break;
      end;
      Inc(i);
    end;

    if (i = System.Length(a_sub_array)) then
    begin
      result := j;
      Exit;
    end;

    Inc(j);
  end;

  raise EArgumentOutOfRangeException.CreateRes(@SArgumentOutOfRange2);
end;

end.
