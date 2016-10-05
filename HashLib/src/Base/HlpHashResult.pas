unit HlpHashResult;

{$I ..\Include\HashLib.inc}

interface

uses

{$IFDEF HAS_UNITSCOPE}
  System.SysUtils,
{$IFDEF DELPHIXE7_UP}
  System.NetEncoding,
{$ELSE}
  System.Classes,
  Soap.EncdDecd,
{$ENDIF DELPHIXE7_UP}
{$ELSE}
  SysUtils,
{$IFDEF DELPHI}
  Classes,
  EncdDecd,
{$ENDIF DELPHI}
{$IFDEF FPC}
  base64,
{$ENDIF FPC}
{$ENDIF HAS_UNITSCOPE}
  HlpBits,
  HlpHashLibTypes,
  HlpIHashResult,
  HlpConverters,
  HlpBitConverter;

resourcestring
  SImpossibleRepresentationInt32 =
    'Current Data Structure cannot be Represented as an "Int32" Type.';
  SImpossibleRepresentationUInt8 =
    'Current Data Structure cannot be Represented as an "UInt8" Type.';
  SImpossibleRepresentationUInt16 =
    'Current Data Structure cannot be Represented as an "UInt16" Type.';
  SImpossibleRepresentationUInt32 =
    'Current Data Structure cannot be Represented as an "UInt32" Type.';
  SImpossibleRepresentationUInt64 =
    'Current Data Structure cannot be Represented as an "UInt64" Type.';

type
  THashResult = class sealed(TInterfacedObject, IHashResult)

  strict private

    Fm_hash: THashLibByteArray;

  public

    constructor Create(a_hash: Int32); overload;
    constructor Create(a_hash: UInt8); overload;
    constructor Create(a_hash: UInt16); overload;
    constructor Create(a_hash: UInt32); overload;
    constructor Create(a_hash: UInt64); overload;
    constructor Create(a_hash: THashLibByteArray); overload;

    function GetBytes(): THashLibByteArray;
    function GetUInt8(): UInt8;
    function GetUInt16(): UInt16;
    function GetUInt32(): UInt32;
    function GetInt32(): Int32;
    function GetUInt64(): UInt64;
    function ToString(a_group: Boolean = false): String; reintroduce;
    function Equals(a_hashResult: IHashResult): Boolean; reintroduce;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    class function SameArrays(a_ar1, a_ar2: THashLibByteArray): Boolean;

  end;

implementation

{ THashResult }

constructor THashResult.Create(a_hash: UInt64);
begin
  a_hash := TBits.ReverseBytesUInt64(a_hash);
  Fm_hash := TBitConverter.GetBytes(a_hash);
end;

constructor THashResult.Create(a_hash: THashLibByteArray);
begin
  Fm_hash := a_hash;
end;

constructor THashResult.Create(a_hash: UInt32);
begin
  a_hash := TBits.ReverseBytesUInt32(a_hash);
  Fm_hash := TBitConverter.GetBytes(a_hash);
end;

constructor THashResult.Create(a_hash: UInt8);
begin
  Fm_hash := TBitConverter.GetBytes(a_hash);
end;

constructor THashResult.Create(a_hash: UInt16);
begin
  a_hash := TBits.ReverseBytesUInt16(a_hash);
  Fm_hash := TBitConverter.GetBytes(a_hash);
end;

constructor THashResult.Create(a_hash: Int32);
begin
  a_hash := TBits.ReverseBytesInt32(a_hash);
  Fm_hash := TBitConverter.GetBytes(a_hash);
end;

function THashResult.Equals(a_hashResult: IHashResult): Boolean;

begin
  result := THashResult.SameArrays(a_hashResult.GetBytes(), Fm_hash);
end;

function THashResult.GetBytes: THashLibByteArray;
begin
  result := Fm_hash;
end;

function THashResult.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}

var
  LResult: UInt32;
  I, Top: Int32;
  Temp: string;
{$IFDEF DELPHIXE7_UP}
  TempHolder: THashLibByteArray;
{$ELSE}
{$IFDEF DELPHI}
  TempHolder: TBytesStream;
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  TempHolder: String;
{$ENDIF FPC}
begin

{$IFDEF DELPHIXE7_UP}
  TempHolder := Self.Fm_hash;
{$ELSE}
{$IFDEF DELPHI}
  TempHolder := TBytesStream.Create(Self.Fm_hash);
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  TempHolder := EncodeStringBase64(TEncoding.UTF8.GetString(Self.Fm_hash));
{$ENDIF FPC}
{$IFDEF DELPHIXE7_UP}
  Temp := StringReplace(TNetEncoding.base64.EncodeBytesToString(TempHolder),
    sLineBreak, '', [rfReplaceAll]);
{$ELSE}
{$IFDEF DELPHI}
  try
    Temp := StringReplace(String(EncodeBase64(TempHolder.Memory,
      TempHolder.Size)), sLineBreak, '', [rfReplaceAll]);
  finally
    TempHolder.Free;
  end;
{$ENDIF DELPHI}
{$ENDIF DELPHIXE7_UP}
{$IFDEF FPC}
  Temp := TempHolder;
{$ENDIF FPC}
  Temp := AnsiUpperCase(Temp);

  LResult := 0;
{$IFDEF DELPHIXE3_UP}
  I := System.Low(Temp);
  Top := System.High(Temp);
{$ELSE}
  I := 1;
  Top := System.Length(Temp);
{$ENDIF DELPHIXE3_UP}
  while I <= Top do
  begin

    LResult := TBits.RotateLeft32(LResult, 5);
    LResult := LResult xor UInt32(Temp[I]);
    System.Inc(I);
  end;

  result := LResult;
end;

function THashResult.GetInt32: Int32;
begin
  if (System.Length(Fm_hash) <> 4) then
    raise EInvalidOperationException.CreateRes(@SImpossibleRepresentationInt32);

  result := TBitConverter.ToInt32(Fm_hash, 0);
  result := TBits.ReverseBytesInt32(result);
end;

function THashResult.GetUInt8: UInt8;
begin
  if (System.Length(Fm_hash) <> 1) then
    raise EInvalidOperationException.CreateRes(@SImpossibleRepresentationUInt8);

  result := TBitConverter.ToUInt8(Fm_hash, 0);
end;

function THashResult.GetUInt16: UInt16;
begin
  if (System.Length(Fm_hash) <> 2) then
    raise EInvalidOperationException.CreateRes
      (@SImpossibleRepresentationUInt16);

  result := TBitConverter.ToUInt16(Fm_hash, 0);
  result := TBits.ReverseBytesUInt16(result);
end;

function THashResult.GetUInt32: UInt32;
begin
  if (System.Length(Fm_hash) <> 4) then
    raise EInvalidOperationException.CreateRes
      (@SImpossibleRepresentationUInt32);

  result := TBitConverter.ToUInt32(Fm_hash, 0);
  result := TBits.ReverseBytesUInt32(result);
end;

function THashResult.GetUInt64: UInt64;
begin
  if (System.Length(Fm_hash) <> 8) then
    raise EInvalidOperationException.CreateRes
      (@SImpossibleRepresentationUInt64);

  result := TBitConverter.ToUInt64(Fm_hash, 0);
  result := TBits.ReverseBytesUInt64(result);
end;

class function THashResult.SameArrays(a_ar1, a_ar2: THashLibByteArray): Boolean;
begin
  if System.Length(a_ar1) <> System.Length(a_ar2) then
  begin
    result := false;
    Exit;
  end;

  result := CompareMem(Pointer(a_ar1), Pointer(a_ar2),
    System.Length(a_ar1) * System.SizeOf(Byte));

end;

function THashResult.ToString(a_group: Boolean): String;
begin
  result := TConverters.ConvertBytesToHexString(Fm_hash, a_group);
end;

end.
