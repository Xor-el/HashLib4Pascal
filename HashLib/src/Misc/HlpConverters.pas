unit HlpConverters;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF FPC}
  StrUtils, // FPC needs StrUtils for BinToHex/HexToBin
{$ENDIF}
  Classes,
  SysUtils,
  HlpHashLibExceptions,
  HlpHashLibTypes;

resourcestring
  SAEncodingNilError = 'AEncoding cannot be nil';

type
  TConverters = class sealed(TObject)

  public

    class function ConvertStringToBytes(const AInput: String;
      const AEncoding: TEncoding): THashLibByteArray; overload; static;

    class function ConvertBytesToString(const AInput: THashLibByteArray;
      const AEncoding: TEncoding): String; overload; static;

    class function ConvertHexStringToBytes(const AInput: String)
      : THashLibByteArray; static; inline;

    class function ConvertBytesToHexString(const AInput: THashLibByteArray;
      AGroup: Boolean): String; static;

  end;

implementation

{ TConverters }

class function TConverters.ConvertBytesToHexString(const AInput
  : THashLibByteArray; AGroup: Boolean): String;
var
  LCount, LIdx: Int32;
  LHex: String;
  LPtrHex, LPtrResult: PChar;
begin
  LCount := System.Length(AInput);
  if LCount = 0 then
  begin
    Result := '';
    Exit;
  end;

  System.SetLength(LHex, LCount * 2);
  {$IFDEF FPC}StrUtils.{$ENDIF}BinToHex(@AInput[0], PChar(LHex), LCount);

  if (not AGroup) or (LCount <= 1) then
  begin
    Result := LHex;
    Exit;
  end;

  System.SetLength(Result, (LCount * 3) - 1);
  LPtrHex := PChar(LHex);
  LPtrResult := PChar(Result);
  for LIdx := 0 to LCount - 1 do
  begin
    LPtrResult^ := LPtrHex^;
    System.Inc(LPtrHex);
    System.Inc(LPtrResult);
    LPtrResult^ := LPtrHex^;
    System.Inc(LPtrHex);
    System.Inc(LPtrResult);
    if LIdx < (LCount - 1) then
    begin
      LPtrResult^ := '-';
      System.Inc(LPtrResult);
    end;
  end;
end;

class function TConverters.ConvertHexStringToBytes(const AInput: String)
  : THashLibByteArray;
var
  LInput: String;
begin
  LInput := AInput;
  LInput := StringReplace(LInput, '-', '', [rfIgnoreCase, rfReplaceAll]);

{$IFDEF DEBUG}
  System.Assert(System.Length(LInput) and 1 = 0);
{$ENDIF DEBUG}
  System.SetLength(Result, System.Length(LInput) shr 1);

  {$IFDEF FPC}StrUtils.{$ENDIF}HexToBin(PChar(LInput), @Result[0], System.Length(Result));
end;

class function TConverters.ConvertStringToBytes(const AInput: String;
  const AEncoding: TEncoding): THashLibByteArray;
begin
  if AEncoding = nil then
  begin
    raise EArgumentNilHashLibException.CreateRes(@SAEncodingNilError);
  end;

{$IFDEF FPC}
  Result := AEncoding.GetBytes(UnicodeString(AInput));
{$ELSE}
  Result := AEncoding.GetBytes(AInput);
{$ENDIF FPC}
end;

class function TConverters.ConvertBytesToString(const AInput: THashLibByteArray;
  const AEncoding: TEncoding): String;
begin
  if AEncoding = nil then
  begin
    raise EArgumentNilHashLibException.CreateRes(@SAEncodingNilError);
  end;

{$IFDEF FPC}
  Result := String(AEncoding.GetString(AInput));
{$ELSE}
  Result := AEncoding.GetString(AInput);
{$ENDIF FPC}
end;

end.
