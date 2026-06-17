unit Blake3Vectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  HlpHashLibTypes,
  JsonVectorParser;

type
  TBlake3Vectors = class sealed
  strict private
    class var
      FXofCases: THashLibGenericArray<THashLibStringArray>;

    class function IsCuratedInputLen(AInputLen: Integer): Boolean; static;
    class procedure LoadCases; static;
  public
    class function GetXofCases: THashLibGenericArray<THashLibStringArray>; static;
    class constructor Create;
  end;

implementation

const
  Blake3RelativePath = 'Crypto/Blake3/test_vectors.json';
  CuratedInputLens: array[0..4] of Integer = (0, 1, 1023, 2048, 31744);

class function TBlake3Vectors.IsCuratedInputLen(AInputLen: Integer): Boolean;
var
  LI: Integer;
begin
  for LI := Low(CuratedInputLens) to High(CuratedInputLens) do
    if CuratedInputLens[LI] = AInputLen then
      Exit(True);
  Result := False;
end;

class procedure TBlake3Vectors.LoadCases;
var
  LDoc: TJsonVectorDocument;
  LCases: THashLibGenericArray<TJsonVectorObject>;
  LI, LOutIdx, LInputLen: Integer;
  LCaseObj: TJsonVectorObject;
begin
  LDoc := TJsonVectorDocument.LoadFile(Blake3RelativePath);
  try
    LCases := LDoc.Root.GetObjectArray('cases');
    try
      SetLength(FXofCases, Length(CuratedInputLens));
      LOutIdx := 0;
      for LI := 0 to High(LCases) do
      begin
        LCaseObj := LCases[LI];
        LInputLen := LCaseObj.GetInt('input_len');
        if not IsCuratedInputLen(LInputLen) then
          Continue;
        FXofCases[LOutIdx] := THashLibStringArray.Create(
          IntToStr(LInputLen),
          UpperCase(LCaseObj.GetString('hash')),
          UpperCase(LCaseObj.GetString('keyed_hash')),
          UpperCase(LCaseObj.GetString('derive_key')));
        Inc(LOutIdx);
      end;
      if LOutIdx <> Length(CuratedInputLens) then
        raise Exception.CreateFmt('Expected %d curated BLAKE3 cases, found %d in %s',
          [Length(CuratedInputLens), LOutIdx, Blake3RelativePath]);
    finally
      TJsonVectorObject.FreeOwnedArray(LCases);
    end;
  finally
    LDoc.Free;
  end;
end;

class function TBlake3Vectors.GetXofCases: THashLibGenericArray<THashLibStringArray>;
begin
  Result := FXofCases;
end;

class constructor TBlake3Vectors.Create;
begin
  LoadCases;
end;

end.
