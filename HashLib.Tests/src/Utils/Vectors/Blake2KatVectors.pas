unit Blake2KatVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpjson,
  jsonparser,
{$ELSE}
  System.JSON,
{$ENDIF FPC}
  HlpHashLibTypes,
  HashLibTestResourceLoader;

type
  TBlake2KatAlgorithm = (Blake2B, Blake2S, Blake2BP, Blake2SP);

  TBlake2KatEntry = record
    HashName: string;
    InputHex: string;
    KeyHex: string;
    OutputHex: string;
  end;

  TBlake2KatVectors = class sealed
  strict private
    class var
      FEntries: THashLibGenericArray<TBlake2KatEntry>;
      FUnkeyedBlake2B, FKeyedBlake2B: THashLibStringArray;
      FUnkeyedBlake2S, FKeyedBlake2S: THashLibStringArray;
      FUnkeyedBlake2BP, FKeyedBlake2BP: THashLibStringArray;
      FUnkeyedBlake2SP, FKeyedBlake2SP: THashLibStringArray;
      FBlake2XsXofCases, FBlake2XbXofCases: THashLibGenericArray<THashLibStringArray>;
      FBlake2XsXofInputHex, FBlake2XbXofInputHex: string;

    class function HashNameForAlgorithm(AAlgo: TBlake2KatAlgorithm): string; static;
    class function ReadJsonString(AObj: TJSONObject; const AName: string): string; static;
    class procedure LoadEntries; static;
    class function BuildLengthIndexedDigests(const AHashName: string;
      AKeyed: Boolean): THashLibStringArray; static;
    class function BuildXofCases(const AHashName: string)
      : THashLibGenericArray<THashLibStringArray>; static;
    class function FindXofInputHex(const AHashName: string): string; static;
  public
    class function GetUnkeyedDigests(AAlgo: TBlake2KatAlgorithm): THashLibStringArray; static;
    class function GetKeyedDigests(AAlgo: TBlake2KatAlgorithm): THashLibStringArray; static;
    class function GetBlake2XsXofCases: THashLibGenericArray<THashLibStringArray>; static;
    class function GetBlake2XbXofCases: THashLibGenericArray<THashLibStringArray>; static;
    class function GetBlake2XsXofInputHex: string; static;
    class function GetBlake2XbXofInputHex: string; static;
    class constructor Create;
  end;

implementation

const
  Blake2KatRelativePath = 'Crypto/Blake2/blake2-kat.json';

class function TBlake2KatVectors.HashNameForAlgorithm(AAlgo: TBlake2KatAlgorithm): string;
begin
  case AAlgo of
    Blake2B: Result := 'blake2b';
    Blake2S: Result := 'blake2s';
    Blake2BP: Result := 'blake2bp';
    Blake2SP: Result := 'blake2sp';
  else
    raise Exception.Create('Unknown Blake2 KAT algorithm');
  end;
end;

class function TBlake2KatVectors.ReadJsonString(AObj: TJSONObject;
  const AName: string): string;
var
{$IFDEF FPC}
  LNode: TJSONData;
{$ELSE}
  LNode: TJSONValue;
{$ENDIF FPC}
begin
  Result := '';
  if AObj = nil then
    Exit;
{$IFDEF FPC}
  LNode := AObj.Find(AName);
  if (LNode = nil) or (LNode.JSONType = TJSONType.jtNull) then
    Exit;
  Result := LNode.AsString;
{$ELSE}
  LNode := AObj.GetValue(AName);
  if (LNode = nil) or (LNode is TJSONNull) then
    Exit;
  Result := LNode.Value;
{$ENDIF FPC}
end;

class procedure TBlake2KatVectors.LoadEntries;
var
  LContent: string;
  LRoot: TJSONArray;
{$IFDEF FPC}
  LRootOwner: TJSONData;
{$ELSE}
  LRootOwner: TJSONValue;
{$ENDIF FPC}
  LI: Integer;
  LObj: TJSONObject;
  LEntry: TBlake2KatEntry;
begin
  LContent := THashLibTestResourceLoader.Instance.LoadAsString(Blake2KatRelativePath);
{$IFDEF FPC}
  LRootOwner := GetJSON(LContent);
  if not (LRootOwner is TJSONArray) then
  begin
    LRootOwner.Free;
    raise Exception.Create('blake2-kat.json root must be an array');
  end;
  LRoot := TJSONArray(LRootOwner);
{$ELSE}
  LRootOwner := TJSONObject.ParseJSONValue(LContent);
  if not (LRootOwner is TJSONArray) then
  begin
    LRootOwner.Free;
    raise Exception.Create('blake2-kat.json root must be an array');
  end;
  LRoot := TJSONArray(LRootOwner);
{$ENDIF FPC}
  try
    SetLength(FEntries, LRoot.Count);
    for LI := 0 to LRoot.Count - 1 do
    begin
      if not (LRoot.Items[LI] is TJSONObject) then
        raise Exception.CreateFmt('blake2-kat.json entry %d is not an object', [LI]);
      LObj := TJSONObject(LRoot.Items[LI]);
      LEntry.HashName := LowerCase(ReadJsonString(LObj, 'hash'));
      LEntry.InputHex := ReadJsonString(LObj, 'in');
      LEntry.KeyHex := ReadJsonString(LObj, 'key');
      LEntry.OutputHex := UpperCase(ReadJsonString(LObj, 'out'));
      FEntries[LI] := LEntry;
    end;
  finally
    LRootOwner.Free;
  end;
end;

class function TBlake2KatVectors.BuildLengthIndexedDigests(const AHashName: string;
  AKeyed: Boolean): THashLibStringArray;
var
  LI, LInputLen, LMaxLen, LIndex: Integer;
  LEntry: TBlake2KatEntry;
begin
  LMaxLen := -1;
  for LI := 0 to High(FEntries) do
  begin
    LEntry := FEntries[LI];
    if LEntry.HashName <> AHashName then
      Continue;
    if AKeyed then
    begin
      if LEntry.KeyHex = '' then
        Continue;
    end
    else if LEntry.KeyHex <> '' then
      Continue;

    LInputLen := Length(LEntry.InputHex) shr 1;
    if LInputLen > LMaxLen then
      LMaxLen := LInputLen;
  end;

  if LMaxLen < 0 then
    Exit(nil);

  SetLength(Result, LMaxLen + 1);
  for LI := 0 to High(FEntries) do
  begin
    LEntry := FEntries[LI];
    if LEntry.HashName <> AHashName then
      Continue;
    if AKeyed then
    begin
      if LEntry.KeyHex = '' then
        Continue;
    end
    else if LEntry.KeyHex <> '' then
      Continue;

    LIndex := Length(LEntry.InputHex) shr 1;
    Result[LIndex] := LEntry.OutputHex;
  end;
end;

class function TBlake2KatVectors.BuildXofCases(const AHashName: string)
  : THashLibGenericArray<THashLibStringArray>;
var
  LI, LCount, LOutLen: Integer;
  LEntry: TBlake2KatEntry;
  LTemp: array of record
    OutLen: Integer;
    KeyHex: string;
    OutputHex: string;
  end;
begin
  SetLength(LTemp, 0);
  for LI := 0 to High(FEntries) do
  begin
    LEntry := FEntries[LI];
    if (LEntry.HashName <> AHashName) or (LEntry.KeyHex <> '') then
      Continue;
    LOutLen := Length(LEntry.OutputHex) shr 1;
    SetLength(LTemp, Length(LTemp) + 1);
    LTemp[High(LTemp)].OutLen := LOutLen;
    LTemp[High(LTemp)].KeyHex := LEntry.KeyHex;
    LTemp[High(LTemp)].OutputHex := LEntry.OutputHex;
  end;

  for LI := 0 to High(LTemp) - 1 do
  begin
    for LCount := LI + 1 to High(LTemp) do
    begin
      if LTemp[LCount].OutLen < LTemp[LI].OutLen then
      begin
        LOutLen := LTemp[LI].OutLen;
        LEntry.KeyHex := LTemp[LI].KeyHex;
        LEntry.OutputHex := LTemp[LI].OutputHex;
        LTemp[LI].OutLen := LTemp[LCount].OutLen;
        LTemp[LI].KeyHex := LTemp[LCount].KeyHex;
        LTemp[LI].OutputHex := LTemp[LCount].OutputHex;
        LTemp[LCount].OutLen := LOutLen;
        LTemp[LCount].KeyHex := LEntry.KeyHex;
        LTemp[LCount].OutputHex := LEntry.OutputHex;
      end;
    end;
  end;

  SetLength(Result, Length(LTemp));
  for LI := 0 to High(LTemp) do
    Result[LI] := THashLibStringArray.Create(LTemp[LI].KeyHex, LTemp[LI].OutputHex);
end;

class function TBlake2KatVectors.FindXofInputHex(const AHashName: string): string;
var
  LI: Integer;
begin
  Result := '';
  for LI := 0 to High(FEntries) do
  begin
    if (FEntries[LI].HashName = AHashName) and (FEntries[LI].KeyHex = '') then
      Exit(FEntries[LI].InputHex);
  end;
end;

class function TBlake2KatVectors.GetUnkeyedDigests(AAlgo: TBlake2KatAlgorithm)
  : THashLibStringArray;
begin
  case AAlgo of
    Blake2B: Result := FUnkeyedBlake2B;
    Blake2S: Result := FUnkeyedBlake2S;
    Blake2BP: Result := FUnkeyedBlake2BP;
    Blake2SP: Result := FUnkeyedBlake2SP;
  else
    Result := nil;
  end;
end;

class function TBlake2KatVectors.GetKeyedDigests(AAlgo: TBlake2KatAlgorithm)
  : THashLibStringArray;
begin
  case AAlgo of
    Blake2B: Result := FKeyedBlake2B;
    Blake2S: Result := FKeyedBlake2S;
    Blake2BP: Result := FKeyedBlake2BP;
    Blake2SP: Result := FKeyedBlake2SP;
  else
    Result := nil;
  end;
end;

class function TBlake2KatVectors.GetBlake2XsXofCases
  : THashLibGenericArray<THashLibStringArray>;
begin
  Result := FBlake2XsXofCases;
end;

class function TBlake2KatVectors.GetBlake2XbXofCases
  : THashLibGenericArray<THashLibStringArray>;
begin
  Result := FBlake2XbXofCases;
end;

class function TBlake2KatVectors.GetBlake2XsXofInputHex: string;
begin
  Result := FBlake2XsXofInputHex;
end;

class function TBlake2KatVectors.GetBlake2XbXofInputHex: string;
begin
  Result := FBlake2XbXofInputHex;
end;

class constructor TBlake2KatVectors.Create;
begin
  LoadEntries;
  FUnkeyedBlake2B := BuildLengthIndexedDigests('blake2b', False);
  FKeyedBlake2B := BuildLengthIndexedDigests('blake2b', True);
  FUnkeyedBlake2S := BuildLengthIndexedDigests('blake2s', False);
  FKeyedBlake2S := BuildLengthIndexedDigests('blake2s', True);
  FUnkeyedBlake2BP := BuildLengthIndexedDigests('blake2bp', False);
  FKeyedBlake2BP := BuildLengthIndexedDigests('blake2bp', True);
  FUnkeyedBlake2SP := BuildLengthIndexedDigests('blake2sp', False);
  FKeyedBlake2SP := BuildLengthIndexedDigests('blake2sp', True);
  FBlake2XsXofCases := BuildXofCases('blake2xs');
  FBlake2XbXofCases := BuildXofCases('blake2xb');
  FBlake2XsXofInputHex := FindXofInputHex('blake2xs');
  FBlake2XbXofInputHex := FindXofInputHex('blake2xb');
end;

end.
