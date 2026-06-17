unit JsonVectorParser;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpjson,
  jsonparser,
{$ELSE}
  System.JSON,
{$ENDIF FPC}
  HlpHashLibTypes,
  HashLibTestResourceLoader;

type
  {$IFDEF FPC}
  TJsonNode = TJSONData;
  {$ELSE}
  TJsonNode = TJSONValue;
  {$ENDIF FPC}

  TJsonVectorObject = class;

  TJsonVectorDocument = class(TObject)
  private
    FRootOwner: TJsonNode;
    FRoot: TJsonVectorObject;
  public
    constructor Create(const AContent: string);
    destructor Destroy; override;
    property Root: TJsonVectorObject read FRoot;
    class function LoadFile(const ARelativePath: string): TJsonVectorDocument;
  end;

  TJsonVectorObject = class(TObject)
  private
    FObj: TJSONObject;
    function GetField(const AName: string): TJsonNode;
    class function NodeIsNull(const ANode: TJsonNode): Boolean; static;
    class function NodeAsString(const ANode: TJsonNode): string; static;
    class function NodeAsInteger(const ANode: TJsonNode): Integer; static;
    function GetArray(const AName: string): TJSONArray;
  public
    constructor Create(AObj: TJSONObject);
    function HasField(const AName: string): Boolean;
    function IsNullField(const AName: string): Boolean;
    function GetString(const AName: string): string;
    function GetInt(const AName: string; ADefault: Integer = 0): Integer;
    function GetObjectArray(const AName: string): THashLibGenericArray<TJsonVectorObject>;
    class procedure FreeOwnedArray(var AObjects: THashLibGenericArray<TJsonVectorObject>);
  end;

implementation

{ TJsonVectorDocument }

constructor TJsonVectorDocument.Create(const AContent: string);
begin
  inherited Create;
{$IFDEF FPC}
  FRootOwner := GetJSON(AContent);
{$ELSE}
  FRootOwner := TJSONObject.ParseJSONValue(AContent);
{$ENDIF FPC}
  if not (FRootOwner is TJSONObject) then
  begin
    FRootOwner.Free;
    raise EConvertError.Create('JSON root must be an object');
  end;
  FRoot := TJsonVectorObject.Create(TJSONObject(FRootOwner));
end;

destructor TJsonVectorDocument.Destroy;
begin
  FRoot.Free;
  FRootOwner.Free;
  inherited;
end;

class function TJsonVectorDocument.LoadFile(const ARelativePath: string)
  : TJsonVectorDocument;
begin
  Result := TJsonVectorDocument.Create(
    THashLibTestResourceLoader.Instance.LoadAsString(ARelativePath));
end;

{ TJsonVectorObject }

constructor TJsonVectorObject.Create(AObj: TJSONObject);
begin
  inherited Create;
  FObj := AObj;
end;

function TJsonVectorObject.GetField(const AName: string): TJsonNode;
begin
  if FObj = nil then
    Exit(nil);
{$IFDEF FPC}
  Result := FObj.Find(AName);
{$ELSE}
  Result := FObj.GetValue(AName);
{$ENDIF FPC}
end;

class function TJsonVectorObject.NodeIsNull(const ANode: TJsonNode): Boolean;
begin
{$IFDEF FPC}
  Result := (ANode = nil) or (ANode.JSONType = TJSONType.jtNull);
{$ELSE}
  Result := (ANode = nil) or (ANode is TJSONNull);
{$ENDIF FPC}
end;

class function TJsonVectorObject.NodeAsString(const ANode: TJsonNode): string;
begin
{$IFDEF FPC}
  Result := ANode.AsString;
{$ELSE}
  Result := ANode.Value;
{$ENDIF FPC}
end;

class function TJsonVectorObject.NodeAsInteger(const ANode: TJsonNode): Integer;
begin
{$IFDEF FPC}
  Result := ANode.AsInteger;
{$ELSE}
  Result := StrToIntDef(ANode.Value, 0);
{$ENDIF FPC}
end;

function TJsonVectorObject.GetArray(const AName: string): TJSONArray;
var
  LNode: TJsonNode;
begin
  Result := nil;
  if FObj = nil then
    Exit;
  LNode := GetField(AName);
  if (LNode <> nil) and (LNode is TJSONArray) then
    Result := TJSONArray(LNode);
end;

function TJsonVectorObject.HasField(const AName: string): Boolean;
begin
  Result := GetField(AName) <> nil;
end;

function TJsonVectorObject.IsNullField(const AName: string): Boolean;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if LNode = nil then
    Exit(False);
  Result := NodeIsNull(LNode);
end;

function TJsonVectorObject.GetString(const AName: string): string;
var
  LNode: TJsonNode;
begin
  LNode := GetField(AName);
  if (LNode = nil) or NodeIsNull(LNode) then
    Exit('');
  Result := NodeAsString(LNode);
end;

function TJsonVectorObject.GetInt(const AName: string; ADefault: Integer): Integer;
begin
  if not HasField(AName) or IsNullField(AName) then
    Exit(ADefault);
  Result := StrToIntDef(GetString(AName), ADefault);
end;

function TJsonVectorObject.GetObjectArray(const AName: string)
  : THashLibGenericArray<TJsonVectorObject>;
var
  LArr: TJSONArray;
  LI: Integer;
  LItem: TJsonNode;
begin
  Result := nil;
  LArr := GetArray(AName);
  if LArr = nil then
    Exit;
  SetLength(Result, LArr.Count);
  for LI := 0 to LArr.Count - 1 do
  begin
    LItem := LArr.Items[LI];
    if not (LItem is TJSONObject) then
      raise EConvertError.CreateFmt('Expected object at %s[%d]', [AName, LI]);
    Result[LI] := TJsonVectorObject.Create(TJSONObject(LItem));
  end;
end;

class procedure TJsonVectorObject.FreeOwnedArray(
  var AObjects: THashLibGenericArray<TJsonVectorObject>);
var
  LI: Integer;
begin
  for LI := 0 to High(AObjects) do
    AObjects[LI].Free;
  AObjects := nil;
end;

end.
