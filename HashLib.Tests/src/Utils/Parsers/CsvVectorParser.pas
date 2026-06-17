unit CsvVectorParser;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  HlpHashLibTypes,
  HashLibTestResourceLoader;

type
  TCsvRow = record
    Fields: THashLibStringArray;
  end;

  TCsvVectorTable = record
    Header: THashLibStringArray;
    Rows: THashLibGenericArray<TCsvRow>;
  end;

  TCsvVectorParser = class sealed
  private
    class function IsCommentOrEmptyLine(const ALine: string): Boolean; static;
    class function ParseCsvLine(const ALine: string): THashLibStringArray; static;
  public
    class function Parse(const AContent: string; AHasHeader: Boolean = True)
      : THashLibGenericArray<TCsvRow>;
    class function ParseFile(const ARelativePath: string; AHasHeader: Boolean = True)
      : THashLibGenericArray<TCsvRow>;
    class function GetHeader(const AContent: string): THashLibStringArray;
    class function GetField(const ARow: TCsvRow; const AHeader: THashLibStringArray;
      const AFieldName: string): string;
    class function GetFieldOrDefault(const ARow: TCsvRow;
      const AHeader: THashLibStringArray; const AFieldName, ADefault: string): string;
    class function ParseBoolField(const AValue: string): Boolean;
    class function LoadTable(const ARelativePath: string): TCsvVectorTable; static;
    class function FilterRows(const ATable: TCsvVectorTable; const AField,
      AValue: string): THashLibGenericArray<TCsvRow>; static;
    class function GetFieldUpperCase(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AFieldName: string): string; static;
    class function FindRowByField(const ATable: TCsvVectorTable; const AField,
      AValue: string): TCsvRow; static;
  end;

implementation

class function TCsvVectorParser.IsCommentOrEmptyLine(const ALine: string): Boolean;
var
  LTrimmed: string;
begin
  LTrimmed := Trim(ALine);
  Result := (LTrimmed = '') or (LTrimmed[1] = '#');
end;

class function TCsvVectorParser.ParseCsvLine(const ALine: string)
  : THashLibStringArray;
var
  LFields: TStringList;
  LField: string;
  LI, LPos, LLength: Integer;
  LInQuotes: Boolean;
begin
  LFields := TStringList.Create;
  try
    LField := '';
    LInQuotes := False;
    LPos := 1;
    LLength := Length(ALine);
    while LPos <= LLength do
    begin
      if LInQuotes then
      begin
        if ALine[LPos] = '"' then
        begin
          if (LPos < LLength) and (ALine[LPos + 1] = '"') then
          begin
            LField := LField + '"';
            Inc(LPos, 2);
          end
          else
          begin
            LInQuotes := False;
            Inc(LPos);
          end;
        end
        else
        begin
          LField := LField + ALine[LPos];
          Inc(LPos);
        end;
      end
      else
      begin
        if ALine[LPos] = '"' then
        begin
          LInQuotes := True;
          Inc(LPos);
        end
        else if ALine[LPos] = ',' then
        begin
          LFields.Add(LField);
          LField := '';
          Inc(LPos);
        end
        else
        begin
          LField := LField + ALine[LPos];
          Inc(LPos);
        end;
      end;
    end;
    LFields.Add(LField);

    SetLength(Result, LFields.Count);
    for LI := 0 to LFields.Count - 1 do
      Result[LI] := LFields[LI];
  finally
    LFields.Free;
  end;
end;

class function TCsvVectorParser.Parse(const AContent: string; AHasHeader: Boolean)
  : THashLibGenericArray<TCsvRow>;
var
  LLines: TStringList;
  LI, LCount, LHeaderIndex: Integer;
  LLine: string;
begin
  LLines := TStringList.Create;
  try
    LLines.Text := AContent;
    LHeaderIndex := -1;
    if AHasHeader then
    begin
      for LI := 0 to LLines.Count - 1 do
      begin
        if not IsCommentOrEmptyLine(LLines[LI]) then
        begin
          LHeaderIndex := LI;
          Break;
        end;
      end;
    end;

    LCount := 0;
    for LI := 0 to LLines.Count - 1 do
    begin
      if AHasHeader and (LI = LHeaderIndex) then
        Continue;
      LLine := Trim(LLines[LI]);
      if IsCommentOrEmptyLine(LLine) then
        Continue;
      SetLength(Result, LCount + 1);
      Result[LCount].Fields := ParseCsvLine(LLine);
      Inc(LCount);
    end;
  finally
    LLines.Free;
  end;
end;

class function TCsvVectorParser.ParseFile(const ARelativePath: string;
  AHasHeader: Boolean): THashLibGenericArray<TCsvRow>;
begin
  Result := Parse(THashLibTestResourceLoader.Instance.LoadAsString(ARelativePath),
    AHasHeader);
end;

class function TCsvVectorParser.GetHeader(const AContent: string)
  : THashLibStringArray;
var
  LLines: TStringList;
  LI: Integer;
begin
  LLines := TStringList.Create;
  try
    LLines.Text := AContent;
    for LI := 0 to LLines.Count - 1 do
    begin
      if not IsCommentOrEmptyLine(LLines[LI]) then
      begin
        Result := ParseCsvLine(Trim(LLines[LI]));
        Exit;
      end;
    end;
    Result := nil;
  finally
    LLines.Free;
  end;
end;

class function TCsvVectorParser.GetField(const ARow: TCsvRow;
  const AHeader: THashLibStringArray; const AFieldName: string): string;
var
  LI: Integer;
begin
  for LI := 0 to High(AHeader) do
  begin
    if SameText(AHeader[LI], AFieldName) then
    begin
      if LI <= High(ARow.Fields) then
        Exit(ARow.Fields[LI]);
      Break;
    end;
  end;
  Result := '';
end;

class function TCsvVectorParser.GetFieldOrDefault(const ARow: TCsvRow;
  const AHeader: THashLibStringArray; const AFieldName, ADefault: string): string;
begin
  Result := GetField(ARow, AHeader, AFieldName);
  if Result = '' then
    Result := ADefault;
end;

class function TCsvVectorParser.ParseBoolField(const AValue: string): Boolean;
var
  LTrimmed: string;
begin
  LTrimmed := Trim(UpperCase(AValue));
  Result := (LTrimmed = 'TRUE') or (LTrimmed = '1') or (LTrimmed = 'YES');
end;

class function TCsvVectorParser.LoadTable(const ARelativePath: string): TCsvVectorTable;
var
  LContent: string;
begin
  LContent := THashLibTestResourceLoader.Instance.LoadAsString(ARelativePath);
  Result.Header := GetHeader(LContent);
  Result.Rows := Parse(LContent, True);
end;

class function TCsvVectorParser.FilterRows(const ATable: TCsvVectorTable;
  const AField, AValue: string): THashLibGenericArray<TCsvRow>;
var
  LI, LCount: Integer;
begin
  LCount := 0;
  Result := nil;
  for LI := 0 to High(ATable.Rows) do
  begin
    if SameText(GetField(ATable.Rows[LI], ATable.Header, AField), AValue) then
    begin
      SetLength(Result, LCount + 1);
      Result[LCount] := ATable.Rows[LI];
      Inc(LCount);
    end;
  end;
end;

class function TCsvVectorParser.GetFieldUpperCase(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AFieldName: string): string;
begin
  Result := UpperCase(GetField(ARow, ATable.Header, AFieldName));
end;

class function TCsvVectorParser.FindRowByField(const ATable: TCsvVectorTable;
  const AField, AValue: string): TCsvRow;
var
  LI: Integer;
begin
  for LI := 0 to High(ATable.Rows) do
  begin
    if SameText(GetField(ATable.Rows[LI], ATable.Header, AField), AValue) then
      Exit(ATable.Rows[LI]);
  end;
  raise Exception.CreateFmt('CSV vector row not found: %s=%s', [AField, AValue]);
end;

end.
