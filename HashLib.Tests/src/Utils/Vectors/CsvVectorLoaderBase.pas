unit CsvVectorLoaderBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  HlpHashLibTypes,
  HashLibTestResourceLoader,
  CsvVectorParser;

type
  TCsvVectorLoaderBase = class sealed
  public
    class procedure LoadCachedTable(var ATable: TCsvVectorTable;
      const ARelativePath: string); static;
    class function LoadTable(const ARelativePath: string): TCsvVectorTable; static;
    class function GetField(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
    class function GetFieldTrimmed(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
    class function GetFieldUpperCase(const ATable: TCsvVectorTable; const ARow: TCsvRow;
      const AName: string): string; static;
  end;

implementation

class procedure TCsvVectorLoaderBase.LoadCachedTable(var ATable: TCsvVectorTable;
  const ARelativePath: string);
begin
  ATable := LoadTable(ARelativePath);
end;

class function TCsvVectorLoaderBase.LoadTable(const ARelativePath: string): TCsvVectorTable;
begin
  Result := TCsvVectorParser.LoadTable(ARelativePath);
end;

class function TCsvVectorLoaderBase.GetField(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := TCsvVectorParser.GetField(ARow, ATable.Header, AName);
end;

class function TCsvVectorLoaderBase.GetFieldTrimmed(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := Trim(GetField(ATable, ARow, AName));
end;

class function TCsvVectorLoaderBase.GetFieldUpperCase(const ATable: TCsvVectorTable;
  const ARow: TCsvRow; const AName: string): string;
begin
  Result := TCsvVectorParser.GetFieldUpperCase(ATable, ARow, AName);
end;

end.
