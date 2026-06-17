unit ScryptVectors;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  HlpHashLibTypes,
  CsvVectorParser,
  CsvVectorLoaderBase;

type
  TScryptVectorRow = record
    Password: string;
    Salt: string;
    Cost: Integer;
    BlockSize: Integer;
    Parallelism: Integer;
    OutputLenBytes: Integer;
    ExpectedHex: string;
  end;

  TScryptVectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TScryptVectorRow; static;
  public
    class function GetEnabledRows: THashLibGenericArray<TScryptVectorRow>; static;
    class constructor Create;
  end;

implementation

class function TScryptVectors.RowFromCsv(const ARow: TCsvRow): TScryptVectorRow;
begin
  Result.Password := TCsvVectorLoaderBase.GetField(FTable, ARow, 'Password');
  Result.Salt := TCsvVectorLoaderBase.GetField(FTable, ARow, 'Salt');
  Result.Cost := StrToIntDef(TCsvVectorLoaderBase.GetField(FTable, ARow, 'Cost'), 0);
  Result.BlockSize := StrToIntDef(TCsvVectorLoaderBase.GetField(FTable, ARow, 'BlockSize'), 0);
  Result.Parallelism := StrToIntDef(TCsvVectorLoaderBase.GetField(FTable, ARow, 'Parallelism'), 0);
  Result.OutputLenBytes := StrToIntDef(
    TCsvVectorLoaderBase.GetField(FTable, ARow, 'OutputLenBytes'), 0);
  Result.ExpectedHex := TCsvVectorLoaderBase.GetFieldUpperCase(FTable, ARow, 'ExpectedHex');
end;

class function TScryptVectors.GetEnabledRows: THashLibGenericArray<TScryptVectorRow>;
var
  LI, LCount: Integer;
  LRow: TCsvRow;
begin
  LCount := 0;
  Result := nil;
  for LI := 0 to High(FTable.Rows) do
  begin
    LRow := FTable.Rows[LI];
    if not TCsvVectorParser.ParseBoolField(
      TCsvVectorParser.GetField(LRow, FTable.Header, 'Enabled')) then
      Continue;
    SetLength(Result, LCount + 1);
    Result[LCount] := RowFromCsv(LRow);
    Inc(LCount);
  end;
end;

class constructor TScryptVectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FTable, 'Crypto/Scrypt/TestVectors.csv');
end;

end.
