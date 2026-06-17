unit Pbkdf2Vectors;

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
  TPbkdf2VectorRow = record
    Algorithm: string;
    PasswordHex: string;
    SaltHex: string;
    Iterations: Integer;
    OutputLenBytes: Integer;
    ExpectedHex: string;
  end;

  TPbkdf2Vectors = class sealed
  strict private
    class var
      FTable: TCsvVectorTable;

    class function RowFromCsv(const ARow: TCsvRow): TPbkdf2VectorRow; static;
  public
    class function GetRowByAlgorithm(const AAlgorithm: string): TPbkdf2VectorRow; static;
    class function GetRows: THashLibGenericArray<TPbkdf2VectorRow>; static;
    class constructor Create;
  end;

implementation

class function TPbkdf2Vectors.RowFromCsv(const ARow: TCsvRow): TPbkdf2VectorRow;
begin
  Result.Algorithm := TCsvVectorLoaderBase.GetField(FTable, ARow, 'Algorithm');
  Result.PasswordHex := TCsvVectorLoaderBase.GetFieldUpperCase(FTable, ARow, 'PasswordHex');
  Result.SaltHex := TCsvVectorLoaderBase.GetFieldUpperCase(FTable, ARow, 'SaltHex');
  Result.Iterations := StrToIntDef(
    TCsvVectorLoaderBase.GetField(FTable, ARow, 'Iterations'), 0);
  Result.OutputLenBytes := StrToIntDef(
    TCsvVectorLoaderBase.GetField(FTable, ARow, 'OutputLenBytes'), 0);
  Result.ExpectedHex := TCsvVectorLoaderBase.GetFieldUpperCase(FTable, ARow, 'ExpectedHex');
end;

class function TPbkdf2Vectors.GetRowByAlgorithm(const AAlgorithm: string): TPbkdf2VectorRow;
begin
  Result := RowFromCsv(TCsvVectorParser.FindRowByField(FTable, 'Algorithm', AAlgorithm));
end;

class function TPbkdf2Vectors.GetRows: THashLibGenericArray<TPbkdf2VectorRow>;
var
  LI: Integer;
begin
  SetLength(Result, Length(FTable.Rows));
  for LI := 0 to High(FTable.Rows) do
    Result[LI] := RowFromCsv(FTable.Rows[LI]);
end;

class constructor TPbkdf2Vectors.Create;
begin
  TCsvVectorLoaderBase.LoadCachedTable(FTable, 'Crypto/Pbkdf2/TestVectors.csv');
end;

end.
