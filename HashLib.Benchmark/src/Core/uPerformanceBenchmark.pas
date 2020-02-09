unit uPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}
{$ZEROBASEDSTRINGS OFF}

interface

uses
  Classes,
  SysUtils,
  Math,
  HlpCRC,
  HlpIHash,
  HlpHashFactory;

type
  TPerformanceBenchmark = class sealed(TObject)
  strict private

    class function Calculate(const AHashInstance: IHash;
      const ANamePrefix: String = ''; ASize: Int32 = 64 * 1024): String;

    class constructor PerformanceBenchmark();

  public
    class procedure DoBenchmark(var AStringList: TStringList);

  end;

implementation

{ TPerformanceBenchmark }

class function TPerformanceBenchmark.Calculate(const AHashInstance: IHash;
  const ANamePrefix: String; ASize: Int32): String;
const
  THREE_SECONDS_IN_MILLISECONDS = UInt32(3000);
var
  MaxRate: Double;
  Data: TBytes;
  Idx: Int32;
  Total: Int64;
  A, B, TotalMilliSeconds: UInt32;
  NewName, BlockSizeAndUnit: String;
begin

  System.SetLength(Data, ASize);

  for Idx := System.Low(Data) to System.High(Data) do
  begin
    Data[Idx] := Byte(Random(ASize));
  end;

  MaxRate := 0.0;
  TotalMilliSeconds := 0;

  Idx := 3;
  while Idx > 0 do
  begin
    Total := 0;

    while (TotalMilliSeconds <= THREE_SECONDS_IN_MILLISECONDS) do
    begin
      A := TThread.GetTickCount;
      AHashInstance.ComputeBytes(Data);
      B := TThread.GetTickCount;
      Total := Total + System.Length(Data);
      TotalMilliSeconds := TotalMilliSeconds + (B - A);
    end;

    MaxRate := Math.Max(Total / (TotalMilliSeconds div 1000) / 1024 /
      1024, MaxRate);

    System.Dec(Idx);
  end;

  if ANamePrefix <> '' then
  begin
    NewName := Format('%s_%s', [AHashInstance.Name, ANamePrefix]);
  end
  else
  begin
    NewName := AHashInstance.Name;
  end;

  if ASize >= 1024 * 1024 * 1024 then
  begin
    BlockSizeAndUnit := Format('%d GB', [(ASize div (1024 * 1024 * 1024))]);
  end
  else if ASize >= 1024 * 1024 then
  begin
    BlockSizeAndUnit := Format('%d MB', [(ASize div (1024 * 1024))]);
  end
  else
  begin
    BlockSizeAndUnit := Format('%d KB', [(ASize div 1024)]);
  end;

  Result := Format('%s Throughput: %.2f MB/s with Blocks of %s',
    [Copy(NewName, 2, System.Length(NewName) - 1), MaxRate, BlockSizeAndUnit]);
end;

class procedure TPerformanceBenchmark.DoBenchmark(var AStringList: TStringList);
begin
  if not Assigned(AStringList) then
  begin
    raise Exception.Create('StringList Instance cannot be Nil');
  end;

  AStringList.Clear;

  AStringList.Append(Calculate(THashFactory.TChecksum.CreateAdler32));

  AStringList.Append(Calculate(THashFactory.TChecksum.TCRC.CreateCRC
    (TCRCStandard.CRC32), 'PKZIP_Generic'));

  AStringList.Append
    (Calculate(THashFactory.TChecksum.TCRC.CreateCRC32_PKZIP, 'Fast'));

  AStringList.Append(Calculate(THashFactory.THash32.CreateMurmurHash3_x86_32));

  AStringList.Append(Calculate(THashFactory.THash32.CreateXXHash32));

  AStringList.Append(Calculate(THashFactory.THash64.CreateSipHash2_4));

  AStringList.Append(Calculate(THashFactory.THash64.CreateXXHash64));

  AStringList.Append
    (Calculate(THashFactory.THash128.CreateMurmurHash3_x86_128));

  AStringList.Append
    (Calculate(THashFactory.THash128.CreateMurmurHash3_x64_128));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateMD5));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateSHA1));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateSHA2_256));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateSHA2_512));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateSHA3_256));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateSHA3_512));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2B_256));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2B_512));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2S_128));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2S_256));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2BP(64, Nil)));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2SP(32, Nil)));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake3_256(Nil)));

end;

class constructor TPerformanceBenchmark.PerformanceBenchmark;
begin
  Randomize();
end;

end.
