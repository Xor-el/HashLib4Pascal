unit uPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

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
  LMaxRate: Double;
  LData: TBytes;
  LIdx: Int32;
  LTotal: Int64;
  LTickStart, LTickEnd, LTotalMilliSeconds: UInt32;
  LNewName, LBlockSizeAndUnit: String;
begin

  System.SetLength(LData, ASize);

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    LData[LIdx] := Byte(Random(ASize));
  end;

  LMaxRate := 0.0;
  LTotalMilliSeconds := 0;

  LIdx := 3;
  while LIdx > 0 do
  begin
    LTotal := 0;

    while (LTotalMilliSeconds <= THREE_SECONDS_IN_MILLISECONDS) do
    begin
      LTickStart := TThread.GetTickCount;
      AHashInstance.ComputeBytes(LData);
      LTickEnd := TThread.GetTickCount;
      LTotal := LTotal + System.Length(LData);
      LTotalMilliSeconds := LTotalMilliSeconds + (LTickEnd - LTickStart);
    end;

    LMaxRate := Math.Max(LTotal / (LTotalMilliSeconds div 1000) / 1024 /
      1024, LMaxRate);

    System.Dec(LIdx);
  end;

  if ANamePrefix <> '' then
  begin
    LNewName := Format('%s_%s', [AHashInstance.Name, ANamePrefix]);
  end
  else
  begin
    LNewName := AHashInstance.Name;
  end;

  if ASize >= 1024 * 1024 * 1024 then
  begin
    LBlockSizeAndUnit := Format('%d GB', [(ASize div (1024 * 1024 * 1024))]);
  end
  else if ASize >= 1024 * 1024 then
  begin
    LBlockSizeAndUnit := Format('%d MB', [(ASize div (1024 * 1024))]);
  end
  else
  begin
    LBlockSizeAndUnit := Format('%d KB', [(ASize div 1024)]);
  end;

  Result := Format('%s Throughput: %.2f MB/s with Blocks of %s',
    [Copy(LNewName, 2, System.Length(LNewName) - 1), LMaxRate,
    LBlockSizeAndUnit]);
end;

class procedure TPerformanceBenchmark.DoBenchmark(var AStringList: TStringList);
begin
  if not Assigned(AStringList) then
  begin
    raise Exception.Create('StringList Instance cannot be nil');
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

  AStringList.Append(Calculate(THashFactory.THash64.CreateXXHash3));

  AStringList.Append
    (Calculate(THashFactory.THash128.CreateMurmurHash3_x86_128));

  AStringList.Append
    (Calculate(THashFactory.THash128.CreateMurmurHash3_x64_128));

  AStringList.Append
    (Calculate(THashFactory.THash128.CreateXXHash128));

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

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2BP(64, nil)));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake2SP(32, nil)));

  AStringList.Append(Calculate(THashFactory.TCrypto.CreateBlake3_256(nil)));

end;

class constructor TPerformanceBenchmark.PerformanceBenchmark;
begin
  Randomize();
end;

end.
