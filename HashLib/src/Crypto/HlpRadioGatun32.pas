unit HlpRadioGatun32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo,
  HlpArrayUtils,
  HlpHashCryptoNotBuildIn;

type
  TRadioGatun32 = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private
  var
    FMill: THashLibUInt32Array;
    FBelt: THashLibMatrixUInt32Array;

    procedure RoundFunction();

  strict protected
    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    procedure Initialize(); override;
    function Clone(): IHash; override;

  end;

implementation

{ TRadioGatun32 }

function TRadioGatun32.Clone(): IHash;
var
  LHashInstance: TRadioGatun32;
begin
  LHashInstance := TRadioGatun32.Create();
  LHashInstance.FMill := System.Copy(FMill);
  LHashInstance.FBelt := TArrayUtils.Clone(FBelt);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TRadioGatun32.Create;
var
  LIdx: Int32;
begin
  inherited Create(32, 12);
  System.SetLength(FMill, 19);

  System.SetLength(FBelt, 13);
  LIdx := 0;
  while LIdx < 13 do
  begin
    System.SetLength(FBelt[LIdx], 3);

    System.Inc(LIdx);
  end;
end;

procedure TRadioGatun32.Finish;
var
  LPaddingSize, LIdx: Int32;
  LPad: THashLibByteArray;
begin
  LPaddingSize := 12 - ((Int32(FProcessedBytesCount)) mod 12);

  System.SetLength(LPad, LPaddingSize);
  LPad[0] := $01;
  TransformBytes(LPad, 0, LPaddingSize);
  LIdx := 0;
  while LIdx < 16 do
  begin
    RoundFunction();
    System.Inc(LIdx);
  end;
end;

function TRadioGatun32.GetResult: THashLibByteArray;
var
  LBuffer: THashLibUInt32Array;
  LIdx: Int32;
begin
  System.SetLength(LBuffer, 8);

  System.SetLength(Result, System.Length(LBuffer) * System.SizeOf(UInt32));

  LIdx := 0;

  while LIdx < 4 do
  begin
    RoundFunction();

    System.Move(FMill[1], LBuffer[LIdx * 2], 2 * System.SizeOf(UInt32));
    System.Inc(LIdx);
  end;

  TConverters.le32_copy(PCardinal(LBuffer), 0, PByte(Result), 0,
    System.Length(Result));
end;

procedure TRadioGatun32.Initialize;
begin
  TArrayUtils.ZeroFill(FMill);
  TArrayUtils.ZeroFill(FBelt);
  inherited Initialize();
end;

procedure TRadioGatun32.RoundFunction;
var
  LBeltQRow: THashLibUInt32Array;
  LMillScratch: array [0 .. 18] of UInt32;
  LIdx: Int32;
begin
  LBeltQRow := FBelt[12];
  LIdx := 12;
  while LIdx > 0 do
  begin
    FBelt[LIdx] := FBelt[LIdx - 1];
    System.Dec(LIdx);
  end;

  FBelt[0] := LBeltQRow;

  LIdx := 0;
  while LIdx < 12 do
  begin
    FBelt[LIdx + 1][LIdx mod 3] := FBelt[LIdx + 1][LIdx mod 3] xor FMill
      [LIdx + 1];
    System.Inc(LIdx);
  end;

  LIdx := 0;
  while LIdx < 19 do
  begin
    LMillScratch[LIdx] := FMill[LIdx] xor (FMill[(LIdx + 1) mod 19] or
      not FMill[(LIdx + 2) mod 19]);
    System.Inc(LIdx);
  end;

  LIdx := 0;
  while LIdx < 19 do
  begin
    FMill[LIdx] := TBits.RotateRight32(LMillScratch[(7 * LIdx) mod 19],
      (LIdx * (LIdx + 1)) shr 1);
    System.Inc(LIdx);
  end;

  LIdx := 0;
  while LIdx < 19 do
  begin
    LMillScratch[LIdx] := FMill[LIdx] xor FMill[(LIdx + 1) mod 19] xor FMill
      [(LIdx + 4) mod 19];
    System.Inc(LIdx);
  end;

  LMillScratch[0] := LMillScratch[0] xor 1;

  LIdx := 0;
  while LIdx < 19 do
  begin
    FMill[LIdx] := LMillScratch[LIdx];
    System.Inc(LIdx);
  end;

  LIdx := 0;
  while LIdx < 3 do
  begin
    FMill[LIdx + 13] := FMill[LIdx + 13] xor LBeltQRow[LIdx];
    System.Inc(LIdx);
  end;

end;

procedure TRadioGatun32.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LData: array [0 .. 2] of UInt32;
  LIdx: Int32;
begin
  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LIdx := 0;
  while LIdx < 3 do
  begin
    FMill[LIdx + 16] := FMill[LIdx + 16] xor LData[LIdx];
    FBelt[0][LIdx] := FBelt[0][LIdx] xor LData[LIdx];
    System.Inc(LIdx);
  end;

  RoundFunction();

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
