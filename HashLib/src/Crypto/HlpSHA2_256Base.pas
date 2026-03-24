unit HlpSHA2_256Base;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn,
  HlpSHA2_256Dispatch;

type
  TSHA2_256Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)
  strict protected
  var
    FState: THashLibUInt32Array;

    constructor Create(AHashSize: Int32);

    procedure Finish(); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

  end;

implementation

{ TSHA2_256Base }

constructor TSHA2_256Base.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 64);
  System.SetLength(FState, 8);
end;

procedure TSHA2_256Base.Finish;
var
  LBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LBits := FProcessedBytesCount * 8;
  if (FBuffer.Position < 56) then
  begin
    LPadIndex := (56 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (120 - FBuffer.Position);
  end;
  System.SetLength(LPad, LPadIndex + 8);
  LPad[0] := $80;

  LBits := TConverters.be2me_64(LBits);

  TConverters.ReadUInt64AsBytesLE(LBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

procedure TSHA2_256Base.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
begin
  SHA256_Compress(@FState[0], AData + AIndex, 1);
end;

procedure TSHA2_256Base.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LPtrData: PByte;
  LBlockCount: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LPtrData := PByte(AData);

  if (not FBuffer.IsEmpty) then
  begin
    if (FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount)) then
    begin
      TransformBuffer();
    end;
  end;

  LBlockCount := ALength div FBuffer.Length;
  if LBlockCount > 0 then
  begin
    FProcessedBytesCount := FProcessedBytesCount +
      UInt64(LBlockCount) * UInt64(FBuffer.Length);
    SHA256_Compress(@FState[0], LPtrData + AIndex, UInt32(LBlockCount));
    AIndex := AIndex + (LBlockCount * FBuffer.Length);
    ALength := ALength - (LBlockCount * FBuffer.Length);
  end;

  if (ALength > 0) then
  begin
    FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount);
  end;
end;

end.
