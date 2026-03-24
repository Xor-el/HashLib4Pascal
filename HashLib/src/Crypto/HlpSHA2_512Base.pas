unit HlpSHA2_512Base;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn,
  HlpSHA2_512Dispatch;

type
  TSHA2_512Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)
  strict protected
  var
    FState: THashLibUInt64Array;

    constructor Create(AHashSize: Int32);

    procedure Finish(); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

  end;

implementation

{ TSHA2_512Base }

constructor TSHA2_512Base.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 128);
  System.SetLength(FState, 8);
end;

procedure TSHA2_512Base.Finish;
var
  LLoBits, LHiBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LLoBits := FProcessedBytesCount shl 3;
  LHiBits := FProcessedBytesCount shr 61;

  if (FBuffer.Position < 112) then
  begin
    LPadIndex := (111 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (239 - FBuffer.Position);
  end;

  System.Inc(LPadIndex);
  System.SetLength(LPad, LPadIndex + 16);
  LPad[0] := $80;

  LHiBits := TConverters.be2me_64(LHiBits);

  TConverters.ReadUInt64AsBytesLE(LHiBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  LLoBits := TConverters.be2me_64(LLoBits);

  TConverters.ReadUInt64AsBytesLE(LLoBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

procedure TSHA2_512Base.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
begin
  SHA512_Compress(@FState[0], AData + AIndex, 1);
end;

procedure TSHA2_512Base.TransformBytes(const AData: THashLibByteArray;
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
    SHA512_Compress(@FState[0], LPtrData + AIndex, UInt32(LBlockCount));
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
