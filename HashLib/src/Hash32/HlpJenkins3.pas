unit HlpJenkins3;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpMultipleTransformNonBlock;

type

  TJenkins3 = class sealed(TMultipleTransformNonBlock, IHash32, ITransformBlock)
  strict private
  var
    FInitialValue: Int32;

  strict protected
    function ComputeAggregatedBytes(const AData: THashLibByteArray)
      : IHashResult; override;
  public
    constructor Create(AInitialValue: Int32 = 0);
    function Clone(): IHash; override;

  end;

implementation

{ TJenkins3 }

constructor TJenkins3.Create(AInitialValue: Int32);
begin
  inherited Create(4, 12);
  FInitialValue := AInitialValue;
end;

function TJenkins3.Clone(): IHash;
var
  LHashInstance: TJenkins3;
begin
  LHashInstance := TJenkins3.Create();
  FBuffer.Position := 0;
  LHashInstance.FInitialValue := FInitialValue;
  LHashInstance.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

function TJenkins3.ComputeAggregatedBytes(const AData: THashLibByteArray)
  : IHashResult;
var
  LLength, LCurrentIndex, LI1, LI2, LI3, LI4: Int32;
  LRegA, LRegB, LRegC: UInt32;
begin
  LLength := System.length(AData);
  LRegA := UInt32($DEADBEEF) + UInt32(LLength) + UInt32(FInitialValue);
  LRegB := LRegA;
  LRegC := LRegB;
  if (LLength = 0) then
  begin
    Result := THashResult.Create(LRegC);
    Exit;
  end;

  LCurrentIndex := 0;
  while (LLength > 12) do
  begin
    LI1 := AData[LCurrentIndex];
    System.Inc(LCurrentIndex);
    LI2 := AData[LCurrentIndex] shl 8;
    System.Inc(LCurrentIndex);
    LI3 := AData[LCurrentIndex] shl 16;
    System.Inc(LCurrentIndex);
    LI4 := AData[LCurrentIndex] shl 24;
    System.Inc(LCurrentIndex);

    LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

    LI1 := AData[LCurrentIndex];
    System.Inc(LCurrentIndex);
    LI2 := AData[LCurrentIndex] shl 8;
    System.Inc(LCurrentIndex);
    LI3 := AData[LCurrentIndex] shl 16;
    System.Inc(LCurrentIndex);
    LI4 := AData[LCurrentIndex] shl 24;
    System.Inc(LCurrentIndex);

    LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);

    LI1 := AData[LCurrentIndex];
    System.Inc(LCurrentIndex);
    LI2 := AData[LCurrentIndex] shl 8;
    System.Inc(LCurrentIndex);
    LI3 := AData[LCurrentIndex] shl 16;
    System.Inc(LCurrentIndex);
    LI4 := AData[LCurrentIndex] shl 24;
    System.Inc(LCurrentIndex);

    LRegC := LRegC + UInt32(LI1 or LI2 or LI3 or LI4);

    LRegA := LRegA - LRegC;
    LRegA := LRegA xor TBits.RotateLeft32(LRegC, 4);
    LRegC := LRegC + LRegB;
    LRegB := LRegB - LRegA;
    LRegB := LRegB xor TBits.RotateLeft32(LRegA, 6);
    LRegA := LRegA + LRegC;
    LRegC := LRegC - LRegB;
    LRegC := LRegC xor TBits.RotateLeft32(LRegB, 8);
    LRegB := LRegB + LRegA;
    LRegA := LRegA - LRegC;
    LRegA := LRegA xor TBits.RotateLeft32(LRegC, 16);
    LRegC := LRegC + LRegB;
    LRegB := LRegB - LRegA;
    LRegB := LRegB xor TBits.RotateLeft32(LRegA, 19);
    LRegA := LRegA + LRegC;
    LRegC := LRegC - LRegB;
    LRegC := LRegC xor TBits.RotateLeft32(LRegB, 4);
    LRegB := LRegB + LRegA;

    System.Dec(LLength, 12);
  end;

  case LLength of
    12:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;

        LRegC := LRegC + UInt32(LI1 or LI2 or LI3 or LI4);
      end;

    11:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;

        LRegC := LRegC + UInt32(LI1 or LI2 or LI3);
      end;

    10:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;

        LRegC := LRegC + UInt32(LI1 or LI2);
      end;

    9:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];

        LRegC := LRegC + UInt32(LI1);
      end;

    8:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3 or LI4);
      end;

    7:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;

        LRegB := LRegB + UInt32(LI1 or LI2 or LI3);
      end;

    6:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;

        LRegB := LRegB + UInt32(LI1 or LI2);
      end;

    5:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;
        System.Inc(LCurrentIndex);

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);

        LI1 := AData[LCurrentIndex];

        LRegB := LRegB + UInt32(LI1);
      end;

    4:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;
        System.Inc(LCurrentIndex);
        LI4 := AData[LCurrentIndex] shl 24;

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3 or LI4);
      end;

    3:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;
        System.Inc(LCurrentIndex);
        LI3 := AData[LCurrentIndex] shl 16;

        LRegA := LRegA + UInt32(LI1 or LI2 or LI3);
      end;

    2:
      begin
        LI1 := AData[LCurrentIndex];
        System.Inc(LCurrentIndex);
        LI2 := AData[LCurrentIndex] shl 8;

        LRegA := LRegA + UInt32(LI1 or LI2);
      end;

    1:
      begin
        LI1 := AData[LCurrentIndex];

        LRegA := LRegA + UInt32(LI1);
      end;
  end;

  LRegC := LRegC xor LRegB;
  LRegC := LRegC - TBits.RotateLeft32(LRegB, 14);
  LRegA := LRegA xor LRegC;
  LRegA := LRegA - TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB xor LRegA;
  LRegB := LRegB - TBits.RotateLeft32(LRegA, 25);
  LRegC := LRegC xor LRegB;
  LRegC := LRegC - TBits.RotateLeft32(LRegB, 16);
  LRegA := LRegA xor LRegC;
  LRegA := LRegA - TBits.RotateLeft32(LRegC, 4);
  LRegB := LRegB xor LRegA;
  LRegB := LRegB - TBits.RotateLeft32(LRegA, 14);
  LRegC := LRegC xor LRegB;
  LRegC := LRegC - TBits.RotateLeft32(LRegB, 24);

  Result := THashResult.Create(LRegC);
end;

end.
