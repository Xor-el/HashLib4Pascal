unit HlpMD4;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpMDBase,
  HlpBits,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo;

type
  TMD4 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

implementation

{ TMD4 }

function TMD4.Clone(): IHash;
var
  LHashInstance: TMD4;
begin
  LHashInstance := TMD4.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TMD4.Create;
begin
  inherited Create(4, 16);
end;

procedure TMD4.TransformBlock(AData: PByte; ADataLength: Int32; AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD: UInt32;
  LData: array [0 .. 15] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];

  LRegA := LRegA + (LData[0] + ((LRegB and LRegC) or ((not LRegB) and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[1] + ((LRegA and LRegB) or ((not LRegA) and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[2] + ((LRegD and LRegA) or ((not LRegD) and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[3] + ((LRegC and LRegD) or ((not LRegC) and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 19);
  LRegA := LRegA + (LData[4] + ((LRegB and LRegC) or ((not LRegB) and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[5] + ((LRegA and LRegB) or ((not LRegA) and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[6] + ((LRegD and LRegA) or ((not LRegD) and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[7] + ((LRegC and LRegD) or ((not LRegC) and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 19);
  LRegA := LRegA + (LData[8] + ((LRegB and LRegC) or ((not LRegB) and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[9] + ((LRegA and LRegB) or ((not LRegA) and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[10] + ((LRegD and LRegA) or ((not LRegD) and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[11] + ((LRegC and LRegD) or ((not LRegC) and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 19);
  LRegA := LRegA + (LData[12] + ((LRegB and LRegC) or ((not LRegB) and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[13] + ((LRegA and LRegB) or ((not LRegA) and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[14] + ((LRegD and LRegA) or ((not LRegD) and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[15] + ((LRegC and LRegD) or ((not LRegC) and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 19);

  LRegA := LRegA + (LData[0] + C2 + ((LRegB and (LRegC or LRegD)) or (LRegC and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[4] + C2 + ((LRegA and (LRegB or LRegC)) or (LRegB and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 5);
  LRegC := LRegC + (LData[8] + C2 + ((LRegD and (LRegA or LRegB)) or (LRegA and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[12] + C2 + ((LRegC and (LRegD or LRegA)) or (LRegD and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 13);
  LRegA := LRegA + (LData[1] + C2 + ((LRegB and (LRegC or LRegD)) or (LRegC and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[5] + C2 + ((LRegA and (LRegB or LRegC)) or (LRegB and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 5);
  LRegC := LRegC + (LData[9] + C2 + ((LRegD and (LRegA or LRegB)) or (LRegA and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[13] + C2 + ((LRegC and (LRegD or LRegA)) or (LRegD and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 13);
  LRegA := LRegA + (LData[2] + C2 + ((LRegB and (LRegC or LRegD)) or (LRegC and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[6] + C2 + ((LRegA and (LRegB or LRegC)) or (LRegB and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 5);
  LRegC := LRegC + (LData[10] + C2 + ((LRegD and (LRegA or LRegB)) or (LRegA and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[14] + C2 + ((LRegC and (LRegD or LRegA)) or (LRegD and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 13);
  LRegA := LRegA + (LData[3] + C2 + ((LRegB and (LRegC or LRegD)) or (LRegC and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[7] + C2 + ((LRegA and (LRegB or LRegC)) or (LRegB and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 5);
  LRegC := LRegC + (LData[11] + C2 + ((LRegD and (LRegA or LRegB)) or (LRegA and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[15] + C2 + ((LRegC and (LRegD or LRegA)) or (LRegD and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 13);

  LRegA := LRegA + (LData[0] + C4 + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[8] + C4 + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[4] + C4 + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[12] + C4 + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[2] + C4 + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[10] + C4 + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[6] + C4 + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[14] + C4 + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[1] + C4 + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[9] + C4 + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[5] + C4 + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[13] + C4 + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[3] + C4 + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 3);
  LRegD := LRegD + (LData[11] + C4 + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[7] + C4 + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 11);
  LRegB := LRegB + (LData[15] + C4 + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);

  FState[0] := FState[0] + LRegA;
  FState[1] := FState[1] + LRegB;
  FState[2] := FState[2] + LRegC;
  FState[3] := FState[3] + LRegD;

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
