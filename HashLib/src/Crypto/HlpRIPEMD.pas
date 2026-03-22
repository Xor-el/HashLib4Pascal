unit HlpRIPEMD;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBits,
  HlpMDBase,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo;

type
  TRIPEMD = class sealed(TMDBase, ITransformBlock)

  strict private
    class function P1(AWord0, AWord1, AWord2: UInt32): UInt32; static; inline;
    class function P2(AWord0, AWord1, AWord2: UInt32): UInt32; static; inline;
    class function P3(AWord0, AWord1, AWord2: UInt32): UInt32; static; inline;

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

implementation

{ TRIPEMD }

function TRIPEMD.Clone(): IHash;
var
  LHashInstance: TRIPEMD;
begin
  LHashInstance := TRIPEMD.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TRIPEMD.Create;
begin
  inherited Create(4, 16);
end;

class function TRIPEMD.P1(AWord0, AWord1, AWord2: UInt32): UInt32;
begin
  Result := (AWord0 and AWord1) or (not AWord0 and AWord2);
end;

class function TRIPEMD.P2(AWord0, AWord1, AWord2: UInt32): UInt32;
begin
  Result := (AWord0 and AWord1) or (AWord0 and AWord2) or (AWord1 and AWord2);
end;

class function TRIPEMD.P3(AWord0, AWord1, AWord2: UInt32): UInt32;
begin
  Result := AWord0 xor AWord1 xor AWord2;
end;

procedure TRIPEMD.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegPA, LRegPB, LRegPC, LRegPD: UInt32;
  LData: array [0 .. 15] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];
  LRegPA := LRegA;
  LRegPB := LRegB;
  LRegPC := LRegC;
  LRegPD := LRegD;

  LRegA := TBits.RotateLeft32(P1(LRegB, LRegC, LRegD) + LRegA + LData[0], 11);
  LRegD := TBits.RotateLeft32(P1(LRegA, LRegB, LRegC) + LRegD + LData[1], 14);
  LRegC := TBits.RotateLeft32(P1(LRegD, LRegA, LRegB) + LRegC + LData[2], 15);
  LRegB := TBits.RotateLeft32(P1(LRegC, LRegD, LRegA) + LRegB + LData[3], 12);
  LRegA := TBits.RotateLeft32(P1(LRegB, LRegC, LRegD) + LRegA + LData[4], 5);
  LRegD := TBits.RotateLeft32(P1(LRegA, LRegB, LRegC) + LRegD + LData[5], 8);
  LRegC := TBits.RotateLeft32(P1(LRegD, LRegA, LRegB) + LRegC + LData[6], 7);
  LRegB := TBits.RotateLeft32(P1(LRegC, LRegD, LRegA) + LRegB + LData[7], 9);
  LRegA := TBits.RotateLeft32(P1(LRegB, LRegC, LRegD) + LRegA + LData[8], 11);
  LRegD := TBits.RotateLeft32(P1(LRegA, LRegB, LRegC) + LRegD + LData[9], 13);
  LRegC := TBits.RotateLeft32(P1(LRegD, LRegA, LRegB) + LRegC + LData[10], 14);
  LRegB := TBits.RotateLeft32(P1(LRegC, LRegD, LRegA) + LRegB + LData[11], 15);
  LRegA := TBits.RotateLeft32(P1(LRegB, LRegC, LRegD) + LRegA + LData[12], 6);
  LRegD := TBits.RotateLeft32(P1(LRegA, LRegB, LRegC) + LRegD + LData[13], 7);
  LRegC := TBits.RotateLeft32(P1(LRegD, LRegA, LRegB) + LRegC + LData[14], 9);
  LRegB := TBits.RotateLeft32(P1(LRegC, LRegD, LRegA) + LRegB + LData[15], 8);

  LRegA := TBits.RotateLeft32(P2(LRegB, LRegC, LRegD) + LRegA + LData[7] + C2, 7);
  LRegD := TBits.RotateLeft32(P2(LRegA, LRegB, LRegC) + LRegD + LData[4] + C2, 6);
  LRegC := TBits.RotateLeft32(P2(LRegD, LRegA, LRegB) + LRegC + LData[13] + C2, 8);
  LRegB := TBits.RotateLeft32(P2(LRegC, LRegD, LRegA) + LRegB + LData[1] + C2, 13);
  LRegA := TBits.RotateLeft32(P2(LRegB, LRegC, LRegD) + LRegA + LData[10] + C2, 11);
  LRegD := TBits.RotateLeft32(P2(LRegA, LRegB, LRegC) + LRegD + LData[6] + C2, 9);
  LRegC := TBits.RotateLeft32(P2(LRegD, LRegA, LRegB) + LRegC + LData[15] + C2, 7);
  LRegB := TBits.RotateLeft32(P2(LRegC, LRegD, LRegA) + LRegB + LData[3] + C2, 15);
  LRegA := TBits.RotateLeft32(P2(LRegB, LRegC, LRegD) + LRegA + LData[12] + C2, 7);
  LRegD := TBits.RotateLeft32(P2(LRegA, LRegB, LRegC) + LRegD + LData[0] + C2, 12);
  LRegC := TBits.RotateLeft32(P2(LRegD, LRegA, LRegB) + LRegC + LData[9] + C2, 15);
  LRegB := TBits.RotateLeft32(P2(LRegC, LRegD, LRegA) + LRegB + LData[5] + C2, 9);
  LRegA := TBits.RotateLeft32(P2(LRegB, LRegC, LRegD) + LRegA + LData[14] + C2, 7);
  LRegD := TBits.RotateLeft32(P2(LRegA, LRegB, LRegC) + LRegD + LData[2] + C2, 11);
  LRegC := TBits.RotateLeft32(P2(LRegD, LRegA, LRegB) + LRegC + LData[11] + C2, 13);
  LRegB := TBits.RotateLeft32(P2(LRegC, LRegD, LRegA) + LRegB + LData[8] + C2, 12);

  LRegA := TBits.RotateLeft32(P3(LRegB, LRegC, LRegD) + LRegA + LData[3] + C4, 11);
  LRegD := TBits.RotateLeft32(P3(LRegA, LRegB, LRegC) + LRegD + LData[10] + C4, 13);
  LRegC := TBits.RotateLeft32(P3(LRegD, LRegA, LRegB) + LRegC + LData[2] + C4, 14);
  LRegB := TBits.RotateLeft32(P3(LRegC, LRegD, LRegA) + LRegB + LData[4] + C4, 7);
  LRegA := TBits.RotateLeft32(P3(LRegB, LRegC, LRegD) + LRegA + LData[9] + C4, 14);
  LRegD := TBits.RotateLeft32(P3(LRegA, LRegB, LRegC) + LRegD + LData[15] + C4, 9);
  LRegC := TBits.RotateLeft32(P3(LRegD, LRegA, LRegB) + LRegC + LData[8] + C4, 13);
  LRegB := TBits.RotateLeft32(P3(LRegC, LRegD, LRegA) + LRegB + LData[1] + C4, 15);
  LRegA := TBits.RotateLeft32(P3(LRegB, LRegC, LRegD) + LRegA + LData[14] + C4, 6);
  LRegD := TBits.RotateLeft32(P3(LRegA, LRegB, LRegC) + LRegD + LData[7] + C4, 8);
  LRegC := TBits.RotateLeft32(P3(LRegD, LRegA, LRegB) + LRegC + LData[0] + C4, 13);
  LRegB := TBits.RotateLeft32(P3(LRegC, LRegD, LRegA) + LRegB + LData[6] + C4, 6);
  LRegA := TBits.RotateLeft32(P3(LRegB, LRegC, LRegD) + LRegA + LData[11] + C4, 12);
  LRegD := TBits.RotateLeft32(P3(LRegA, LRegB, LRegC) + LRegD + LData[13] + C4, 5);
  LRegC := TBits.RotateLeft32(P3(LRegD, LRegA, LRegB) + LRegC + LData[5] + C4, 7);
  LRegB := TBits.RotateLeft32(P3(LRegC, LRegD, LRegA) + LRegB + LData[12] + C4, 5);

  LRegPA := TBits.RotateLeft32(P1(LRegPB, LRegPC, LRegPD) + LRegPA + LData[0] + C1, 11);
  LRegPD := TBits.RotateLeft32(P1(LRegPA, LRegPB, LRegPC) + LRegPD + LData[1] + C1, 14);
  LRegPC := TBits.RotateLeft32(P1(LRegPD, LRegPA, LRegPB) + LRegPC + LData[2] + C1, 15);
  LRegPB := TBits.RotateLeft32(P1(LRegPC, LRegPD, LRegPA) + LRegPB + LData[3] + C1, 12);
  LRegPA := TBits.RotateLeft32(P1(LRegPB, LRegPC, LRegPD) + LRegPA + LData[4] + C1, 5);
  LRegPD := TBits.RotateLeft32(P1(LRegPA, LRegPB, LRegPC) + LRegPD + LData[5] + C1, 8);
  LRegPC := TBits.RotateLeft32(P1(LRegPD, LRegPA, LRegPB) + LRegPC + LData[6] + C1, 7);
  LRegPB := TBits.RotateLeft32(P1(LRegPC, LRegPD, LRegPA) + LRegPB + LData[7] + C1, 9);
  LRegPA := TBits.RotateLeft32(P1(LRegPB, LRegPC, LRegPD) + LRegPA + LData[8] + C1, 11);
  LRegPD := TBits.RotateLeft32(P1(LRegPA, LRegPB, LRegPC) + LRegPD + LData[9] + C1, 13);
  LRegPC := TBits.RotateLeft32(P1(LRegPD, LRegPA, LRegPB) + LRegPC + LData[10] + C1, 14);
  LRegPB := TBits.RotateLeft32(P1(LRegPC, LRegPD, LRegPA) + LRegPB + LData[11] + C1, 15);
  LRegPA := TBits.RotateLeft32(P1(LRegPB, LRegPC, LRegPD) + LRegPA + LData[12] + C1, 6);
  LRegPD := TBits.RotateLeft32(P1(LRegPA, LRegPB, LRegPC) + LRegPD + LData[13] + C1, 7);
  LRegPC := TBits.RotateLeft32(P1(LRegPD, LRegPA, LRegPB) + LRegPC + LData[14] + C1, 9);
  LRegPB := TBits.RotateLeft32(P1(LRegPC, LRegPD, LRegPA) + LRegPB + LData[15] + C1, 8);

  LRegPA := TBits.RotateLeft32(P2(LRegPB, LRegPC, LRegPD) + LRegPA + LData[7], 7);
  LRegPD := TBits.RotateLeft32(P2(LRegPA, LRegPB, LRegPC) + LRegPD + LData[4], 6);
  LRegPC := TBits.RotateLeft32(P2(LRegPD, LRegPA, LRegPB) + LRegPC + LData[13], 8);
  LRegPB := TBits.RotateLeft32(P2(LRegPC, LRegPD, LRegPA) + LRegPB + LData[1], 13);
  LRegPA := TBits.RotateLeft32(P2(LRegPB, LRegPC, LRegPD) + LRegPA + LData[10], 11);
  LRegPD := TBits.RotateLeft32(P2(LRegPA, LRegPB, LRegPC) + LRegPD + LData[6], 9);
  LRegPC := TBits.RotateLeft32(P2(LRegPD, LRegPA, LRegPB) + LRegPC + LData[15], 7);
  LRegPB := TBits.RotateLeft32(P2(LRegPC, LRegPD, LRegPA) + LRegPB + LData[3], 15);
  LRegPA := TBits.RotateLeft32(P2(LRegPB, LRegPC, LRegPD) + LRegPA + LData[12], 7);
  LRegPD := TBits.RotateLeft32(P2(LRegPA, LRegPB, LRegPC) + LRegPD + LData[0], 12);
  LRegPC := TBits.RotateLeft32(P2(LRegPD, LRegPA, LRegPB) + LRegPC + LData[9], 15);
  LRegPB := TBits.RotateLeft32(P2(LRegPC, LRegPD, LRegPA) + LRegPB + LData[5], 9);
  LRegPA := TBits.RotateLeft32(P2(LRegPB, LRegPC, LRegPD) + LRegPA + LData[14], 7);
  LRegPD := TBits.RotateLeft32(P2(LRegPA, LRegPB, LRegPC) + LRegPD + LData[2], 11);
  LRegPC := TBits.RotateLeft32(P2(LRegPD, LRegPA, LRegPB) + LRegPC + LData[11], 13);
  LRegPB := TBits.RotateLeft32(P2(LRegPC, LRegPD, LRegPA) + LRegPB + LData[8], 12);

  LRegPA := TBits.RotateLeft32(P3(LRegPB, LRegPC, LRegPD) + LRegPA + LData[3] + C3, 11);
  LRegPD := TBits.RotateLeft32(P3(LRegPA, LRegPB, LRegPC) + LRegPD + LData[10] + C3, 13);
  LRegPC := TBits.RotateLeft32(P3(LRegPD, LRegPA, LRegPB) + LRegPC + LData[2] + C3, 14);
  LRegPB := TBits.RotateLeft32(P3(LRegPC, LRegPD, LRegPA) + LRegPB + LData[4] + C3, 7);
  LRegPA := TBits.RotateLeft32(P3(LRegPB, LRegPC, LRegPD) + LRegPA + LData[9] + C3, 14);
  LRegPD := TBits.RotateLeft32(P3(LRegPA, LRegPB, LRegPC) + LRegPD + LData[15] + C3, 9);
  LRegPC := TBits.RotateLeft32(P3(LRegPD, LRegPA, LRegPB) + LRegPC + LData[8] + C3, 13);
  LRegPB := TBits.RotateLeft32(P3(LRegPC, LRegPD, LRegPA) + LRegPB + LData[1] + C3, 15);
  LRegPA := TBits.RotateLeft32(P3(LRegPB, LRegPC, LRegPD) + LRegPA + LData[14] + C3, 6);
  LRegPD := TBits.RotateLeft32(P3(LRegPA, LRegPB, LRegPC) + LRegPD + LData[7] + C3, 8);
  LRegPC := TBits.RotateLeft32(P3(LRegPD, LRegPA, LRegPB) + LRegPC + LData[0] + C3, 13);
  LRegPB := TBits.RotateLeft32(P3(LRegPC, LRegPD, LRegPA) + LRegPB + LData[6] + C3, 6);
  LRegPA := TBits.RotateLeft32(P3(LRegPB, LRegPC, LRegPD) + LRegPA + LData[11] + C3, 12);
  LRegPD := TBits.RotateLeft32(P3(LRegPA, LRegPB, LRegPC) + LRegPD + LData[13] + C3, 5);
  LRegPC := TBits.RotateLeft32(P3(LRegPD, LRegPA, LRegPB) + LRegPC + LData[5] + C3, 7);
  LRegPB := TBits.RotateLeft32(P3(LRegPC, LRegPD, LRegPA) + LRegPB + LData[12] + C3, 5);

  LRegPC := LRegPC + FState[0] + LRegB;
  FState[0] := FState[1] + LRegC + LRegPD;
  FState[1] := FState[2] + LRegD + LRegPA;
  FState[2] := FState[3] + LRegA + LRegPB;
  FState[3] := LRegPC;

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
