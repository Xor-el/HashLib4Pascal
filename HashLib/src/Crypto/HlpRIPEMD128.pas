unit HlpRIPEMD128;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpMDBase,
  HlpBits,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo;

type
  TRIPEMD128 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

implementation

{ TRIPEMD128 }

function TRIPEMD128.Clone(): IHash;
var
  LHashInstance: TRIPEMD128;
begin
  LHashInstance := TRIPEMD128.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TRIPEMD128.Create;
begin
  inherited Create(4, 16);
end;

procedure TRIPEMD128.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegAa, LRegBb, LRegCc, LRegDd: UInt32;
  LData: array [0 .. 15] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];
  LRegAa := LRegA;
  LRegBb := LRegB;
  LRegCc := LRegC;
  LRegDd := LRegD;

  LRegA := LRegA + (LData[0] + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[1] + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 14);
  LRegC := LRegC + (LData[2] + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 15);
  LRegB := LRegB + (LData[3] + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 12);
  LRegA := LRegA + (LData[4] + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5);
  LRegD := LRegD + (LData[5] + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 8);
  LRegC := LRegC + (LData[6] + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 7);
  LRegB := LRegB + (LData[7] + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 9);
  LRegA := LRegA + (LData[8] + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[9] + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 13);
  LRegC := LRegC + (LData[10] + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 14);
  LRegB := LRegB + (LData[11] + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[12] + (LRegB xor LRegC xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 6);
  LRegD := LRegD + (LData[13] + (LRegA xor LRegB xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[14] + (LRegD xor LRegA xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[15] + (LRegC xor LRegD xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 8);

  LRegA := LRegA + (LData[7] + C2 + ((LRegB and LRegC) or (not LRegB and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 7);
  LRegD := LRegD + (LData[4] + C2 + ((LRegA and LRegB) or (not LRegA and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 6);
  LRegC := LRegC + (LData[13] + C2 + ((LRegD and LRegA) or (not LRegD and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 8);
  LRegB := LRegB + (LData[1] + C2 + ((LRegC and LRegD) or (not LRegC and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 13);
  LRegA := LRegA + (LData[10] + C2 + ((LRegB and LRegC) or (not LRegB and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[6] + C2 + ((LRegA and LRegB) or (not LRegA and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[15] + C2 + ((LRegD and LRegA) or (not LRegD and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 7);
  LRegB := LRegB + (LData[3] + C2 + ((LRegC and LRegD) or (not LRegC and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[12] + C2 + ((LRegB and LRegC) or (not LRegB and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 7);
  LRegD := LRegD + (LData[0] + C2 + ((LRegA and LRegB) or (not LRegA and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 12);
  LRegC := LRegC + (LData[9] + C2 + ((LRegD and LRegA) or (not LRegD and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 15);
  LRegB := LRegB + (LData[5] + C2 + ((LRegC and LRegD) or (not LRegC and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 9);
  LRegA := LRegA + (LData[2] + C2 + ((LRegB and LRegC) or (not LRegB and LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[14] + C2 + ((LRegA and LRegB) or (not LRegA and LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 7);
  LRegC := LRegC + (LData[11] + C2 + ((LRegD and LRegA) or (not LRegD and LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 13);
  LRegB := LRegB + (LData[8] + C2 + ((LRegC and LRegD) or (not LRegC and LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 12);

  LRegA := LRegA + (LData[3] + C4 + ((LRegB or not LRegC) xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[10] + C4 + ((LRegA or not LRegB) xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 13);
  LRegC := LRegC + (LData[14] + C4 + ((LRegD or not LRegA) xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 6);
  LRegB := LRegB + (LData[4] + C4 + ((LRegC or not LRegD) xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 7);
  LRegA := LRegA + (LData[9] + C4 + ((LRegB or not LRegC) xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 14);
  LRegD := LRegD + (LData[15] + C4 + ((LRegA or not LRegB) xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9);
  LRegC := LRegC + (LData[8] + C4 + ((LRegD or not LRegA) xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 13);
  LRegB := LRegB + (LData[1] + C4 + ((LRegC or not LRegD) xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[2] + C4 + ((LRegB or not LRegC) xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 14);
  LRegD := LRegD + (LData[7] + C4 + ((LRegA or not LRegB) xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 8);
  LRegC := LRegC + (LData[0] + C4 + ((LRegD or not LRegA) xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 13);
  LRegB := LRegB + (LData[6] + C4 + ((LRegC or not LRegD) xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 6);
  LRegA := LRegA + (LData[13] + C4 + ((LRegB or not LRegC) xor LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5);
  LRegD := LRegD + (LData[11] + C4 + ((LRegA or not LRegB) xor LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 12);
  LRegC := LRegC + (LData[5] + C4 + ((LRegD or not LRegA) xor LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 7);
  LRegB := LRegB + (LData[12] + C4 + ((LRegC or not LRegD) xor LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 5);

  LRegA := LRegA + (LData[1] + C6 + ((LRegB and LRegD) or (LRegC and not LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 11);
  LRegD := LRegD + (LData[9] + C6 + ((LRegA and LRegC) or (LRegB and not LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 12);
  LRegC := LRegC + (LData[11] + C6 + ((LRegD and LRegB) or (LRegA and not LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 14);
  LRegB := LRegB + (LData[10] + C6 + ((LRegC and LRegA) or (LRegD and not LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 15);
  LRegA := LRegA + (LData[0] + C6 + ((LRegB and LRegD) or (LRegC and not LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 14);
  LRegD := LRegD + (LData[8] + C6 + ((LRegA and LRegC) or (LRegB and not LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 15);
  LRegC := LRegC + (LData[12] + C6 + ((LRegD and LRegB) or (LRegA and not LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 9);
  LRegB := LRegB + (LData[4] + C6 + ((LRegC and LRegA) or (LRegD and not LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 8);
  LRegA := LRegA + (LData[13] + C6 + ((LRegB and LRegD) or (LRegC and not LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 9);
  LRegD := LRegD + (LData[3] + C6 + ((LRegA and LRegC) or (LRegB and not LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 14);
  LRegC := LRegC + (LData[7] + C6 + ((LRegD and LRegB) or (LRegA and not LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 5);
  LRegB := LRegB + (LData[15] + C6 + ((LRegC and LRegA) or (LRegD and not LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 6);
  LRegA := LRegA + (LData[14] + C6 + ((LRegB and LRegD) or (LRegC and not LRegD)));
  LRegA := TBits.RotateLeft32(LRegA, 8);
  LRegD := LRegD + (LData[5] + C6 + ((LRegA and LRegC) or (LRegB and not LRegC)));
  LRegD := TBits.RotateLeft32(LRegD, 6);
  LRegC := LRegC + (LData[6] + C6 + ((LRegD and LRegB) or (LRegA and not LRegB)));
  LRegC := TBits.RotateLeft32(LRegC, 5);
  LRegB := LRegB + (LData[2] + C6 + ((LRegC and LRegA) or (LRegD and not LRegA)));
  LRegB := TBits.RotateLeft32(LRegB, 12);

  LRegAa := LRegAa + (LData[5] + C1 + ((LRegBb and LRegDd) or (LRegCc and not LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 8);
  LRegDd := LRegDd + (LData[14] + C1 + ((LRegAa and LRegCc) or (LRegBb and not LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 9);
  LRegCc := LRegCc + (LData[7] + C1 + ((LRegDd and LRegBb) or (LRegAa and not LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 9);
  LRegBb := LRegBb + (LData[0] + C1 + ((LRegCc and LRegAa) or (LRegDd and not LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);
  LRegAa := LRegAa + (LData[9] + C1 + ((LRegBb and LRegDd) or (LRegCc and not LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 13);
  LRegDd := LRegDd + (LData[2] + C1 + ((LRegAa and LRegCc) or (LRegBb and not LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 15);
  LRegCc := LRegCc + (LData[11] + C1 + ((LRegDd and LRegBb) or (LRegAa and not LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 15);
  LRegBb := LRegBb + (LData[4] + C1 + ((LRegCc and LRegAa) or (LRegDd and not LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 5);
  LRegAa := LRegAa + (LData[13] + C1 + ((LRegBb and LRegDd) or (LRegCc and not LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 7);
  LRegDd := LRegDd + (LData[6] + C1 + ((LRegAa and LRegCc) or (LRegBb and not LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 7);
  LRegCc := LRegCc + (LData[15] + C1 + ((LRegDd and LRegBb) or (LRegAa and not LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 8);
  LRegBb := LRegBb + (LData[8] + C1 + ((LRegCc and LRegAa) or (LRegDd and not LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);
  LRegAa := LRegAa + (LData[1] + C1 + ((LRegBb and LRegDd) or (LRegCc and not LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 14);
  LRegDd := LRegDd + (LData[10] + C1 + ((LRegAa and LRegCc) or (LRegBb and not LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 14);
  LRegCc := LRegCc + (LData[3] + C1 + ((LRegDd and LRegBb) or (LRegAa and not LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 12);
  LRegBb := LRegBb + (LData[12] + C1 + ((LRegCc and LRegAa) or (LRegDd and not LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 6);

  LRegAa := LRegAa + (LData[6] + C3 + ((LRegBb or not LRegCc) xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 9);
  LRegDd := LRegDd + (LData[11] + C3 + ((LRegAa or not LRegBb) xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 13);
  LRegCc := LRegCc + (LData[3] + C3 + ((LRegDd or not LRegAa) xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 15);
  LRegBb := LRegBb + (LData[7] + C3 + ((LRegCc or not LRegDd) xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 7);
  LRegAa := LRegAa + (LData[0] + C3 + ((LRegBb or not LRegCc) xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 12);
  LRegDd := LRegDd + (LData[13] + C3 + ((LRegAa or not LRegBb) xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 8);
  LRegCc := LRegCc + (LData[5] + C3 + ((LRegDd or not LRegAa) xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 9);
  LRegBb := LRegBb + (LData[10] + C3 + ((LRegCc or not LRegDd) xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);
  LRegAa := LRegAa + (LData[14] + C3 + ((LRegBb or not LRegCc) xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 7);
  LRegDd := LRegDd + (LData[15] + C3 + ((LRegAa or not LRegBb) xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 7);
  LRegCc := LRegCc + (LData[8] + C3 + ((LRegDd or not LRegAa) xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 12);
  LRegBb := LRegBb + (LData[12] + C3 + ((LRegCc or not LRegDd) xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 7);
  LRegAa := LRegAa + (LData[4] + C3 + ((LRegBb or not LRegCc) xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 6);
  LRegDd := LRegDd + (LData[9] + C3 + ((LRegAa or not LRegBb) xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 15);
  LRegCc := LRegCc + (LData[1] + C3 + ((LRegDd or not LRegAa) xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 13);
  LRegBb := LRegBb + (LData[2] + C3 + ((LRegCc or not LRegDd) xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);

  LRegAa := LRegAa + (LData[15] + C5 + ((LRegBb and LRegCc) or (not LRegBb and LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 9);
  LRegDd := LRegDd + (LData[5] + C5 + ((LRegAa and LRegBb) or (not LRegAa and LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 7);
  LRegCc := LRegCc + (LData[1] + C5 + ((LRegDd and LRegAa) or (not LRegDd and LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 15);
  LRegBb := LRegBb + (LData[3] + C5 + ((LRegCc and LRegDd) or (not LRegCc and LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);
  LRegAa := LRegAa + (LData[7] + C5 + ((LRegBb and LRegCc) or (not LRegBb and LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 8);
  LRegDd := LRegDd + (LData[14] + C5 + ((LRegAa and LRegBb) or (not LRegAa and LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 6);
  LRegCc := LRegCc + (LData[6] + C5 + ((LRegDd and LRegAa) or (not LRegDd and LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 6);
  LRegBb := LRegBb + (LData[9] + C5 + ((LRegCc and LRegDd) or (not LRegCc and LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 14);
  LRegAa := LRegAa + (LData[11] + C5 + ((LRegBb and LRegCc) or (not LRegBb and LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 12);
  LRegDd := LRegDd + (LData[8] + C5 + ((LRegAa and LRegBb) or (not LRegAa and LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 13);
  LRegCc := LRegCc + (LData[12] + C5 + ((LRegDd and LRegAa) or (not LRegDd and LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 5);
  LRegBb := LRegBb + (LData[2] + C5 + ((LRegCc and LRegDd) or (not LRegCc and LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 14);
  LRegAa := LRegAa + (LData[10] + C5 + ((LRegBb and LRegCc) or (not LRegBb and LRegDd)));
  LRegAa := TBits.RotateLeft32(LRegAa, 13);
  LRegDd := LRegDd + (LData[0] + C5 + ((LRegAa and LRegBb) or (not LRegAa and LRegCc)));
  LRegDd := TBits.RotateLeft32(LRegDd, 13);
  LRegCc := LRegCc + (LData[4] + C5 + ((LRegDd and LRegAa) or (not LRegDd and LRegBb)));
  LRegCc := TBits.RotateLeft32(LRegCc, 7);
  LRegBb := LRegBb + (LData[13] + C5 + ((LRegCc and LRegDd) or (not LRegCc and LRegAa)));
  LRegBb := TBits.RotateLeft32(LRegBb, 5);

  LRegAa := LRegAa + (LData[8] + (LRegBb xor LRegCc xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 15);
  LRegDd := LRegDd + (LData[6] + (LRegAa xor LRegBb xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 5);
  LRegCc := LRegCc + (LData[4] + (LRegDd xor LRegAa xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 8);
  LRegBb := LRegBb + (LData[1] + (LRegCc xor LRegDd xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 11);
  LRegAa := LRegAa + (LData[3] + (LRegBb xor LRegCc xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 14);
  LRegDd := LRegDd + (LData[11] + (LRegAa xor LRegBb xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 14);
  LRegCc := LRegCc + (LData[15] + (LRegDd xor LRegAa xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 6);
  LRegBb := LRegBb + (LData[0] + (LRegCc xor LRegDd xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 14);
  LRegAa := LRegAa + (LData[5] + (LRegBb xor LRegCc xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 6);
  LRegDd := LRegDd + (LData[12] + (LRegAa xor LRegBb xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 9);
  LRegCc := LRegCc + (LData[2] + (LRegDd xor LRegAa xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 12);
  LRegBb := LRegBb + (LData[13] + (LRegCc xor LRegDd xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 9);
  LRegAa := LRegAa + (LData[9] + (LRegBb xor LRegCc xor LRegDd));
  LRegAa := TBits.RotateLeft32(LRegAa, 12);
  LRegDd := LRegDd + (LData[7] + (LRegAa xor LRegBb xor LRegCc));
  LRegDd := TBits.RotateLeft32(LRegDd, 5);
  LRegCc := LRegCc + (LData[10] + (LRegDd xor LRegAa xor LRegBb));
  LRegCc := TBits.RotateLeft32(LRegCc, 15);
  LRegBb := LRegBb + (LData[14] + (LRegCc xor LRegDd xor LRegAa));
  LRegBb := TBits.RotateLeft32(LRegBb, 8);

  LRegDd := LRegDd + LRegC + FState[1];
  FState[1] := FState[2] + LRegD + LRegAa;
  FState[2] := FState[3] + LRegA + LRegBb;
  FState[3] := FState[0] + LRegB + LRegCc;
  FState[0] := LRegDd;

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
