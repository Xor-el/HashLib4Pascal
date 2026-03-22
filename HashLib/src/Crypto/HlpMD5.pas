unit HlpMD5;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBits,
  HlpMDBase,
  HlpIHash,
  HlpConverters,
  HlpIHashInfo;

type
  TMD5 = class sealed(TMDBase, ITransformBlock)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

implementation

{ TMD5 }

function TMD5.Clone(): IHash;
var
  LHashInstance: TMD5;
begin
  LHashInstance := TMD5.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TMD5.Create;
begin
  inherited Create(4, 16);
end;

procedure TMD5.TransformBlock(AData: PByte; ADataLength: Int32; AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD: UInt32;
  LData: array [0 .. 15] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  LRegA := FState[0];
  LRegB := FState[1];
  LRegC := FState[2];
  LRegD := FState[3];

  LRegA := LData[0] + $D76AA478 + LRegA + ((LRegB and LRegC) or (not LRegB and LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 7) + LRegB;
  LRegD := LData[1] + $E8C7B756 + LRegD + ((LRegA and LRegB) or (not LRegA and LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 12) + LRegA;
  LRegC := LData[2] + $242070DB + LRegC + ((LRegD and LRegA) or (not LRegD and LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 17) + LRegD;
  LRegB := LData[3] + $C1BDCEEE + LRegB + ((LRegC and LRegD) or (not LRegC and LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 22) + LRegC;
  LRegA := LData[4] + $F57C0FAF + LRegA + ((LRegB and LRegC) or (not LRegB and LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 7) + LRegB;
  LRegD := LData[5] + $4787C62A + LRegD + ((LRegA and LRegB) or (not LRegA and LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 12) + LRegA;
  LRegC := LData[6] + $A8304613 + LRegC + ((LRegD and LRegA) or (not LRegD and LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 17) + LRegD;
  LRegB := LData[7] + $FD469501 + LRegB + ((LRegC and LRegD) or (not LRegC and LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 22) + LRegC;
  LRegA := LData[8] + $698098D8 + LRegA + ((LRegB and LRegC) or (not LRegB and LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 7) + LRegB;
  LRegD := LData[9] + $8B44F7AF + LRegD + ((LRegA and LRegB) or (not LRegA and LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 12) + LRegA;
  LRegC := LData[10] + $FFFF5BB1 + LRegC + ((LRegD and LRegA) or (not LRegD and LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 17) + LRegD;
  LRegB := LData[11] + $895CD7BE + LRegB + ((LRegC and LRegD) or (not LRegC and LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 22) + LRegC;
  LRegA := LData[12] + $6B901122 + LRegA + ((LRegB and LRegC) or (not LRegB and LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 7) + LRegB;
  LRegD := LData[13] + $FD987193 + LRegD + ((LRegA and LRegB) or (not LRegA and LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 12) + LRegA;
  LRegC := LData[14] + $A679438E + LRegC + ((LRegD and LRegA) or (not LRegD and LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 17) + LRegD;
  LRegB := LData[15] + $49B40821 + LRegB + ((LRegC and LRegD) or (not LRegC and LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 22) + LRegC;

  LRegA := LData[1] + $F61E2562 + LRegA + ((LRegB and LRegD) or (LRegC and not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5) + LRegB;
  LRegD := LData[6] + $C040B340 + LRegD + ((LRegA and LRegC) or (LRegB and not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9) + LRegA;
  LRegC := LData[11] + $265E5A51 + LRegC + ((LRegD and LRegB) or (LRegA and not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 14) + LRegD;
  LRegB := LData[0] + $E9B6C7AA + LRegB + ((LRegC and LRegA) or (LRegD and not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 20) + LRegC;
  LRegA := LData[5] + $D62F105D + LRegA + ((LRegB and LRegD) or (LRegC and not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5) + LRegB;
  LRegD := LData[10] + $2441453 + LRegD + ((LRegA and LRegC) or (LRegB and not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9) + LRegA;
  LRegC := LData[15] + $D8A1E681 + LRegC + ((LRegD and LRegB) or (LRegA and not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 14) + LRegD;
  LRegB := LData[4] + $E7D3FBC8 + LRegB + ((LRegC and LRegA) or (LRegD and not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 20) + LRegC;
  LRegA := LData[9] + $21E1CDE6 + LRegA + ((LRegB and LRegD) or (LRegC and not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5) + LRegB;
  LRegD := LData[14] + $C33707D6 + LRegD + ((LRegA and LRegC) or (LRegB and not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9) + LRegA;
  LRegC := LData[3] + $F4D50D87 + LRegC + ((LRegD and LRegB) or (LRegA and not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 14) + LRegD;
  LRegB := LData[8] + $455A14ED + LRegB + ((LRegC and LRegA) or (LRegD and not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 20) + LRegC;
  LRegA := LData[13] + $A9E3E905 + LRegA + ((LRegB and LRegD) or (LRegC and not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 5) + LRegB;
  LRegD := LData[2] + $FCEFA3F8 + LRegD + ((LRegA and LRegC) or (LRegB and not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 9) + LRegA;
  LRegC := LData[7] + $676F02D9 + LRegC + ((LRegD and LRegB) or (LRegA and not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 14) + LRegD;
  LRegB := LData[12] + $8D2A4C8A + LRegB + ((LRegC and LRegA) or (LRegD and not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 20) + LRegC;

  LRegA := LData[5] + $FFFA3942 + LRegA + (LRegB xor LRegC xor LRegD);
  LRegA := TBits.RotateLeft32(LRegA, 4) + LRegB;
  LRegD := LData[8] + $8771F681 + LRegD + (LRegA xor LRegB xor LRegC);
  LRegD := TBits.RotateLeft32(LRegD, 11) + LRegA;
  LRegC := LData[11] + $6D9D6122 + LRegC + (LRegD xor LRegA xor LRegB);
  LRegC := TBits.RotateLeft32(LRegC, 16) + LRegD;
  LRegB := LData[14] + $FDE5380C + LRegB + (LRegC xor LRegD xor LRegA);
  LRegB := TBits.RotateLeft32(LRegB, 23) + LRegC;
  LRegA := LData[1] + $A4BEEA44 + LRegA + (LRegB xor LRegC xor LRegD);
  LRegA := TBits.RotateLeft32(LRegA, 4) + LRegB;
  LRegD := LData[4] + $4BDECFA9 + LRegD + (LRegA xor LRegB xor LRegC);
  LRegD := TBits.RotateLeft32(LRegD, 11) + LRegA;
  LRegC := LData[7] + $F6BB4B60 + LRegC + (LRegD xor LRegA xor LRegB);
  LRegC := TBits.RotateLeft32(LRegC, 16) + LRegD;
  LRegB := LData[10] + $BEBFBC70 + LRegB + (LRegC xor LRegD xor LRegA);
  LRegB := TBits.RotateLeft32(LRegB, 23) + LRegC;
  LRegA := LData[13] + $289B7EC6 + LRegA + (LRegB xor LRegC xor LRegD);
  LRegA := TBits.RotateLeft32(LRegA, 4) + LRegB;
  LRegD := LData[0] + $EAA127FA + LRegD + (LRegA xor LRegB xor LRegC);
  LRegD := TBits.RotateLeft32(LRegD, 11) + LRegA;
  LRegC := LData[3] + $D4EF3085 + LRegC + (LRegD xor LRegA xor LRegB);
  LRegC := TBits.RotateLeft32(LRegC, 16) + LRegD;
  LRegB := LData[6] + $4881D05 + LRegB + (LRegC xor LRegD xor LRegA);
  LRegB := TBits.RotateLeft32(LRegB, 23) + LRegC;
  LRegA := LData[9] + $D9D4D039 + LRegA + (LRegB xor LRegC xor LRegD);
  LRegA := TBits.RotateLeft32(LRegA, 4) + LRegB;
  LRegD := LData[12] + $E6DB99E5 + LRegD + (LRegA xor LRegB xor LRegC);
  LRegD := TBits.RotateLeft32(LRegD, 11) + LRegA;
  LRegC := LData[15] + $1FA27CF8 + LRegC + (LRegD xor LRegA xor LRegB);
  LRegC := TBits.RotateLeft32(LRegC, 16) + LRegD;
  LRegB := LData[2] + $C4AC5665 + LRegB + (LRegC xor LRegD xor LRegA);
  LRegB := TBits.RotateLeft32(LRegB, 23) + LRegC;

  LRegA := LData[0] + $F4292244 + LRegA + (LRegC xor (LRegB or not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 6) + LRegB;
  LRegD := LData[7] + $432AFF97 + LRegD + (LRegB xor (LRegA or not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 10) + LRegA;
  LRegC := LData[14] + $AB9423A7 + LRegC + (LRegA xor (LRegD or not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 15) + LRegD;
  LRegB := LData[5] + $FC93A039 + LRegB + (LRegD xor (LRegC or not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 21) + LRegC;
  LRegA := LData[12] + $655B59C3 + LRegA + (LRegC xor (LRegB or not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 6) + LRegB;
  LRegD := LData[3] + $8F0CCC92 + LRegD + (LRegB xor (LRegA or not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 10) + LRegA;
  LRegC := LData[10] + $FFEFF47D + LRegC + (LRegA xor (LRegD or not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 15) + LRegD;
  LRegB := LData[1] + $85845DD1 + LRegB + (LRegD xor (LRegC or not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 21) + LRegC;
  LRegA := LData[8] + $6FA87E4F + LRegA + (LRegC xor (LRegB or not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 6) + LRegB;
  LRegD := LData[15] + $FE2CE6E0 + LRegD + (LRegB xor (LRegA or not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 10) + LRegA;
  LRegC := LData[6] + $A3014314 + LRegC + (LRegA xor (LRegD or not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 15) + LRegD;
  LRegB := LData[13] + $4E0811A1 + LRegB + (LRegD xor (LRegC or not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 21) + LRegC;
  LRegA := LData[4] + $F7537E82 + LRegA + (LRegC xor (LRegB or not LRegD));
  LRegA := TBits.RotateLeft32(LRegA, 6) + LRegB;
  LRegD := LData[11] + $BD3AF235 + LRegD + (LRegB xor (LRegA or not LRegC));
  LRegD := TBits.RotateLeft32(LRegD, 10) + LRegA;
  LRegC := LData[2] + $2AD7D2BB + LRegC + (LRegA xor (LRegD or not LRegB));
  LRegC := TBits.RotateLeft32(LRegC, 15) + LRegD;
  LRegB := LData[9] + $EB86D391 + LRegB + (LRegD xor (LRegC or not LRegA));
  LRegB := TBits.RotateLeft32(LRegB, 21) + LRegC;

  FState[0] := FState[0] + LRegA;
  FState[1] := FState[1] + LRegB;
  FState[2] := FState[2] + LRegC;
  FState[3] := FState[3] + LRegD;

  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
