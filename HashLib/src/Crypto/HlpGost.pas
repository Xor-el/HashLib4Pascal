unit HlpGost;

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

  TGost = class sealed(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  type
    TSBoxType = (TestParamSet, CryptoProParamSet);
  strict private

    class var

      FSBox1_Test, FSBox2_Test, FSBox3_Test, FSBox4_Test: THashLibUInt32Array;
      FSBox1_CryptoPro, FSBox2_CryptoPro, FSBox3_CryptoPro,
        FSBox4_CryptoPro: THashLibUInt32Array;

  var
    FState, FHash: THashLibUInt32Array;
    FSBox1, FSBox2, FSBox3, FSBox4: THashLibUInt32Array;
    FSBoxType: TSBoxType;

    procedure Compress(APtr: PCardinal);
    class procedure ComputeSBoxes(const ASBox: THashLibMatrixUInt32Array;
      out ASBox1, ASBox2, ASBox3, ASBox4: THashLibUInt32Array); static;
    class constructor Gost();

  strict protected
    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create(ASBoxType: TSBoxType = TSBoxType.TestParamSet);
    procedure Initialize(); override;
    function Clone(): IHash; override;

  end;

implementation

{ TGost }

function TGost.Clone(): IHash;
var
  LHashInstance: TGost;
begin
  LHashInstance := TGost.Create(FSBoxType);
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

procedure TGost.Compress(APtr: PCardinal);
var
  LUWord0, LUWord1, LUWord2, LUWord3, LUWord4, LUWord5, LUWord6, LUWord7, LVWord0, LVWord1, LVWord2, LVWord3, LVWord4, LVWord5, LVWord6, LVWord7, LWWord0, LWWord1, LWWord2,
    LWWord3, LWWord4, LWWord5, LWWord6, LWWord7, LKey0, LKey1, LKey2, LKey3, LKey4, LKey5, LKey6, LKey7, LRight, LLeft,
    LTemp: UInt32;
  LStep: Int32;
  LScratch: array [0 .. 7] of UInt32;
begin
  LUWord0 := FHash[0];
  LUWord1 := FHash[1];
  LUWord2 := FHash[2];
  LUWord3 := FHash[3];
  LUWord4 := FHash[4];
  LUWord5 := FHash[5];
  LUWord6 := FHash[6];
  LUWord7 := FHash[7];

  LVWord0 := APtr[0];
  LVWord1 := APtr[1];
  LVWord2 := APtr[2];
  LVWord3 := APtr[3];
  LVWord4 := APtr[4];
  LVWord5 := APtr[5];
  LVWord6 := APtr[6];
  LVWord7 := APtr[7];

  LStep := 0;

  while LStep < 8 do
  begin
    LWWord0 := LUWord0 xor LVWord0;
    LWWord1 := LUWord1 xor LVWord1;
    LWWord2 := LUWord2 xor LVWord2;
    LWWord3 := LUWord3 xor LVWord3;
    LWWord4 := LUWord4 xor LVWord4;
    LWWord5 := LUWord5 xor LVWord5;
    LWWord6 := LUWord6 xor LVWord6;
    LWWord7 := LUWord7 xor LVWord7;

    LKey0 := UInt32(Byte(LWWord0)) or (UInt32(Byte(LWWord2)) shl 8) or
      (UInt32(Byte(LWWord4)) shl 16) or (UInt32(Byte(LWWord6)) shl 24);
    LKey1 := UInt32(Byte(LWWord0 shr 8)) or (LWWord2 and $0000FF00) or
      ((LWWord4 and $0000FF00) shl 8) or ((LWWord6 and $0000FF00) shl 16);
    LKey2 := UInt32(Byte(LWWord0 shr 16)) or ((LWWord2 and $00FF0000) shr 8) or
      (LWWord4 and $00FF0000) or ((LWWord6 and $00FF0000) shl 8);
    LKey3 := (LWWord0 shr 24) or ((LWWord2 and $FF000000) shr 16) or
      ((LWWord4 and $FF000000) shr 8) or (LWWord6 and $FF000000);
    LKey4 := UInt32(Byte(LWWord1)) or ((LWWord3 and $000000FF) shl 8) or
      ((LWWord5 and $000000FF) shl 16) or ((LWWord7 and $000000FF) shl 24);
    LKey5 := UInt32(Byte(LWWord1 shr 8)) or (LWWord3 and $0000FF00) or
      ((LWWord5 and $0000FF00) shl 8) or ((LWWord7 and $0000FF00) shl 16);
    LKey6 := UInt32(Byte(LWWord1 shr 16)) or ((LWWord3 and $00FF0000) shr 8) or
      (LWWord5 and $00FF0000) or ((LWWord7 and $00FF0000) shl 8);
    LKey7 := (LWWord1 shr 24) or ((LWWord3 and $FF000000) shr 16) or
      ((LWWord5 and $FF000000) shr 8) or (LWWord7 and $FF000000);

    LRight := FHash[LStep];
    LLeft := FHash[LStep + 1];

    LTemp := LKey0 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey1 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey2 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey3 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey4 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey5 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey6 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey7 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey0 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey1 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey2 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey3 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey4 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey5 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey6 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey7 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey0 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey1 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey2 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey3 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey4 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey5 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey6 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey7 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey7 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey6 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey5 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey4 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey3 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey2 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey1 + LRight;
    LLeft := LLeft xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);
    LTemp := LKey0 + LLeft;
    LRight := LRight xor (FSBox1[Byte(LTemp)] xor FSBox2[Byte(LTemp shr 8)] xor FSBox3
      [Byte(LTemp shr 16)] xor FSBox4[LTemp shr 24]);

    LTemp := LRight;
    LRight := LLeft;
    LLeft := LTemp;

    LScratch[LStep] := LRight;
    LScratch[LStep + 1] := LLeft;

    if (LStep = 6) then
      break;

    LLeft := LUWord0 xor LUWord2;
    LRight := LUWord1 xor LUWord3;
    LUWord0 := LUWord2;
    LUWord1 := LUWord3;
    LUWord2 := LUWord4;
    LUWord3 := LUWord5;
    LUWord4 := LUWord6;
    LUWord5 := LUWord7;
    LUWord6 := LLeft;
    LUWord7 := LRight;

    if (LStep = 2) then
    begin
      LUWord0 := LUWord0 xor $FF00FF00;
      LUWord1 := LUWord1 xor $FF00FF00;
      LUWord2 := LUWord2 xor $00FF00FF;
      LUWord3 := LUWord3 xor $00FF00FF;
      LUWord4 := LUWord4 xor $00FFFF00;
      LUWord5 := LUWord5 xor $FF0000FF;
      LUWord6 := LUWord6 xor $000000FF;
      LUWord7 := LUWord7 xor $FF00FFFF;
    end;

    LLeft := LVWord0;
    LRight := LVWord2;
    LVWord0 := LVWord4;
    LVWord2 := LVWord6;
    LVWord4 := LLeft xor LRight;
    LVWord6 := LVWord0 xor LRight;
    LLeft := LVWord1;
    LRight := LVWord3;
    LVWord1 := LVWord5;
    LVWord3 := LVWord7;
    LVWord5 := LLeft xor LRight;
    LVWord7 := LVWord1 xor LRight;

    System.Inc(LStep, 2);
  end;

  LUWord0 := APtr[0] xor LScratch[6];
  LUWord1 := APtr[1] xor LScratch[7];
  LUWord2 := APtr[2] xor (LScratch[0] shl 16) xor (LScratch[0] shr 16) xor (LScratch[0] and $FFFF)
    xor (LScratch[1] and $FFFF) xor (LScratch[1] shr 16) xor (LScratch[2] shl 16)
    xor LScratch[6] xor (LScratch[6] shl 16) xor (LScratch[7] and $FFFF0000) xor (LScratch[7] shr 16);
  LUWord3 := APtr[3] xor (LScratch[0] and $FFFF) xor (LScratch[0] shl 16) xor (LScratch[1] and $FFFF)
    xor (LScratch[1] shl 16) xor (LScratch[1] shr 16) xor (LScratch[2] shl 16) xor (LScratch[2] shr 16)
    xor (LScratch[3] shl 16) xor LScratch[6] xor (LScratch[6] shl 16) xor (LScratch[6] shr 16)
    xor (LScratch[7] and $FFFF) xor (LScratch[7] shl 16) xor (LScratch[7] shr 16);
  LUWord4 := APtr[4] xor (LScratch[0] and $FFFF0000) xor (LScratch[0] shl 16) xor (LScratch[0] shr 16)
    xor (LScratch[1] and $FFFF0000) xor (LScratch[1] shr 16) xor (LScratch[2] shl 16)
    xor (LScratch[2] shr 16) xor (LScratch[3] shl 16) xor (LScratch[3] shr 16) xor (LScratch[4] shl 16)
    xor (LScratch[6] shl 16) xor (LScratch[6] shr 16) xor (LScratch[7] and $FFFF) xor (LScratch[7] shl 16)
    xor (LScratch[7] shr 16);
  LUWord5 := APtr[5] xor (LScratch[0] shl 16) xor (LScratch[0] shr 16) xor (LScratch[0] and $FFFF0000)
    xor (LScratch[1] and $FFFF) xor LScratch[2] xor (LScratch[2] shr 16) xor (LScratch[3] shl 16)
    xor (LScratch[3] shr 16) xor (LScratch[4] shl 16) xor (LScratch[4] shr 16) xor (LScratch[5] shl 16)
    xor (LScratch[6] shl 16) xor (LScratch[6] shr 16) xor (LScratch[7] and $FFFF0000)
    xor (LScratch[7] shl 16) xor (LScratch[7] shr 16);
  LUWord6 := APtr[6] xor LScratch[0] xor (LScratch[1] shr 16) xor (LScratch[2] shl 16)
    xor LScratch[3] xor (LScratch[3] shr 16) xor (LScratch[4] shl 16) xor (LScratch[4] shr 16)
    xor (LScratch[5] shl 16) xor (LScratch[5] shr 16) xor LScratch[6] xor (LScratch[6] shl 16)
    xor (LScratch[6] shr 16) xor (LScratch[7] shl 16);
  LUWord7 := APtr[7] xor (LScratch[0] and $FFFF0000) xor (LScratch[0] shl 16) xor (LScratch[1] and $FFFF)
    xor (LScratch[1] shl 16) xor (LScratch[2] shr 16) xor (LScratch[3] shl 16)
    xor LScratch[4] xor (LScratch[4] shr 16) xor (LScratch[5] shl 16) xor (LScratch[5] shr 16)
    xor (LScratch[6] shr 16) xor (LScratch[7] and $FFFF) xor (LScratch[7] shl 16) xor (LScratch[7] shr 16);

  LVWord0 := FHash[0] xor (LUWord1 shl 16) xor (LUWord0 shr 16);
  LVWord1 := FHash[1] xor (LUWord2 shl 16) xor (LUWord1 shr 16);
  LVWord2 := FHash[2] xor (LUWord3 shl 16) xor (LUWord2 shr 16);
  LVWord3 := FHash[3] xor (LUWord4 shl 16) xor (LUWord3 shr 16);
  LVWord4 := FHash[4] xor (LUWord5 shl 16) xor (LUWord4 shr 16);
  LVWord5 := FHash[5] xor (LUWord6 shl 16) xor (LUWord5 shr 16);
  LVWord6 := FHash[6] xor (LUWord7 shl 16) xor (LUWord6 shr 16);
  LVWord7 := FHash[7] xor (LUWord0 and $FFFF0000) xor (LUWord0 shl 16) xor (LUWord7 shr 16)
    xor (LUWord1 and $FFFF0000) xor (LUWord1 shl 16) xor (LUWord6 shl 16)
    xor (LUWord7 and $FFFF0000);

  FHash[0] := (LVWord0 and $FFFF0000) xor (LVWord0 shl 16) xor (LVWord0 shr 16) xor (LVWord1 shr 16)
    xor (LVWord1 and $FFFF0000) xor (LVWord2 shl 16) xor (LVWord3 shr 16) xor (LVWord4 shl 16)
    xor (LVWord5 shr 16) xor LVWord5 xor (LVWord6 shr 16) xor (LVWord7 shl 16) xor (LVWord7 shr 16)
    xor (LVWord7 and $FFFF);
  FHash[1] := (LVWord0 shl 16) xor (LVWord0 shr 16) xor (LVWord0 and $FFFF0000)
    xor (LVWord1 and $FFFF) xor LVWord2 xor (LVWord2 shr 16) xor (LVWord3 shl 16) xor (LVWord4 shr 16)
    xor (LVWord5 shl 16) xor (LVWord6 shl 16) xor LVWord6 xor (LVWord7 and $FFFF0000)
    xor (LVWord7 shr 16);
  FHash[2] := (LVWord0 and $FFFF) xor (LVWord0 shl 16) xor (LVWord1 shl 16) xor (LVWord1 shr 16)
    xor (LVWord1 and $FFFF0000) xor (LVWord2 shl 16) xor (LVWord3 shr 16)
    xor LVWord3 xor (LVWord4 shl 16) xor (LVWord5 shr 16) xor LVWord6 xor (LVWord6 shr 16)
    xor (LVWord7 and $FFFF) xor (LVWord7 shl 16) xor (LVWord7 shr 16);
  FHash[3] := (LVWord0 shl 16) xor (LVWord0 shr 16) xor (LVWord0 and $FFFF0000)
    xor (LVWord1 and $FFFF0000) xor (LVWord1 shr 16) xor (LVWord2 shl 16) xor (LVWord2 shr 16)
    xor LVWord2 xor (LVWord3 shl 16) xor (LVWord4 shr 16) xor LVWord4 xor (LVWord5 shl 16)
    xor (LVWord6 shl 16) xor (LVWord7 and $FFFF) xor (LVWord7 shr 16);
  FHash[4] := (LVWord0 shr 16) xor (LVWord1 shl 16) xor LVWord1 xor (LVWord2 shr 16)
    xor LVWord2 xor (LVWord3 shl 16) xor (LVWord3 shr 16) xor LVWord3 xor (LVWord4 shl 16)
    xor (LVWord5 shr 16) xor LVWord5 xor (LVWord6 shl 16) xor (LVWord6 shr 16) xor (LVWord7 shl 16);
  FHash[5] := (LVWord0 shl 16) xor (LVWord0 and $FFFF0000) xor (LVWord1 shl 16) xor (LVWord1 shr 16)
    xor (LVWord1 and $FFFF0000) xor (LVWord2 shl 16) xor LVWord2 xor (LVWord3 shr 16)
    xor LVWord3 xor (LVWord4 shl 16) xor (LVWord4 shr 16) xor LVWord4 xor (LVWord5 shl 16)
    xor (LVWord6 shl 16) xor (LVWord6 shr 16) xor LVWord6 xor (LVWord7 shl 16) xor (LVWord7 shr 16)
    xor (LVWord7 and $FFFF0000);
  FHash[6] := LVWord0 xor LVWord2 xor (LVWord2 shr 16) xor LVWord3 xor (LVWord3 shl 16)
    xor LVWord4 xor (LVWord4 shr 16) xor (LVWord5 shl 16) xor (LVWord5 shr 16)
    xor LVWord5 xor (LVWord6 shl 16) xor (LVWord6 shr 16) xor LVWord6 xor (LVWord7 shl 16) xor LVWord7;
  FHash[7] := LVWord0 xor (LVWord0 shr 16) xor (LVWord1 shl 16) xor (LVWord1 shr 16) xor (LVWord2 shl 16)
    xor (LVWord3 shr 16) xor LVWord3 xor (LVWord4 shl 16) xor LVWord4 xor (LVWord5 shr 16)
    xor LVWord5 xor (LVWord6 shl 16) xor (LVWord6 shr 16) xor (LVWord7 shl 16) xor LVWord7;

end;

class procedure TGost.ComputeSBoxes(const ASBox: THashLibMatrixUInt32Array;
  out ASBox1, ASBox2, ASBox3, ASBox4: THashLibUInt32Array);
var
  LIdx, LRowIdx, LColIdx: Int32;
  LWordA, LWordB, LWordC, LWordD: UInt32;
begin
  System.SetLength(ASBox1, 256);
  System.SetLength(ASBox2, 256);
  System.SetLength(ASBox3, 256);
  System.SetLength(ASBox4, 256);

  LIdx := 0;

  for LRowIdx := 0 to 15 do
  begin
    LWordA := ASBox[1, LRowIdx] shl 15;
    LWordB := ASBox[3, LRowIdx] shl 23;
    LWordC := ASBox[5, LRowIdx];
    LWordC := TBits.RotateRight32(LWordC, 1);
    LWordD := ASBox[7, LRowIdx] shl 7;

    for LColIdx := 0 to 15 do
    begin
      ASBox1[LIdx] := LWordA or (ASBox[0, LColIdx] shl 11);
      ASBox2[LIdx] := LWordB or (ASBox[2, LColIdx] shl 19);
      ASBox3[LIdx] := LWordC or (ASBox[4, LColIdx] shl 27);
      ASBox4[LIdx] := LWordD or (ASBox[6, LColIdx] shl 3);
      System.Inc(LIdx);
    end;
  end;
end;

constructor TGost.Create(ASBoxType: TGost.TSBoxType);
begin
  inherited Create(32, 32);
  System.SetLength(FState, 8);
  System.SetLength(FHash, 8);
  FSBoxType := ASBoxType;
  case ASBoxType of
    TGost.TSBoxType.TestParamSet:
      begin
        FSBox1 := FSBox1_Test;
        FSBox2 := FSBox2_Test;
        FSBox3 := FSBox3_Test;
        FSBox4 := FSBox4_Test;
      end;
    TGost.TSBoxType.CryptoProParamSet:
      begin
        FSBox1 := FSBox1_CryptoPro;
        FSBox2 := FSBox2_CryptoPro;
        FSBox3 := FSBox3_CryptoPro;
        FSBox4 := FSBox4_CryptoPro;
      end;
  end;
end;

procedure TGost.Finish;
var
  LBits: UInt64;
  LPad: THashLibByteArray;
  LLength: THashLibUInt32Array;
begin
  LBits := FProcessedBytesCount * 8;

  if (FBuffer.Position > 0) then
  begin
    System.SetLength(LPad, 32 - FBuffer.Position);
    TransformBytes(LPad, 0, 32 - FBuffer.Position);
  end;
  System.SetLength(LLength, 8);
  LLength[0] := UInt32(LBits);
  LLength[1] := UInt32(LBits shr 32);

  Compress(PCardinal(LLength));

  Compress(PCardinal(FState));
end;

function TGost.GetResult: THashLibByteArray;
begin
  System.SetLength(Result, 8 * System.SizeOf(UInt32));
  TConverters.le32_copy(PCardinal(FHash), 0, PByte(Result), 0,
    System.Length(Result));
end;

class constructor TGost.Gost;
var
  LSBox: THashLibMatrixUInt32Array;
begin
  // DSbox_Test (id-GostR3411-94-TestParamSet)
  LSBox := THashLibMatrixUInt32Array.Create(THashLibUInt32Array.Create(4, 10, 9,
    2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3), THashLibUInt32Array.Create(14,
    11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    THashLibUInt32Array.Create(5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9,
    11), THashLibUInt32Array.Create(7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11,
    2, 5, 3), THashLibUInt32Array.Create(6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9,
    14, 0, 3, 11, 2), THashLibUInt32Array.Create(4, 11, 10, 0, 7, 2, 1, 13, 3,
    6, 8, 5, 9, 12, 15, 14), THashLibUInt32Array.Create(13, 11, 4, 1, 3, 15, 5,
    9, 0, 10, 14, 7, 6, 8, 2, 12), THashLibUInt32Array.Create(1, 15, 13, 0, 5,
    7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12));

  ComputeSBoxes(LSBox, FSBox1_Test, FSBox2_Test, FSBox3_Test, FSBox4_Test);

  // DSbox_A (id-GostR3411-94-CryptoProParamSet)
  LSBox := THashLibMatrixUInt32Array.Create(THashLibUInt32Array.Create(10, 4, 5,
    6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15), THashLibUInt32Array.Create(5,
    15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8),
    THashLibUInt32Array.Create(7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8,
    13), THashLibUInt32Array.Create(4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13,
    11, 9, 3), THashLibUInt32Array.Create(7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0,
    14, 15, 13, 3, 5), THashLibUInt32Array.Create(7, 6, 2, 4, 13, 9, 15, 0, 10,
    1, 5, 11, 8, 14, 12, 3), THashLibUInt32Array.Create(13, 14, 4, 1, 7, 0, 5,
    10, 3, 12, 8, 15, 6, 2, 9, 11), THashLibUInt32Array.Create(1, 3, 10, 9, 5,
    11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12));

  ComputeSBoxes(LSBox, FSBox1_CryptoPro, FSBox2_CryptoPro, FSBox3_CryptoPro,
    FSBox4_CryptoPro);
end;

procedure TGost.Initialize;
begin
  TArrayUtils.ZeroFill(FState);
  TArrayUtils.ZeroFill(FHash);
  inherited Initialize();
end;

procedure TGost.TransformBlock(AData: PByte; ADataLength: Int32; AIndex: Int32);
var
  LData, LCompressBuffer: array [0 .. 7] of UInt32;
  LCarry, LBlockWord, LPriorState: UInt32;
  LIdx: Int32;
begin
  LCarry := 0;

  TConverters.le32_copy(AData, AIndex, @(LData[0]), 0, ADataLength);

  for LIdx := 0 to 7 do
  begin
    LBlockWord := LData[LIdx];
    LCompressBuffer[LIdx] := LBlockWord;
    LPriorState := FState[LIdx];
    LCarry := LBlockWord + LCarry + FState[LIdx];
    FState[LIdx] := LCarry;
    if ((LCarry < LBlockWord) or (LCarry < LPriorState)) then
    begin
      LCarry := UInt32(1)
    end
    else
    begin
      LCarry := UInt32(0);
    end;
  end;

  Compress(@(LCompressBuffer[0]));

  System.FillChar(LCompressBuffer, System.SizeOf(LCompressBuffer), UInt32(0));
  System.FillChar(LData, System.SizeOf(LData), UInt32(0));
end;

end.
