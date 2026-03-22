unit HlpHaval;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpBits,
  HlpHashSize,
  HlpHashRounds,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

resourcestring
  SInvalidHavalRound = 'Haval Round Must be 3, 4 or 5';
  SInvalidHavalHashSize =
    'Haval HashSize Must be Either 128 bit(16 byte), 160 bit(20 byte), 192 bit(24 byte), 224 bit(28 byte) or 256 bit(32 byte)';

type
  THaval = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  strict private
  const
    HAVAL_VERSION = Int32(1);

  var
    FRounds: Int32;

    procedure TailorDigestBits();

  strict protected
  var
    FHash: THashLibUInt32Array;

    constructor Create(ARounds: THashRounds; AHashSize: THashSize);

    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;

  public
    procedure Initialize(); override;
  end;

type

  THaval3 = class abstract(THaval)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create(AHashSize: THashSize);

  end;

type

  THaval4 = class abstract(THaval)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create(AHashSize: THashSize);

  end;

type

  THaval5 = class abstract(THaval)

  strict protected
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create(AHashSize: THashSize);

  end;

type

  THaval_3_128 = class sealed(THaval3)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_4_128 = class sealed(THaval4)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_5_128 = class sealed(THaval5)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_3_160 = class sealed(THaval3)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_4_160 = class sealed(THaval4)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_5_160 = class sealed(THaval5)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_3_192 = class sealed(THaval3)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_4_192 = class sealed(THaval4)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_5_192 = class sealed(THaval5)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_3_224 = class sealed(THaval3)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_4_224 = class sealed(THaval4)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_5_224 = class sealed(THaval5)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_3_256 = class sealed(THaval3)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_4_256 = class sealed(THaval4)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

type

  THaval_5_256 = class sealed(THaval5)

  public
    constructor Create();
    function Clone(): IHash; override;

  end;

implementation

{ THaval }

constructor THaval.Create(ARounds: THashRounds; AHashSize: THashSize);
begin
  inherited Create(Int32(AHashSize), 128);
  System.SetLength(FHash, 8);
  FRounds := Int32(ARounds);
end;

procedure THaval.Finish;
var
  LBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LBits := FProcessedBytesCount * 8;
  if (FBuffer.Position < 118) then
  begin
    LPadIndex := (118 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (246 - FBuffer.Position);
  end;
  System.SetLength(LPad, LPadIndex + 10);

  LPad[0] := Byte($01);

  LPad[LPadIndex] := Byte((FRounds shl 3) or (HAVAL_VERSION and $07));
  System.Inc(LPadIndex);
  LPad[LPadIndex] := Byte(HashSize shl 1);
  System.Inc(LPadIndex);

  LBits := TConverters.le2me_64(LBits);

  TConverters.ReadUInt64AsBytesLE(LBits, LPad, LPadIndex);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

function THaval.GetResult: THashLibByteArray;
begin
  TailorDigestBits();
  System.SetLength(Result, (HashSize shr 2) * System.SizeOf(UInt32));
  TConverters.le32_copy(PCardinal(FHash), 0, PByte(Result), 0,
    System.Length(Result));
end;

procedure THaval.Initialize;
begin
  FHash[0] := $243F6A88;
  FHash[1] := $85A308D3;
  FHash[2] := $13198A2E;
  FHash[3] := $03707344;
  FHash[4] := $A4093822;
  FHash[5] := $299F31D0;
  FHash[6] := $082EFA98;
  FHash[7] := $EC4E6C89;

  inherited Initialize();
end;

procedure THaval.TailorDigestBits;
var
  LTailorWord: UInt32;
begin

  case HashSize of
    16:
      begin
        LTailorWord := (FHash[7] and $000000FF) or (FHash[6] and $FF000000) or
          (FHash[5] and $00FF0000) or (FHash[4] and $0000FF00);
        FHash[0] := FHash[0] + TBits.RotateRight32(LTailorWord, 8);
        LTailorWord := (FHash[7] and $0000FF00) or (FHash[6] and $000000FF) or
          (FHash[5] and $FF000000) or (FHash[4] and $00FF0000);
        FHash[1] := FHash[1] + TBits.RotateRight32(LTailorWord, 16);
        LTailorWord := (FHash[7] and $00FF0000) or (FHash[6] and $0000FF00) or
          (FHash[5] and $000000FF) or (FHash[4] and $FF000000);
        FHash[2] := FHash[2] + TBits.RotateRight32(LTailorWord, 24);
        LTailorWord := (FHash[7] and $FF000000) or (FHash[6] and $00FF0000) or
          (FHash[5] and $0000FF00) or (FHash[4] and $000000FF);
        FHash[3] := FHash[3] + LTailorWord;
      end;

    20:
      begin
        LTailorWord := UInt32(FHash[7] and $3F) or UInt32(FHash[6] and ($7F shl 25)) or
          UInt32(FHash[5] and ($3F shl 19));
        FHash[0] := FHash[0] + TBits.RotateRight32(LTailorWord, 19);
        LTailorWord := UInt32(FHash[7] and ($3F shl 6)) or UInt32(FHash[6] and $3F) or
          UInt32(FHash[5] and ($7F shl 25));
        FHash[1] := FHash[1] + TBits.RotateRight32(LTailorWord, 25);
        LTailorWord := (FHash[7] and ($7F shl 12)) or (FHash[6] and ($3F shl 6)) or
          (FHash[5] and $3F);
        FHash[2] := FHash[2] + LTailorWord;
        LTailorWord := (FHash[7] and ($3F shl 19)) or (FHash[6] and ($7F shl 12)) or
          (FHash[5] and ($3F shl 6));
        FHash[3] := FHash[3] + (LTailorWord shr 6);
        LTailorWord := (FHash[7] and (UInt32($7F) shl 25)) or
          UInt32(FHash[6] and ($3F shl 19)) or
          UInt32(FHash[5] and ($7F shl 12));
        FHash[4] := FHash[4] + (LTailorWord shr 12);
      end;

    24:
      begin
        LTailorWord := UInt32(FHash[7] and $1F) or UInt32(FHash[6] and ($3F shl 26));
        FHash[0] := FHash[0] + TBits.RotateRight32(LTailorWord, 26);
        LTailorWord := (FHash[7] and ($1F shl 5)) or (FHash[6] and $1F);
        FHash[1] := FHash[1] + LTailorWord;
        LTailorWord := (FHash[7] and ($3F shl 10)) or (FHash[6] and ($1F shl 5));
        FHash[2] := FHash[2] + (LTailorWord shr 5);
        LTailorWord := (FHash[7] and ($1F shl 16)) or (FHash[6] and ($3F shl 10));
        FHash[3] := FHash[3] + (LTailorWord shr 10);
        LTailorWord := (FHash[7] and ($1F shl 21)) or (FHash[6] and ($1F shl 16));
        FHash[4] := FHash[4] + (LTailorWord shr 16);
        LTailorWord := UInt32(FHash[7] and ($3F shl 26)) or
          UInt32(FHash[6] and ($1F shl 21));
        FHash[5] := FHash[5] + (LTailorWord shr 21);
      end;

    28:
      begin
        FHash[0] := FHash[0] + ((FHash[7] shr 27) and $1F);
        FHash[1] := FHash[1] + ((FHash[7] shr 22) and $1F);
        FHash[2] := FHash[2] + ((FHash[7] shr 18) and $0F);
        FHash[3] := FHash[3] + ((FHash[7] shr 13) and $1F);
        FHash[4] := FHash[4] + ((FHash[7] shr 9) and $0F);
        FHash[5] := FHash[5] + ((FHash[7] shr 4) and $1F);
        FHash[6] := FHash[6] + (FHash[7] and $0F);
      end;
  end;

end;

{ THaval3 }

constructor THaval3.Create(AHashSize: THashSize);
begin
  inherited Create(THashRounds.hrRounds3, AHashSize);
end;

procedure THaval3.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegE, LRegF, LRegG, LRegH, LNfOut: UInt32;
  LTemp: array [0 .. 31] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LTemp[0]), 0, ADataLength);

  LRegA := FHash[0];
  LRegB := FHash[1];
  LRegC := FHash[2];
  LRegD := FHash[3];
  LRegE := FHash[4];
  LRegF := FHash[5];
  LRegG := FHash[6];
  LRegH := FHash[7];

  LNfOut := LRegC and (LRegE xor LRegD) xor LRegG and LRegA xor LRegF and LRegB xor LRegE;
  LRegH := LTemp[0] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegD xor LRegC) xor LRegF and LRegH xor LRegE and LRegA xor LRegD;
  LRegG := LTemp[1] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegC xor LRegB) xor LRegE and LRegG xor LRegD and LRegH xor LRegC;
  LRegF := LTemp[2] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegB xor LRegA) xor LRegD and LRegF xor LRegC and LRegG xor LRegB;
  LRegE := LTemp[3] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegA xor LRegH) xor LRegC and LRegE xor LRegB and LRegF xor LRegA;
  LRegD := LTemp[4] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegH xor LRegG) xor LRegB and LRegD xor LRegA and LRegE xor LRegH;
  LRegC := LTemp[5] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegG xor LRegF) xor LRegA and LRegC xor LRegH and LRegD xor LRegG;
  LRegB := LTemp[6] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegF xor LRegE) xor LRegH and LRegB xor LRegG and LRegC xor LRegF;
  LRegA := LTemp[7] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegE xor LRegD) xor LRegG and LRegA xor LRegF and LRegB xor LRegE;
  LRegH := LTemp[8] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegD xor LRegC) xor LRegF and LRegH xor LRegE and LRegA xor LRegD;
  LRegG := LTemp[9] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegC xor LRegB) xor LRegE and LRegG xor LRegD and LRegH xor LRegC;
  LRegF := LTemp[10] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegB xor LRegA) xor LRegD and LRegF xor LRegC and LRegG xor LRegB;
  LRegE := LTemp[11] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegA xor LRegH) xor LRegC and LRegE xor LRegB and LRegF xor LRegA;
  LRegD := LTemp[12] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegH xor LRegG) xor LRegB and LRegD xor LRegA and LRegE xor LRegH;
  LRegC := LTemp[13] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegG xor LRegF) xor LRegA and LRegC xor LRegH and LRegD xor LRegG;
  LRegB := LTemp[14] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegF xor LRegE) xor LRegH and LRegB xor LRegG and LRegC xor LRegF;
  LRegA := LTemp[15] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegE xor LRegD) xor LRegG and LRegA xor LRegF and LRegB xor LRegE;
  LRegH := LTemp[16] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegD xor LRegC) xor LRegF and LRegH xor LRegE and LRegA xor LRegD;
  LRegG := LTemp[17] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegC xor LRegB) xor LRegE and LRegG xor LRegD and LRegH xor LRegC;
  LRegF := LTemp[18] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegB xor LRegA) xor LRegD and LRegF xor LRegC and LRegG xor LRegB;
  LRegE := LTemp[19] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegA xor LRegH) xor LRegC and LRegE xor LRegB and LRegF xor LRegA;
  LRegD := LTemp[20] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegH xor LRegG) xor LRegB and LRegD xor LRegA and LRegE xor LRegH;
  LRegC := LTemp[21] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegG xor LRegF) xor LRegA and LRegC xor LRegH and LRegD xor LRegG;
  LRegB := LTemp[22] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegF xor LRegE) xor LRegH and LRegB xor LRegG and LRegC xor LRegF;
  LRegA := LTemp[23] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegE xor LRegD) xor LRegG and LRegA xor LRegF and LRegB xor LRegE;
  LRegH := LTemp[24] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegD xor LRegC) xor LRegF and LRegH xor LRegE and LRegA xor LRegD;
  LRegG := LTemp[25] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegC xor LRegB) xor LRegE and LRegG xor LRegD and LRegH xor LRegC;
  LRegF := LTemp[26] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegB xor LRegA) xor LRegD and LRegF xor LRegC and LRegG xor LRegB;
  LRegE := LTemp[27] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegA xor LRegH) xor LRegC and LRegE xor LRegB and LRegF xor LRegA;
  LRegD := LTemp[28] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegH xor LRegG) xor LRegB and LRegD xor LRegA and LRegE xor LRegH;
  LRegC := LTemp[29] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegG xor LRegF) xor LRegA and LRegC xor LRegH and LRegD xor LRegG;
  LRegB := LTemp[30] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegF xor LRegE) xor LRegH and LRegB xor LRegG and LRegC xor LRegF;
  LRegA := LTemp[31] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegF and (LRegD and not LRegA xor LRegB and LRegC xor LRegE xor LRegG) xor LRegB and (LRegD xor LRegC)
    xor LRegA and LRegC xor LRegG;
  LRegH := LTemp[5] + $452821E6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegE and (LRegC and not LRegH xor LRegA and LRegB xor LRegD xor LRegF) xor LRegA and (LRegC xor LRegB)
    xor LRegH and LRegB xor LRegF;
  LRegG := LTemp[14] + $38D01377 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegD and (LRegB and not LRegG xor LRegH and LRegA xor LRegC xor LRegE) xor LRegH and (LRegB xor LRegA)
    xor LRegG and LRegA xor LRegE;
  LRegF := LTemp[26] + $BE5466CF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegC and (LRegA and not LRegF xor LRegG and LRegH xor LRegB xor LRegD) xor LRegG and (LRegA xor LRegH)
    xor LRegF and LRegH xor LRegD;
  LRegE := LTemp[18] + $34E90C6C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegB and (LRegH and not LRegE xor LRegF and LRegG xor LRegA xor LRegC) xor LRegF and (LRegH xor LRegG)
    xor LRegE and LRegG xor LRegC;
  LRegD := LTemp[11] + $C0AC29B7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegA and (LRegG and not LRegD xor LRegE and LRegF xor LRegH xor LRegB) xor LRegE and (LRegG xor LRegF)
    xor LRegD and LRegF xor LRegB;
  LRegC := LTemp[28] + $C97C50DD + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegH and (LRegF and not LRegC xor LRegD and LRegE xor LRegG xor LRegA) xor LRegD and (LRegF xor LRegE)
    xor LRegC and LRegE xor LRegA;
  LRegB := LTemp[7] + $3F84D5B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegG and (LRegE and not LRegB xor LRegC and LRegD xor LRegF xor LRegH) xor LRegC and (LRegE xor LRegD)
    xor LRegB and LRegD xor LRegH;
  LRegA := LTemp[16] + $B5470917 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegF and (LRegD and not LRegA xor LRegB and LRegC xor LRegE xor LRegG) xor LRegB and (LRegD xor LRegC)
    xor LRegA and LRegC xor LRegG;
  LRegH := LTemp[0] + $9216D5D9 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegE and (LRegC and not LRegH xor LRegA and LRegB xor LRegD xor LRegF) xor LRegA and (LRegC xor LRegB)
    xor LRegH and LRegB xor LRegF;
  LRegG := LTemp[23] + $8979FB1B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegD and (LRegB and not LRegG xor LRegH and LRegA xor LRegC xor LRegE) xor LRegH and (LRegB xor LRegA)
    xor LRegG and LRegA xor LRegE;
  LRegF := LTemp[20] + $D1310BA6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegC and (LRegA and not LRegF xor LRegG and LRegH xor LRegB xor LRegD) xor LRegG and (LRegA xor LRegH)
    xor LRegF and LRegH xor LRegD;
  LRegE := LTemp[22] + $98DFB5AC + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegB and (LRegH and not LRegE xor LRegF and LRegG xor LRegA xor LRegC) xor LRegF and (LRegH xor LRegG)
    xor LRegE and LRegG xor LRegC;
  LRegD := LTemp[1] + $2FFD72DB + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegA and (LRegG and not LRegD xor LRegE and LRegF xor LRegH xor LRegB) xor LRegE and (LRegG xor LRegF)
    xor LRegD and LRegF xor LRegB;
  LRegC := LTemp[10] + $D01ADFB7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegH and (LRegF and not LRegC xor LRegD and LRegE xor LRegG xor LRegA) xor LRegD and (LRegF xor LRegE)
    xor LRegC and LRegE xor LRegA;
  LRegB := LTemp[4] + $B8E1AFED + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegG and (LRegE and not LRegB xor LRegC and LRegD xor LRegF xor LRegH) xor LRegC and (LRegE xor LRegD)
    xor LRegB and LRegD xor LRegH;
  LRegA := LTemp[8] + $6A267E96 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegF and (LRegD and not LRegA xor LRegB and LRegC xor LRegE xor LRegG) xor LRegB and (LRegD xor LRegC)
    xor LRegA and LRegC xor LRegG;
  LRegH := LTemp[30] + $BA7C9045 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegE and (LRegC and not LRegH xor LRegA and LRegB xor LRegD xor LRegF) xor LRegA and (LRegC xor LRegB)
    xor LRegH and LRegB xor LRegF;
  LRegG := LTemp[3] + $F12C7F99 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegD and (LRegB and not LRegG xor LRegH and LRegA xor LRegC xor LRegE) xor LRegH and (LRegB xor LRegA)
    xor LRegG and LRegA xor LRegE;
  LRegF := LTemp[21] + $24A19947 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegC and (LRegA and not LRegF xor LRegG and LRegH xor LRegB xor LRegD) xor LRegG and (LRegA xor LRegH)
    xor LRegF and LRegH xor LRegD;
  LRegE := LTemp[9] + $B3916CF7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegB and (LRegH and not LRegE xor LRegF and LRegG xor LRegA xor LRegC) xor LRegF and (LRegH xor LRegG)
    xor LRegE and LRegG xor LRegC;
  LRegD := LTemp[17] + $0801F2E2 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegA and (LRegG and not LRegD xor LRegE and LRegF xor LRegH xor LRegB) xor LRegE and (LRegG xor LRegF)
    xor LRegD and LRegF xor LRegB;
  LRegC := LTemp[24] + $858EFC16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegH and (LRegF and not LRegC xor LRegD and LRegE xor LRegG xor LRegA) xor LRegD and (LRegF xor LRegE)
    xor LRegC and LRegE xor LRegA;
  LRegB := LTemp[29] + $636920D8 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegG and (LRegE and not LRegB xor LRegC and LRegD xor LRegF xor LRegH) xor LRegC and (LRegE xor LRegD)
    xor LRegB and LRegD xor LRegH;
  LRegA := LTemp[6] + $71574E69 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegF and (LRegD and not LRegA xor LRegB and LRegC xor LRegE xor LRegG) xor LRegB and (LRegD xor LRegC)
    xor LRegA and LRegC xor LRegG;
  LRegH := LTemp[19] + $A458FEA3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegE and (LRegC and not LRegH xor LRegA and LRegB xor LRegD xor LRegF) xor LRegA and (LRegC xor LRegB)
    xor LRegH and LRegB xor LRegF;
  LRegG := LTemp[12] + $F4933D7E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegD and (LRegB and not LRegG xor LRegH and LRegA xor LRegC xor LRegE) xor LRegH and (LRegB xor LRegA)
    xor LRegG and LRegA xor LRegE;
  LRegF := LTemp[15] + $0D95748F + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegC and (LRegA and not LRegF xor LRegG and LRegH xor LRegB xor LRegD) xor LRegG and (LRegA xor LRegH)
    xor LRegF and LRegH xor LRegD;
  LRegE := LTemp[13] + $728EB658 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegB and (LRegH and not LRegE xor LRegF and LRegG xor LRegA xor LRegC) xor LRegF and (LRegH xor LRegG)
    xor LRegE and LRegG xor LRegC;
  LRegD := LTemp[2] + $718BCD58 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegA and (LRegG and not LRegD xor LRegE and LRegF xor LRegH xor LRegB) xor LRegE and (LRegG xor LRegF)
    xor LRegD and LRegF xor LRegB;
  LRegC := LTemp[25] + $82154AEE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegH and (LRegF and not LRegC xor LRegD and LRegE xor LRegG xor LRegA) xor LRegD and (LRegF xor LRegE)
    xor LRegC and LRegE xor LRegA;
  LRegB := LTemp[31] + $7B54A41D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegG and (LRegE and not LRegB xor LRegC and LRegD xor LRegF xor LRegH) xor LRegC and (LRegE xor LRegD)
    xor LRegB and LRegD xor LRegH;
  LRegA := LTemp[27] + $C25A59B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and LRegE xor LRegG xor LRegA) xor LRegF and LRegC xor LRegE and LRegB xor LRegA;
  LRegH := LTemp[19] + $9C30D539 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and LRegD xor LRegF xor LRegH) xor LRegE and LRegB xor LRegD and LRegA xor LRegH;
  LRegG := LTemp[9] + $2AF26013 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and LRegC xor LRegE xor LRegG) xor LRegD and LRegA xor LRegC and LRegH xor LRegG;
  LRegF := LTemp[4] + $C5D1B023 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and LRegB xor LRegD xor LRegF) xor LRegC and LRegH xor LRegB and LRegG xor LRegF;
  LRegE := LTemp[20] + $286085F0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and LRegA xor LRegC xor LRegE) xor LRegB and LRegG xor LRegA and LRegF xor LRegE;
  LRegD := LTemp[28] + $CA417918 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and LRegH xor LRegB xor LRegD) xor LRegA and LRegF xor LRegH and LRegE xor LRegD;
  LRegC := LTemp[17] + $B8DB38EF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and LRegG xor LRegA xor LRegC) xor LRegH and LRegE xor LRegG and LRegD xor LRegC;
  LRegB := LTemp[8] + $8E79DCB0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and LRegF xor LRegH xor LRegB) xor LRegG and LRegD xor LRegF and LRegC xor LRegB;
  LRegA := LTemp[22] + $603A180E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and LRegE xor LRegG xor LRegA) xor LRegF and LRegC xor LRegE and LRegB xor LRegA;
  LRegH := LTemp[29] + $6C9E0E8B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and LRegD xor LRegF xor LRegH) xor LRegE and LRegB xor LRegD and LRegA xor LRegH;
  LRegG := LTemp[14] + $B01E8A3E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and LRegC xor LRegE xor LRegG) xor LRegD and LRegA xor LRegC and LRegH xor LRegG;
  LRegF := LTemp[25] + $D71577C1 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and LRegB xor LRegD xor LRegF) xor LRegC and LRegH xor LRegB and LRegG xor LRegF;
  LRegE := LTemp[12] + $BD314B27 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and LRegA xor LRegC xor LRegE) xor LRegB and LRegG xor LRegA and LRegF xor LRegE;
  LRegD := LTemp[24] + $78AF2FDA + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and LRegH xor LRegB xor LRegD) xor LRegA and LRegF xor LRegH and LRegE xor LRegD;
  LRegC := LTemp[30] + $55605C60 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and LRegG xor LRegA xor LRegC) xor LRegH and LRegE xor LRegG and LRegD xor LRegC;
  LRegB := LTemp[16] + $E65525F3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and LRegF xor LRegH xor LRegB) xor LRegG and LRegD xor LRegF and LRegC xor LRegB;
  LRegA := LTemp[26] + $AA55AB94 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and LRegE xor LRegG xor LRegA) xor LRegF and LRegC xor LRegE and LRegB xor LRegA;
  LRegH := LTemp[31] + $57489862 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and LRegD xor LRegF xor LRegH) xor LRegE and LRegB xor LRegD and LRegA xor LRegH;
  LRegG := LTemp[15] + $63E81440 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and LRegC xor LRegE xor LRegG) xor LRegD and LRegA xor LRegC and LRegH xor LRegG;
  LRegF := LTemp[7] + $55CA396A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and LRegB xor LRegD xor LRegF) xor LRegC and LRegH xor LRegB and LRegG xor LRegF;
  LRegE := LTemp[3] + $2AAB10B6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and LRegA xor LRegC xor LRegE) xor LRegB and LRegG xor LRegA and LRegF xor LRegE;
  LRegD := LTemp[1] + $B4CC5C34 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and LRegH xor LRegB xor LRegD) xor LRegA and LRegF xor LRegH and LRegE xor LRegD;
  LRegC := LTemp[0] + $1141E8CE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and LRegG xor LRegA xor LRegC) xor LRegH and LRegE xor LRegG and LRegD xor LRegC;
  LRegB := LTemp[18] + $A15486AF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and LRegF xor LRegH xor LRegB) xor LRegG and LRegD xor LRegF and LRegC xor LRegB;
  LRegA := LTemp[27] + $7C72E993 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and LRegE xor LRegG xor LRegA) xor LRegF and LRegC xor LRegE and LRegB xor LRegA;
  LRegH := LTemp[13] + $B3EE1411 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and LRegD xor LRegF xor LRegH) xor LRegE and LRegB xor LRegD and LRegA xor LRegH;
  LRegG := LTemp[6] + $636FBC2A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and LRegC xor LRegE xor LRegG) xor LRegD and LRegA xor LRegC and LRegH xor LRegG;
  LRegF := LTemp[21] + $2BA9C55D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and LRegB xor LRegD xor LRegF) xor LRegC and LRegH xor LRegB and LRegG xor LRegF;
  LRegE := LTemp[10] + $741831F6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and LRegA xor LRegC xor LRegE) xor LRegB and LRegG xor LRegA and LRegF xor LRegE;
  LRegD := LTemp[23] + $CE5C3E16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and LRegH xor LRegB xor LRegD) xor LRegA and LRegF xor LRegH and LRegE xor LRegD;
  LRegC := LTemp[11] + $9B87931E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and LRegG xor LRegA xor LRegC) xor LRegH and LRegE xor LRegG and LRegD xor LRegC;
  LRegB := LTemp[5] + $AFD6BA33 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and LRegF xor LRegH xor LRegB) xor LRegG and LRegD xor LRegF and LRegC xor LRegB;
  LRegA := LTemp[2] + $6C24CF5C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  FHash[0] := FHash[0] + LRegA;
  FHash[1] := FHash[1] + LRegB;
  FHash[2] := FHash[2] + LRegC;
  FHash[3] := FHash[3] + LRegD;
  FHash[4] := FHash[4] + LRegE;
  FHash[5] := FHash[5] + LRegF;
  FHash[6] := FHash[6] + LRegG;
  FHash[7] := FHash[7] + LRegH;

  System.FillChar(LTemp, System.SizeOf(LTemp), UInt32(0));
end;

{ THaval4 }

constructor THaval4.Create(AHashSize: THashSize);
begin
  inherited Create(THashRounds.hrRounds4, AHashSize);
end;

procedure THaval4.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegE, LRegF, LRegG, LRegH, LNfOut: UInt32;
  LTemp: array [0 .. 31] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LTemp[0]), 0, ADataLength);

  LRegA := FHash[0];
  LRegB := FHash[1];
  LRegC := FHash[2];
  LRegD := FHash[3];
  LRegE := FHash[4];
  LRegF := FHash[5];
  LRegG := FHash[6];
  LRegH := FHash[7];

  LNfOut := LRegD and (LRegA xor LRegB) xor LRegF and LRegG xor LRegE and LRegC xor LRegA;
  LRegH := LTemp[0] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegH xor LRegA) xor LRegE and LRegF xor LRegD and LRegB xor LRegH;
  LRegG := LTemp[1] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegG xor LRegH) xor LRegD and LRegE xor LRegC and LRegA xor LRegG;
  LRegF := LTemp[2] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegF xor LRegG) xor LRegC and LRegD xor LRegB and LRegH xor LRegF;
  LRegE := LTemp[3] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegE xor LRegF) xor LRegB and LRegC xor LRegA and LRegG xor LRegE;
  LRegD := LTemp[4] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegD xor LRegE) xor LRegA and LRegB xor LRegH and LRegF xor LRegD;
  LRegC := LTemp[5] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegC xor LRegD) xor LRegH and LRegA xor LRegG and LRegE xor LRegC;
  LRegB := LTemp[6] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegB xor LRegC) xor LRegG and LRegH xor LRegF and LRegD xor LRegB;
  LRegA := LTemp[7] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegA xor LRegB) xor LRegF and LRegG xor LRegE and LRegC xor LRegA;
  LRegH := LTemp[8] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegH xor LRegA) xor LRegE and LRegF xor LRegD and LRegB xor LRegH;
  LRegG := LTemp[9] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegG xor LRegH) xor LRegD and LRegE xor LRegC and LRegA xor LRegG;
  LRegF := LTemp[10] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegF xor LRegG) xor LRegC and LRegD xor LRegB and LRegH xor LRegF;
  LRegE := LTemp[11] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegE xor LRegF) xor LRegB and LRegC xor LRegA and LRegG xor LRegE;
  LRegD := LTemp[12] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegD xor LRegE) xor LRegA and LRegB xor LRegH and LRegF xor LRegD;
  LRegC := LTemp[13] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegC xor LRegD) xor LRegH and LRegA xor LRegG and LRegE xor LRegC;
  LRegB := LTemp[14] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegB xor LRegC) xor LRegG and LRegH xor LRegF and LRegD xor LRegB;
  LRegA := LTemp[15] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegA xor LRegB) xor LRegF and LRegG xor LRegE and LRegC xor LRegA;
  LRegH := LTemp[16] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegH xor LRegA) xor LRegE and LRegF xor LRegD and LRegB xor LRegH;
  LRegG := LTemp[17] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegG xor LRegH) xor LRegD and LRegE xor LRegC and LRegA xor LRegG;
  LRegF := LTemp[18] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegF xor LRegG) xor LRegC and LRegD xor LRegB and LRegH xor LRegF;
  LRegE := LTemp[19] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegE xor LRegF) xor LRegB and LRegC xor LRegA and LRegG xor LRegE;
  LRegD := LTemp[20] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegD xor LRegE) xor LRegA and LRegB xor LRegH and LRegF xor LRegD;
  LRegC := LTemp[21] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegC xor LRegD) xor LRegH and LRegA xor LRegG and LRegE xor LRegC;
  LRegB := LTemp[22] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegB xor LRegC) xor LRegG and LRegH xor LRegF and LRegD xor LRegB;
  LRegA := LTemp[23] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegA xor LRegB) xor LRegF and LRegG xor LRegE and LRegC xor LRegA;
  LRegH := LTemp[24] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegH xor LRegA) xor LRegE and LRegF xor LRegD and LRegB xor LRegH;
  LRegG := LTemp[25] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegG xor LRegH) xor LRegD and LRegE xor LRegC and LRegA xor LRegG;
  LRegF := LTemp[26] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegF xor LRegG) xor LRegC and LRegD xor LRegB and LRegH xor LRegF;
  LRegE := LTemp[27] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegE xor LRegF) xor LRegB and LRegC xor LRegA and LRegG xor LRegE;
  LRegD := LTemp[28] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegD xor LRegE) xor LRegA and LRegB xor LRegH and LRegF xor LRegD;
  LRegC := LTemp[29] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegC xor LRegD) xor LRegH and LRegA xor LRegG and LRegE xor LRegC;
  LRegB := LTemp[30] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegB xor LRegC) xor LRegG and LRegH xor LRegF and LRegD xor LRegB;
  LRegA := LTemp[31] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegG and not LRegA xor LRegC and LRegF xor LRegD xor LRegE) xor LRegC and (LRegG xor LRegF)
    xor LRegA and LRegF xor LRegE;
  LRegH := LTemp[5] + $452821E6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegF and not LRegH xor LRegB and LRegE xor LRegC xor LRegD) xor LRegB and (LRegF xor LRegE)
    xor LRegH and LRegE xor LRegD;
  LRegG := LTemp[14] + $38D01377 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegE and not LRegG xor LRegA and LRegD xor LRegB xor LRegC) xor LRegA and (LRegE xor LRegD)
    xor LRegG and LRegD xor LRegC;
  LRegF := LTemp[26] + $BE5466CF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegD and not LRegF xor LRegH and LRegC xor LRegA xor LRegB) xor LRegH and (LRegD xor LRegC)
    xor LRegF and LRegC xor LRegB;
  LRegE := LTemp[18] + $34E90C6C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegC and not LRegE xor LRegG and LRegB xor LRegH xor LRegA) xor LRegG and (LRegC xor LRegB)
    xor LRegE and LRegB xor LRegA;
  LRegD := LTemp[11] + $C0AC29B7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegB and not LRegD xor LRegF and LRegA xor LRegG xor LRegH) xor LRegF and (LRegB xor LRegA)
    xor LRegD and LRegA xor LRegH;
  LRegC := LTemp[28] + $C97C50DD + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegA and not LRegC xor LRegE and LRegH xor LRegF xor LRegG) xor LRegE and (LRegA xor LRegH)
    xor LRegC and LRegH xor LRegG;
  LRegB := LTemp[7] + $3F84D5B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegH and not LRegB xor LRegD and LRegG xor LRegE xor LRegF) xor LRegD and (LRegH xor LRegG)
    xor LRegB and LRegG xor LRegF;
  LRegA := LTemp[16] + $B5470917 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegG and not LRegA xor LRegC and LRegF xor LRegD xor LRegE) xor LRegC and (LRegG xor LRegF)
    xor LRegA and LRegF xor LRegE;
  LRegH := LTemp[0] + $9216D5D9 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegF and not LRegH xor LRegB and LRegE xor LRegC xor LRegD) xor LRegB and (LRegF xor LRegE)
    xor LRegH and LRegE xor LRegD;
  LRegG := LTemp[23] + $8979FB1B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegE and not LRegG xor LRegA and LRegD xor LRegB xor LRegC) xor LRegA and (LRegE xor LRegD)
    xor LRegG and LRegD xor LRegC;
  LRegF := LTemp[20] + $D1310BA6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegD and not LRegF xor LRegH and LRegC xor LRegA xor LRegB) xor LRegH and (LRegD xor LRegC)
    xor LRegF and LRegC xor LRegB;
  LRegE := LTemp[22] + $98DFB5AC + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegC and not LRegE xor LRegG and LRegB xor LRegH xor LRegA) xor LRegG and (LRegC xor LRegB)
    xor LRegE and LRegB xor LRegA;
  LRegD := LTemp[1] + $2FFD72DB + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegB and not LRegD xor LRegF and LRegA xor LRegG xor LRegH) xor LRegF and (LRegB xor LRegA)
    xor LRegD and LRegA xor LRegH;
  LRegC := LTemp[10] + $D01ADFB7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegA and not LRegC xor LRegE and LRegH xor LRegF xor LRegG) xor LRegE and (LRegA xor LRegH)
    xor LRegC and LRegH xor LRegG;
  LRegB := LTemp[4] + $B8E1AFED + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegH and not LRegB xor LRegD and LRegG xor LRegE xor LRegF) xor LRegD and (LRegH xor LRegG)
    xor LRegB and LRegG xor LRegF;
  LRegA := LTemp[8] + $6A267E96 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegG and not LRegA xor LRegC and LRegF xor LRegD xor LRegE) xor LRegC and (LRegG xor LRegF)
    xor LRegA and LRegF xor LRegE;
  LRegH := LTemp[30] + $BA7C9045 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegF and not LRegH xor LRegB and LRegE xor LRegC xor LRegD) xor LRegB and (LRegF xor LRegE)
    xor LRegH and LRegE xor LRegD;
  LRegG := LTemp[3] + $F12C7F99 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegE and not LRegG xor LRegA and LRegD xor LRegB xor LRegC) xor LRegA and (LRegE xor LRegD)
    xor LRegG and LRegD xor LRegC;
  LRegF := LTemp[21] + $24A19947 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegD and not LRegF xor LRegH and LRegC xor LRegA xor LRegB) xor LRegH and (LRegD xor LRegC)
    xor LRegF and LRegC xor LRegB;
  LRegE := LTemp[9] + $B3916CF7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegC and not LRegE xor LRegG and LRegB xor LRegH xor LRegA) xor LRegG and (LRegC xor LRegB)
    xor LRegE and LRegB xor LRegA;
  LRegD := LTemp[17] + $0801F2E2 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegB and not LRegD xor LRegF and LRegA xor LRegG xor LRegH) xor LRegF and (LRegB xor LRegA)
    xor LRegD and LRegA xor LRegH;
  LRegC := LTemp[24] + $858EFC16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegA and not LRegC xor LRegE and LRegH xor LRegF xor LRegG) xor LRegE and (LRegA xor LRegH)
    xor LRegC and LRegH xor LRegG;
  LRegB := LTemp[29] + $636920D8 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegH and not LRegB xor LRegD and LRegG xor LRegE xor LRegF) xor LRegD and (LRegH xor LRegG)
    xor LRegB and LRegG xor LRegF;
  LRegA := LTemp[6] + $71574E69 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegG and not LRegA xor LRegC and LRegF xor LRegD xor LRegE) xor LRegC and (LRegG xor LRegF)
    xor LRegA and LRegF xor LRegE;
  LRegH := LTemp[19] + $A458FEA3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegF and not LRegH xor LRegB and LRegE xor LRegC xor LRegD) xor LRegB and (LRegF xor LRegE)
    xor LRegH and LRegE xor LRegD;
  LRegG := LTemp[12] + $F4933D7E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegE and not LRegG xor LRegA and LRegD xor LRegB xor LRegC) xor LRegA and (LRegE xor LRegD)
    xor LRegG and LRegD xor LRegC;
  LRegF := LTemp[15] + $0D95748F + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegD and not LRegF xor LRegH and LRegC xor LRegA xor LRegB) xor LRegH and (LRegD xor LRegC)
    xor LRegF and LRegC xor LRegB;
  LRegE := LTemp[13] + $728EB658 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegC and not LRegE xor LRegG and LRegB xor LRegH xor LRegA) xor LRegG and (LRegC xor LRegB)
    xor LRegE and LRegB xor LRegA;
  LRegD := LTemp[2] + $718BCD58 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegB and not LRegD xor LRegF and LRegA xor LRegG xor LRegH) xor LRegF and (LRegB xor LRegA)
    xor LRegD and LRegA xor LRegH;
  LRegC := LTemp[25] + $82154AEE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegA and not LRegC xor LRegE and LRegH xor LRegF xor LRegG) xor LRegE and (LRegA xor LRegH)
    xor LRegC and LRegH xor LRegG;
  LRegB := LTemp[31] + $7B54A41D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegH and not LRegB xor LRegD and LRegG xor LRegE xor LRegF) xor LRegD and (LRegH xor LRegG)
    xor LRegB and LRegG xor LRegF;
  LRegA := LTemp[27] + $C25A59B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegG and (LRegC and LRegA xor LRegB xor LRegF) xor LRegC and LRegD xor LRegA and LRegE xor LRegF;
  LRegH := LTemp[19] + $9C30D539 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegF and (LRegB and LRegH xor LRegA xor LRegE) xor LRegB and LRegC xor LRegH and LRegD xor LRegE;
  LRegG := LTemp[9] + $2AF26013 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegE and (LRegA and LRegG xor LRegH xor LRegD) xor LRegA and LRegB xor LRegG and LRegC xor LRegD;
  LRegF := LTemp[4] + $C5D1B023 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegD and (LRegH and LRegF xor LRegG xor LRegC) xor LRegH and LRegA xor LRegF and LRegB xor LRegC;
  LRegE := LTemp[20] + $286085F0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegC and (LRegG and LRegE xor LRegF xor LRegB) xor LRegG and LRegH xor LRegE and LRegA xor LRegB;
  LRegD := LTemp[28] + $CA417918 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegB and (LRegF and LRegD xor LRegE xor LRegA) xor LRegF and LRegG xor LRegD and LRegH xor LRegA;
  LRegC := LTemp[17] + $B8DB38EF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegA and (LRegE and LRegC xor LRegD xor LRegH) xor LRegE and LRegF xor LRegC and LRegG xor LRegH;
  LRegB := LTemp[8] + $8E79DCB0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegH and (LRegD and LRegB xor LRegC xor LRegG) xor LRegD and LRegE xor LRegB and LRegF xor LRegG;
  LRegA := LTemp[22] + $603A180E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegG and (LRegC and LRegA xor LRegB xor LRegF) xor LRegC and LRegD xor LRegA and LRegE xor LRegF;
  LRegH := LTemp[29] + $6C9E0E8B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegF and (LRegB and LRegH xor LRegA xor LRegE) xor LRegB and LRegC xor LRegH and LRegD xor LRegE;
  LRegG := LTemp[14] + $B01E8A3E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegE and (LRegA and LRegG xor LRegH xor LRegD) xor LRegA and LRegB xor LRegG and LRegC xor LRegD;
  LRegF := LTemp[25] + $D71577C1 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegD and (LRegH and LRegF xor LRegG xor LRegC) xor LRegH and LRegA xor LRegF and LRegB xor LRegC;
  LRegE := LTemp[12] + $BD314B27 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegC and (LRegG and LRegE xor LRegF xor LRegB) xor LRegG and LRegH xor LRegE and LRegA xor LRegB;
  LRegD := LTemp[24] + $78AF2FDA + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegB and (LRegF and LRegD xor LRegE xor LRegA) xor LRegF and LRegG xor LRegD and LRegH xor LRegA;
  LRegC := LTemp[30] + $55605C60 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegA and (LRegE and LRegC xor LRegD xor LRegH) xor LRegE and LRegF xor LRegC and LRegG xor LRegH;
  LRegB := LTemp[16] + $E65525F3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegH and (LRegD and LRegB xor LRegC xor LRegG) xor LRegD and LRegE xor LRegB and LRegF xor LRegG;
  LRegA := LTemp[26] + $AA55AB94 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegG and (LRegC and LRegA xor LRegB xor LRegF) xor LRegC and LRegD xor LRegA and LRegE xor LRegF;
  LRegH := LTemp[31] + $57489862 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegF and (LRegB and LRegH xor LRegA xor LRegE) xor LRegB and LRegC xor LRegH and LRegD xor LRegE;
  LRegG := LTemp[15] + $63E81440 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegE and (LRegA and LRegG xor LRegH xor LRegD) xor LRegA and LRegB xor LRegG and LRegC xor LRegD;
  LRegF := LTemp[7] + $55CA396A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegD and (LRegH and LRegF xor LRegG xor LRegC) xor LRegH and LRegA xor LRegF and LRegB xor LRegC;
  LRegE := LTemp[3] + $2AAB10B6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegC and (LRegG and LRegE xor LRegF xor LRegB) xor LRegG and LRegH xor LRegE and LRegA xor LRegB;
  LRegD := LTemp[1] + $B4CC5C34 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegB and (LRegF and LRegD xor LRegE xor LRegA) xor LRegF and LRegG xor LRegD and LRegH xor LRegA;
  LRegC := LTemp[0] + $1141E8CE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegA and (LRegE and LRegC xor LRegD xor LRegH) xor LRegE and LRegF xor LRegC and LRegG xor LRegH;
  LRegB := LTemp[18] + $A15486AF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegH and (LRegD and LRegB xor LRegC xor LRegG) xor LRegD and LRegE xor LRegB and LRegF xor LRegG;
  LRegA := LTemp[27] + $7C72E993 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegG and (LRegC and LRegA xor LRegB xor LRegF) xor LRegC and LRegD xor LRegA and LRegE xor LRegF;
  LRegH := LTemp[13] + $B3EE1411 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegF and (LRegB and LRegH xor LRegA xor LRegE) xor LRegB and LRegC xor LRegH and LRegD xor LRegE;
  LRegG := LTemp[6] + $636FBC2A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegE and (LRegA and LRegG xor LRegH xor LRegD) xor LRegA and LRegB xor LRegG and LRegC xor LRegD;
  LRegF := LTemp[21] + $2BA9C55D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegD and (LRegH and LRegF xor LRegG xor LRegC) xor LRegH and LRegA xor LRegF and LRegB xor LRegC;
  LRegE := LTemp[10] + $741831F6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegC and (LRegG and LRegE xor LRegF xor LRegB) xor LRegG and LRegH xor LRegE and LRegA xor LRegB;
  LRegD := LTemp[23] + $CE5C3E16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegB and (LRegF and LRegD xor LRegE xor LRegA) xor LRegF and LRegG xor LRegD and LRegH xor LRegA;
  LRegC := LTemp[11] + $9B87931E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegA and (LRegE and LRegC xor LRegD xor LRegH) xor LRegE and LRegF xor LRegC and LRegG xor LRegH;
  LRegB := LTemp[5] + $AFD6BA33 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegH and (LRegD and LRegB xor LRegC xor LRegG) xor LRegD and LRegE xor LRegB and LRegF xor LRegG;
  LRegA := LTemp[2] + $6C24CF5C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegA and (LRegE and not LRegC xor LRegF and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegF and
    (LRegB and LRegC xor LRegE xor LRegG) xor LRegC and LRegG xor LRegD;
  LRegH := LTemp[24] + $7A325381 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegH and (LRegD and not LRegB xor LRegE and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegE and
    (LRegA and LRegB xor LRegD xor LRegF) xor LRegB and LRegF xor LRegC;
  LRegG := LTemp[4] + $28958677 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegG and (LRegC and not LRegA xor LRegD and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegD and
    (LRegH and LRegA xor LRegC xor LRegE) xor LRegA and LRegE xor LRegB;
  LRegF := LTemp[0] + $3B8F4898 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegF and (LRegB and not LRegH xor LRegC and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegC and
    (LRegG and LRegH xor LRegB xor LRegD) xor LRegH and LRegD xor LRegA;
  LRegE := LTemp[14] + $6B4BB9AF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegE and (LRegA and not LRegG xor LRegB and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegB and
    (LRegF and LRegG xor LRegA xor LRegC) xor LRegG and LRegC xor LRegH;
  LRegD := LTemp[2] + $C4BFE81B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegD and (LRegH and not LRegF xor LRegA and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegA and
    (LRegE and LRegF xor LRegH xor LRegB) xor LRegF and LRegB xor LRegG;
  LRegC := LTemp[7] + $66282193 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegC and (LRegG and not LRegE xor LRegH and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegH and
    (LRegD and LRegE xor LRegG xor LRegA) xor LRegE and LRegA xor LRegF;
  LRegB := LTemp[28] + $61D809CC + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegB and (LRegF and not LRegD xor LRegG and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegG and
    (LRegC and LRegD xor LRegF xor LRegH) xor LRegD and LRegH xor LRegE;
  LRegA := LTemp[23] + $FB21A991 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegA and (LRegE and not LRegC xor LRegF and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegF and
    (LRegB and LRegC xor LRegE xor LRegG) xor LRegC and LRegG xor LRegD;
  LRegH := LTemp[26] + $487CAC60 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegH and (LRegD and not LRegB xor LRegE and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegE and
    (LRegA and LRegB xor LRegD xor LRegF) xor LRegB and LRegF xor LRegC;
  LRegG := LTemp[6] + $5DEC8032 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegG and (LRegC and not LRegA xor LRegD and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegD and
    (LRegH and LRegA xor LRegC xor LRegE) xor LRegA and LRegE xor LRegB;
  LRegF := LTemp[30] + $EF845D5D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegF and (LRegB and not LRegH xor LRegC and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegC and
    (LRegG and LRegH xor LRegB xor LRegD) xor LRegH and LRegD xor LRegA;
  LRegE := LTemp[20] + $E98575B1 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegE and (LRegA and not LRegG xor LRegB and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegB and
    (LRegF and LRegG xor LRegA xor LRegC) xor LRegG and LRegC xor LRegH;
  LRegD := LTemp[18] + $DC262302 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegD and (LRegH and not LRegF xor LRegA and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegA and
    (LRegE and LRegF xor LRegH xor LRegB) xor LRegF and LRegB xor LRegG;
  LRegC := LTemp[25] + $EB651B88 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegC and (LRegG and not LRegE xor LRegH and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegH and
    (LRegD and LRegE xor LRegG xor LRegA) xor LRegE and LRegA xor LRegF;
  LRegB := LTemp[19] + $23893E81 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegB and (LRegF and not LRegD xor LRegG and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegG and
    (LRegC and LRegD xor LRegF xor LRegH) xor LRegD and LRegH xor LRegE;
  LRegA := LTemp[3] + $D396ACC5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegA and (LRegE and not LRegC xor LRegF and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegF and
    (LRegB and LRegC xor LRegE xor LRegG) xor LRegC and LRegG xor LRegD;
  LRegH := LTemp[22] + $0F6D6FF3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegH and (LRegD and not LRegB xor LRegE and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegE and
    (LRegA and LRegB xor LRegD xor LRegF) xor LRegB and LRegF xor LRegC;
  LRegG := LTemp[11] + $83F44239 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegG and (LRegC and not LRegA xor LRegD and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegD and
    (LRegH and LRegA xor LRegC xor LRegE) xor LRegA and LRegE xor LRegB;
  LRegF := LTemp[31] + $2E0B4482 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegF and (LRegB and not LRegH xor LRegC and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegC and
    (LRegG and LRegH xor LRegB xor LRegD) xor LRegH and LRegD xor LRegA;
  LRegE := LTemp[21] + $A4842004 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegE and (LRegA and not LRegG xor LRegB and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegB and
    (LRegF and LRegG xor LRegA xor LRegC) xor LRegG and LRegC xor LRegH;
  LRegD := LTemp[8] + $69C8F04A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegD and (LRegH and not LRegF xor LRegA and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegA and
    (LRegE and LRegF xor LRegH xor LRegB) xor LRegF and LRegB xor LRegG;
  LRegC := LTemp[27] + $9E1F9B5E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegC and (LRegG and not LRegE xor LRegH and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegH and
    (LRegD and LRegE xor LRegG xor LRegA) xor LRegE and LRegA xor LRegF;
  LRegB := LTemp[12] + $21C66842 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegB and (LRegF and not LRegD xor LRegG and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegG and
    (LRegC and LRegD xor LRegF xor LRegH) xor LRegD and LRegH xor LRegE;
  LRegA := LTemp[9] + $F6E96C9A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegA and (LRegE and not LRegC xor LRegF and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegF and
    (LRegB and LRegC xor LRegE xor LRegG) xor LRegC and LRegG xor LRegD;
  LRegH := LTemp[1] + $670C9C61 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegH and (LRegD and not LRegB xor LRegE and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegE and
    (LRegA and LRegB xor LRegD xor LRegF) xor LRegB and LRegF xor LRegC;
  LRegG := LTemp[29] + $ABD388F0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegG and (LRegC and not LRegA xor LRegD and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegD and
    (LRegH and LRegA xor LRegC xor LRegE) xor LRegA and LRegE xor LRegB;
  LRegF := LTemp[5] + $6A51A0D2 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegF and (LRegB and not LRegH xor LRegC and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegC and
    (LRegG and LRegH xor LRegB xor LRegD) xor LRegH and LRegD xor LRegA;
  LRegE := LTemp[15] + $D8542F68 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegE and (LRegA and not LRegG xor LRegB and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegB and
    (LRegF and LRegG xor LRegA xor LRegC) xor LRegG and LRegC xor LRegH;
  LRegD := LTemp[17] + $960FA728 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegD and (LRegH and not LRegF xor LRegA and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegA and
    (LRegE and LRegF xor LRegH xor LRegB) xor LRegF and LRegB xor LRegG;
  LRegC := LTemp[10] + $AB5133A3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegC and (LRegG and not LRegE xor LRegH and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegH and
    (LRegD and LRegE xor LRegG xor LRegA) xor LRegE and LRegA xor LRegF;
  LRegB := LTemp[16] + $6EEF0B6C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegB and (LRegF and not LRegD xor LRegG and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegG and
    (LRegC and LRegD xor LRegF xor LRegH) xor LRegD and LRegH xor LRegE;
  LRegA := LTemp[13] + $137A3BE4 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  FHash[0] := FHash[0] + LRegA;
  FHash[1] := FHash[1] + LRegB;
  FHash[2] := FHash[2] + LRegC;
  FHash[3] := FHash[3] + LRegD;
  FHash[4] := FHash[4] + LRegE;
  FHash[5] := FHash[5] + LRegF;
  FHash[6] := FHash[6] + LRegG;
  FHash[7] := FHash[7] + LRegH;

  System.FillChar(LTemp, System.SizeOf(LTemp), UInt32(0));
end;

{ THaval5 }

constructor THaval5.Create(AHashSize: THashSize);
begin
  inherited Create(THashRounds.hrRounds5, AHashSize);
end;

procedure THaval5.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
var
  LRegA, LRegB, LRegC, LRegD, LRegE, LRegF, LRegG, LRegH, LNfOut: UInt32;
  LTemp: array [0 .. 31] of UInt32;
begin
  TConverters.le32_copy(AData, AIndex, @(LTemp[0]), 0, ADataLength);

  LRegA := FHash[0];
  LRegB := FHash[1];
  LRegC := FHash[2];
  LRegD := FHash[3];
  LRegE := FHash[4];
  LRegF := FHash[5];
  LRegG := FHash[6];
  LRegH := FHash[7];

  LNfOut := LRegC and (LRegG xor LRegB) xor LRegF and LRegE xor LRegA and LRegD xor LRegG;
  LRegH := LTemp[0] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);
  LNfOut := LRegB and (LRegF xor LRegA) xor LRegE and LRegD xor LRegH and LRegC xor LRegF;
  LRegG := LTemp[1] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegE xor LRegH) xor LRegD and LRegC xor LRegG and LRegB xor LRegE;
  LRegF := LTemp[2] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegD xor LRegG) xor LRegC and LRegB xor LRegF and LRegA xor LRegD;
  LRegE := LTemp[3] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegC xor LRegF) xor LRegB and LRegA xor LRegE and LRegH xor LRegC;
  LRegD := LTemp[4] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegB xor LRegE) xor LRegA and LRegH xor LRegD and LRegG xor LRegB;
  LRegC := LTemp[5] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegA xor LRegD) xor LRegH and LRegG xor LRegC and LRegF xor LRegA;
  LRegB := LTemp[6] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegH xor LRegC) xor LRegG and LRegF xor LRegB and LRegE xor LRegH;
  LRegA := LTemp[7] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegG xor LRegB) xor LRegF and LRegE xor LRegA and LRegD xor LRegG;
  LRegH := LTemp[8] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegF xor LRegA) xor LRegE and LRegD xor LRegH and LRegC xor LRegF;
  LRegG := LTemp[9] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegE xor LRegH) xor LRegD and LRegC xor LRegG and LRegB xor LRegE;
  LRegF := LTemp[10] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegD xor LRegG) xor LRegC and LRegB xor LRegF and LRegA xor LRegD;
  LRegE := LTemp[11] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegC xor LRegF) xor LRegB and LRegA xor LRegE and LRegH xor LRegC;
  LRegD := LTemp[12] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegB xor LRegE) xor LRegA and LRegH xor LRegD and LRegG xor LRegB;
  LRegC := LTemp[13] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegA xor LRegD) xor LRegH and LRegG xor LRegC and LRegF xor LRegA;
  LRegB := LTemp[14] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegH xor LRegC) xor LRegG and LRegF xor LRegB and LRegE xor LRegH;
  LRegA := LTemp[15] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegG xor LRegB) xor LRegF and LRegE xor LRegA and LRegD xor LRegG;
  LRegH := LTemp[16] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegF xor LRegA) xor LRegE and LRegD xor LRegH and LRegC xor LRegF;
  LRegG := LTemp[17] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegE xor LRegH) xor LRegD and LRegC xor LRegG and LRegB xor LRegE;
  LRegF := LTemp[18] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegD xor LRegG) xor LRegC and LRegB xor LRegF and LRegA xor LRegD;
  LRegE := LTemp[19] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegC xor LRegF) xor LRegB and LRegA xor LRegE and LRegH xor LRegC;
  LRegD := LTemp[20] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegB xor LRegE) xor LRegA and LRegH xor LRegD and LRegG xor LRegB;
  LRegC := LTemp[21] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegA xor LRegD) xor LRegH and LRegG xor LRegC and LRegF xor LRegA;
  LRegB := LTemp[22] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegH xor LRegC) xor LRegG and LRegF xor LRegB and LRegE xor LRegH;
  LRegA := LTemp[23] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegC and (LRegG xor LRegB) xor LRegF and LRegE xor LRegA and LRegD xor LRegG;
  LRegH := LTemp[24] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegB and (LRegF xor LRegA) xor LRegE and LRegD xor LRegH and LRegC xor LRegF;
  LRegG := LTemp[25] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegA and (LRegE xor LRegH) xor LRegD and LRegC xor LRegG and LRegB xor LRegE;
  LRegF := LTemp[26] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegH and (LRegD xor LRegG) xor LRegC and LRegB xor LRegF and LRegA xor LRegD;
  LRegE := LTemp[27] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegG and (LRegC xor LRegF) xor LRegB and LRegA xor LRegE and LRegH xor LRegC;
  LRegD := LTemp[28] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegF and (LRegB xor LRegE) xor LRegA and LRegH xor LRegD and LRegG xor LRegB;
  LRegC := LTemp[29] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegE and (LRegA xor LRegD) xor LRegH and LRegG xor LRegC and LRegF xor LRegA;
  LRegB := LTemp[30] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegD and (LRegH xor LRegC) xor LRegG and LRegF xor LRegB and LRegE xor LRegH;
  LRegA := LTemp[31] + TBits.RotateRight32(LNfOut, 7) + TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegE and not LRegA xor LRegB and LRegC xor LRegG xor LRegF) xor LRegB and (LRegE xor LRegC)
    xor LRegA and LRegC xor LRegF;
  LRegH := LTemp[5] + $452821E6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegD and not LRegH xor LRegA and LRegB xor LRegF xor LRegE) xor LRegA and (LRegD xor LRegB)
    xor LRegH and LRegB xor LRegE;
  LRegG := LTemp[14] + $38D01377 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegC and not LRegG xor LRegH and LRegA xor LRegE xor LRegD) xor LRegH and (LRegC xor LRegA)
    xor LRegG and LRegA xor LRegD;
  LRegF := LTemp[26] + $BE5466CF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegB and not LRegF xor LRegG and LRegH xor LRegD xor LRegC) xor LRegG and (LRegB xor LRegH)
    xor LRegF and LRegH xor LRegC;
  LRegE := LTemp[18] + $34E90C6C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegA and not LRegE xor LRegF and LRegG xor LRegC xor LRegB) xor LRegF and (LRegA xor LRegG)
    xor LRegE and LRegG xor LRegB;
  LRegD := LTemp[11] + $C0AC29B7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegH and not LRegD xor LRegE and LRegF xor LRegB xor LRegA) xor LRegE and (LRegH xor LRegF)
    xor LRegD and LRegF xor LRegA;
  LRegC := LTemp[28] + $C97C50DD + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegG and not LRegC xor LRegD and LRegE xor LRegA xor LRegH) xor LRegD and (LRegG xor LRegE)
    xor LRegC and LRegE xor LRegH;
  LRegB := LTemp[7] + $3F84D5B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegF and not LRegB xor LRegC and LRegD xor LRegH xor LRegG) xor LRegC and (LRegF xor LRegD)
    xor LRegB and LRegD xor LRegG;
  LRegA := LTemp[16] + $B5470917 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegE and not LRegA xor LRegB and LRegC xor LRegG xor LRegF) xor LRegB and (LRegE xor LRegC)
    xor LRegA and LRegC xor LRegF;
  LRegH := LTemp[0] + $9216D5D9 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegD and not LRegH xor LRegA and LRegB xor LRegF xor LRegE) xor LRegA and (LRegD xor LRegB)
    xor LRegH and LRegB xor LRegE;
  LRegG := LTemp[23] + $8979FB1B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegC and not LRegG xor LRegH and LRegA xor LRegE xor LRegD) xor LRegH and (LRegC xor LRegA)
    xor LRegG and LRegA xor LRegD;
  LRegF := LTemp[20] + $D1310BA6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegB and not LRegF xor LRegG and LRegH xor LRegD xor LRegC) xor LRegG and (LRegB xor LRegH)
    xor LRegF and LRegH xor LRegC;
  LRegE := LTemp[22] + $98DFB5AC + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegA and not LRegE xor LRegF and LRegG xor LRegC xor LRegB) xor LRegF and (LRegA xor LRegG)
    xor LRegE and LRegG xor LRegB;
  LRegD := LTemp[1] + $2FFD72DB + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegH and not LRegD xor LRegE and LRegF xor LRegB xor LRegA) xor LRegE and (LRegH xor LRegF)
    xor LRegD and LRegF xor LRegA;
  LRegC := LTemp[10] + $D01ADFB7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegG and not LRegC xor LRegD and LRegE xor LRegA xor LRegH) xor LRegD and (LRegG xor LRegE)
    xor LRegC and LRegE xor LRegH;
  LRegB := LTemp[4] + $B8E1AFED + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegF and not LRegB xor LRegC and LRegD xor LRegH xor LRegG) xor LRegC and (LRegF xor LRegD)
    xor LRegB and LRegD xor LRegG;
  LRegA := LTemp[8] + $6A267E96 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegE and not LRegA xor LRegB and LRegC xor LRegG xor LRegF) xor LRegB and (LRegE xor LRegC)
    xor LRegA and LRegC xor LRegF;
  LRegH := LTemp[30] + $BA7C9045 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegD and not LRegH xor LRegA and LRegB xor LRegF xor LRegE) xor LRegA and (LRegD xor LRegB)
    xor LRegH and LRegB xor LRegE;
  LRegG := LTemp[3] + $F12C7F99 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegC and not LRegG xor LRegH and LRegA xor LRegE xor LRegD) xor LRegH and (LRegC xor LRegA)
    xor LRegG and LRegA xor LRegD;
  LRegF := LTemp[21] + $24A19947 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegB and not LRegF xor LRegG and LRegH xor LRegD xor LRegC) xor LRegG and (LRegB xor LRegH)
    xor LRegF and LRegH xor LRegC;
  LRegE := LTemp[9] + $B3916CF7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegA and not LRegE xor LRegF and LRegG xor LRegC xor LRegB) xor LRegF and (LRegA xor LRegG)
    xor LRegE and LRegG xor LRegB;
  LRegD := LTemp[17] + $0801F2E2 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegH and not LRegD xor LRegE and LRegF xor LRegB xor LRegA) xor LRegE and (LRegH xor LRegF)
    xor LRegD and LRegF xor LRegA;
  LRegC := LTemp[24] + $858EFC16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegG and not LRegC xor LRegD and LRegE xor LRegA xor LRegH) xor LRegD and (LRegG xor LRegE)
    xor LRegC and LRegE xor LRegH;
  LRegB := LTemp[29] + $636920D8 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegF and not LRegB xor LRegC and LRegD xor LRegH xor LRegG) xor LRegC and (LRegF xor LRegD)
    xor LRegB and LRegD xor LRegG;
  LRegA := LTemp[6] + $71574E69 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegE and not LRegA xor LRegB and LRegC xor LRegG xor LRegF) xor LRegB and (LRegE xor LRegC)
    xor LRegA and LRegC xor LRegF;
  LRegH := LTemp[19] + $A458FEA3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegD and not LRegH xor LRegA and LRegB xor LRegF xor LRegE) xor LRegA and (LRegD xor LRegB)
    xor LRegH and LRegB xor LRegE;
  LRegG := LTemp[12] + $F4933D7E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegC and not LRegG xor LRegH and LRegA xor LRegE xor LRegD) xor LRegH and (LRegC xor LRegA)
    xor LRegG and LRegA xor LRegD;
  LRegF := LTemp[15] + $0D95748F + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegB and not LRegF xor LRegG and LRegH xor LRegD xor LRegC) xor LRegG and (LRegB xor LRegH)
    xor LRegF and LRegH xor LRegC;
  LRegE := LTemp[13] + $728EB658 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegA and not LRegE xor LRegF and LRegG xor LRegC xor LRegB) xor LRegF and (LRegA xor LRegG)
    xor LRegE and LRegG xor LRegB;
  LRegD := LTemp[2] + $718BCD58 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegH and not LRegD xor LRegE and LRegF xor LRegB xor LRegA) xor LRegE and (LRegH xor LRegF)
    xor LRegD and LRegF xor LRegA;
  LRegC := LTemp[25] + $82154AEE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegG and not LRegC xor LRegD and LRegE xor LRegA xor LRegH) xor LRegD and (LRegG xor LRegE)
    xor LRegC and LRegE xor LRegH;
  LRegB := LTemp[31] + $7B54A41D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegF and not LRegB xor LRegC and LRegD xor LRegH xor LRegG) xor LRegC and (LRegF xor LRegD)
    xor LRegB and LRegD xor LRegG;
  LRegA := LTemp[27] + $C25A59B5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegE and (LRegB and LRegD xor LRegC xor LRegF) xor LRegB and LRegA xor LRegD and LRegG xor LRegF;
  LRegH := LTemp[19] + $9C30D539 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegD and (LRegA and LRegC xor LRegB xor LRegE) xor LRegA and LRegH xor LRegC and LRegF xor LRegE;
  LRegG := LTemp[9] + $2AF26013 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegC and (LRegH and LRegB xor LRegA xor LRegD) xor LRegH and LRegG xor LRegB and LRegE xor LRegD;
  LRegF := LTemp[4] + $C5D1B023 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegB and (LRegG and LRegA xor LRegH xor LRegC) xor LRegG and LRegF xor LRegA and LRegD xor LRegC;
  LRegE := LTemp[20] + $286085F0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegA and (LRegF and LRegH xor LRegG xor LRegB) xor LRegF and LRegE xor LRegH and LRegC xor LRegB;
  LRegD := LTemp[28] + $CA417918 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegH and (LRegE and LRegG xor LRegF xor LRegA) xor LRegE and LRegD xor LRegG and LRegB xor LRegA;
  LRegC := LTemp[17] + $B8DB38EF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegG and (LRegD and LRegF xor LRegE xor LRegH) xor LRegD and LRegC xor LRegF and LRegA xor LRegH;
  LRegB := LTemp[8] + $8E79DCB0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegF and (LRegC and LRegE xor LRegD xor LRegG) xor LRegC and LRegB xor LRegE and LRegH xor LRegG;
  LRegA := LTemp[22] + $603A180E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegE and (LRegB and LRegD xor LRegC xor LRegF) xor LRegB and LRegA xor LRegD and LRegG xor LRegF;
  LRegH := LTemp[29] + $6C9E0E8B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegD and (LRegA and LRegC xor LRegB xor LRegE) xor LRegA and LRegH xor LRegC and LRegF xor LRegE;
  LRegG := LTemp[14] + $B01E8A3E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegC and (LRegH and LRegB xor LRegA xor LRegD) xor LRegH and LRegG xor LRegB and LRegE xor LRegD;
  LRegF := LTemp[25] + $D71577C1 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegB and (LRegG and LRegA xor LRegH xor LRegC) xor LRegG and LRegF xor LRegA and LRegD xor LRegC;
  LRegE := LTemp[12] + $BD314B27 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegA and (LRegF and LRegH xor LRegG xor LRegB) xor LRegF and LRegE xor LRegH and LRegC xor LRegB;
  LRegD := LTemp[24] + $78AF2FDA + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegH and (LRegE and LRegG xor LRegF xor LRegA) xor LRegE and LRegD xor LRegG and LRegB xor LRegA;
  LRegC := LTemp[30] + $55605C60 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegG and (LRegD and LRegF xor LRegE xor LRegH) xor LRegD and LRegC xor LRegF and LRegA xor LRegH;
  LRegB := LTemp[16] + $E65525F3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegF and (LRegC and LRegE xor LRegD xor LRegG) xor LRegC and LRegB xor LRegE and LRegH xor LRegG;
  LRegA := LTemp[26] + $AA55AB94 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegE and (LRegB and LRegD xor LRegC xor LRegF) xor LRegB and LRegA xor LRegD and LRegG xor LRegF;
  LRegH := LTemp[31] + $57489862 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegD and (LRegA and LRegC xor LRegB xor LRegE) xor LRegA and LRegH xor LRegC and LRegF xor LRegE;
  LRegG := LTemp[15] + $63E81440 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegC and (LRegH and LRegB xor LRegA xor LRegD) xor LRegH and LRegG xor LRegB and LRegE xor LRegD;
  LRegF := LTemp[7] + $55CA396A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegB and (LRegG and LRegA xor LRegH xor LRegC) xor LRegG and LRegF xor LRegA and LRegD xor LRegC;
  LRegE := LTemp[3] + $2AAB10B6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegA and (LRegF and LRegH xor LRegG xor LRegB) xor LRegF and LRegE xor LRegH and LRegC xor LRegB;
  LRegD := LTemp[1] + $B4CC5C34 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegH and (LRegE and LRegG xor LRegF xor LRegA) xor LRegE and LRegD xor LRegG and LRegB xor LRegA;
  LRegC := LTemp[0] + $1141E8CE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegG and (LRegD and LRegF xor LRegE xor LRegH) xor LRegD and LRegC xor LRegF and LRegA xor LRegH;
  LRegB := LTemp[18] + $A15486AF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegF and (LRegC and LRegE xor LRegD xor LRegG) xor LRegC and LRegB xor LRegE and LRegH xor LRegG;
  LRegA := LTemp[27] + $7C72E993 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegE and (LRegB and LRegD xor LRegC xor LRegF) xor LRegB and LRegA xor LRegD and LRegG xor LRegF;
  LRegH := LTemp[13] + $B3EE1411 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegD and (LRegA and LRegC xor LRegB xor LRegE) xor LRegA and LRegH xor LRegC and LRegF xor LRegE;
  LRegG := LTemp[6] + $636FBC2A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegC and (LRegH and LRegB xor LRegA xor LRegD) xor LRegH and LRegG xor LRegB and LRegE xor LRegD;
  LRegF := LTemp[21] + $2BA9C55D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegB and (LRegG and LRegA xor LRegH xor LRegC) xor LRegG and LRegF xor LRegA and LRegD xor LRegC;
  LRegE := LTemp[10] + $741831F6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegA and (LRegF and LRegH xor LRegG xor LRegB) xor LRegF and LRegE xor LRegH and LRegC xor LRegB;
  LRegD := LTemp[23] + $CE5C3E16 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegH and (LRegE and LRegG xor LRegF xor LRegA) xor LRegE and LRegD xor LRegG and LRegB xor LRegA;
  LRegC := LTemp[11] + $9B87931E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegG and (LRegD and LRegF xor LRegE xor LRegH) xor LRegD and LRegC xor LRegF and LRegA xor LRegH;
  LRegB := LTemp[5] + $AFD6BA33 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegF and (LRegC and LRegE xor LRegD xor LRegG) xor LRegC and LRegB xor LRegE and LRegH xor LRegG;
  LRegA := LTemp[2] + $6C24CF5C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and not LRegA xor LRegC and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegC and
    (LRegE and LRegA xor LRegF xor LRegB) xor LRegA and LRegB xor LRegG;
  LRegH := LTemp[24] + $7A325381 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and not LRegH xor LRegB and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegB and
    (LRegD and LRegH xor LRegE xor LRegA) xor LRegH and LRegA xor LRegF;
  LRegG := LTemp[4] + $28958677 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and not LRegG xor LRegA and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegA and
    (LRegC and LRegG xor LRegD xor LRegH) xor LRegG and LRegH xor LRegE;
  LRegF := LTemp[0] + $3B8F4898 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and not LRegF xor LRegH and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegH and
    (LRegB and LRegF xor LRegC xor LRegG) xor LRegF and LRegG xor LRegD;
  LRegE := LTemp[14] + $6B4BB9AF + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and not LRegE xor LRegG and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegG and
    (LRegA and LRegE xor LRegB xor LRegF) xor LRegE and LRegF xor LRegC;
  LRegD := LTemp[2] + $C4BFE81B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and not LRegD xor LRegF and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegF and
    (LRegH and LRegD xor LRegA xor LRegE) xor LRegD and LRegE xor LRegB;
  LRegC := LTemp[7] + $66282193 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and not LRegC xor LRegE and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegE and
    (LRegG and LRegC xor LRegH xor LRegD) xor LRegC and LRegD xor LRegA;
  LRegB := LTemp[28] + $61D809CC + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and not LRegB xor LRegD and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegD and
    (LRegF and LRegB xor LRegG xor LRegC) xor LRegB and LRegC xor LRegH;
  LRegA := LTemp[23] + $FB21A991 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and not LRegA xor LRegC and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegC and
    (LRegE and LRegA xor LRegF xor LRegB) xor LRegA and LRegB xor LRegG;
  LRegH := LTemp[26] + $487CAC60 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and not LRegH xor LRegB and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegB and
    (LRegD and LRegH xor LRegE xor LRegA) xor LRegH and LRegA xor LRegF;
  LRegG := LTemp[6] + $5DEC8032 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and not LRegG xor LRegA and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegA and
    (LRegC and LRegG xor LRegD xor LRegH) xor LRegG and LRegH xor LRegE;
  LRegF := LTemp[30] + $EF845D5D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and not LRegF xor LRegH and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegH and
    (LRegB and LRegF xor LRegC xor LRegG) xor LRegF and LRegG xor LRegD;
  LRegE := LTemp[20] + $E98575B1 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and not LRegE xor LRegG and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegG and
    (LRegA and LRegE xor LRegB xor LRegF) xor LRegE and LRegF xor LRegC;
  LRegD := LTemp[18] + $DC262302 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and not LRegD xor LRegF and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegF and
    (LRegH and LRegD xor LRegA xor LRegE) xor LRegD and LRegE xor LRegB;
  LRegC := LTemp[25] + $EB651B88 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and not LRegC xor LRegE and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegE and
    (LRegG and LRegC xor LRegH xor LRegD) xor LRegC and LRegD xor LRegA;
  LRegB := LTemp[19] + $23893E81 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and not LRegB xor LRegD and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegD and
    (LRegF and LRegB xor LRegG xor LRegC) xor LRegB and LRegC xor LRegH;
  LRegA := LTemp[3] + $D396ACC5 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and not LRegA xor LRegC and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegC and
    (LRegE and LRegA xor LRegF xor LRegB) xor LRegA and LRegB xor LRegG;
  LRegH := LTemp[22] + $0F6D6FF3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and not LRegH xor LRegB and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegB and
    (LRegD and LRegH xor LRegE xor LRegA) xor LRegH and LRegA xor LRegF;
  LRegG := LTemp[11] + $83F44239 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and not LRegG xor LRegA and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegA and
    (LRegC and LRegG xor LRegD xor LRegH) xor LRegG and LRegH xor LRegE;
  LRegF := LTemp[31] + $2E0B4482 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and not LRegF xor LRegH and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegH and
    (LRegB and LRegF xor LRegC xor LRegG) xor LRegF and LRegG xor LRegD;
  LRegE := LTemp[21] + $A4842004 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and not LRegE xor LRegG and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegG and
    (LRegA and LRegE xor LRegB xor LRegF) xor LRegE and LRegF xor LRegC;
  LRegD := LTemp[8] + $69C8F04A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and not LRegD xor LRegF and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegF and
    (LRegH and LRegD xor LRegA xor LRegE) xor LRegD and LRegE xor LRegB;
  LRegC := LTemp[27] + $9E1F9B5E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and not LRegC xor LRegE and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegE and
    (LRegG and LRegC xor LRegH xor LRegD) xor LRegC and LRegD xor LRegA;
  LRegB := LTemp[12] + $21C66842 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and not LRegB xor LRegD and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegD and
    (LRegF and LRegB xor LRegG xor LRegC) xor LRegB and LRegC xor LRegH;
  LRegA := LTemp[9] + $F6E96C9A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegD and (LRegF and not LRegA xor LRegC and not LRegB xor LRegE xor LRegB xor LRegG) xor LRegC and
    (LRegE and LRegA xor LRegF xor LRegB) xor LRegA and LRegB xor LRegG;
  LRegH := LTemp[1] + $670C9C61 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegC and (LRegE and not LRegH xor LRegB and not LRegA xor LRegD xor LRegA xor LRegF) xor LRegB and
    (LRegD and LRegH xor LRegE xor LRegA) xor LRegH and LRegA xor LRegF;
  LRegG := LTemp[29] + $ABD388F0 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegB and (LRegD and not LRegG xor LRegA and not LRegH xor LRegC xor LRegH xor LRegE) xor LRegA and
    (LRegC and LRegG xor LRegD xor LRegH) xor LRegG and LRegH xor LRegE;
  LRegF := LTemp[5] + $6A51A0D2 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegA and (LRegC and not LRegF xor LRegH and not LRegG xor LRegB xor LRegG xor LRegD) xor LRegH and
    (LRegB and LRegF xor LRegC xor LRegG) xor LRegF and LRegG xor LRegD;
  LRegE := LTemp[15] + $D8542F68 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegH and (LRegB and not LRegE xor LRegG and not LRegF xor LRegA xor LRegF xor LRegC) xor LRegG and
    (LRegA and LRegE xor LRegB xor LRegF) xor LRegE and LRegF xor LRegC;
  LRegD := LTemp[17] + $960FA728 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegG and (LRegA and not LRegD xor LRegF and not LRegE xor LRegH xor LRegE xor LRegB) xor LRegF and
    (LRegH and LRegD xor LRegA xor LRegE) xor LRegD and LRegE xor LRegB;
  LRegC := LTemp[10] + $AB5133A3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegF and (LRegH and not LRegC xor LRegE and not LRegD xor LRegG xor LRegD xor LRegA) xor LRegE and
    (LRegG and LRegC xor LRegH xor LRegD) xor LRegC and LRegD xor LRegA;
  LRegB := LTemp[16] + $6EEF0B6C + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegE and (LRegG and not LRegB xor LRegD and not LRegC xor LRegF xor LRegC xor LRegH) xor LRegD and
    (LRegF and LRegB xor LRegG xor LRegC) xor LRegB and LRegC xor LRegH;
  LRegA := LTemp[13] + $137A3BE4 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegD and LRegE and LRegG xor not LRegF) xor LRegD and LRegA xor LRegE and LRegF xor LRegG and LRegC;
  LRegH := LTemp[27] + $BA3BF050 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegC and LRegD and LRegF xor not LRegE) xor LRegC and LRegH xor LRegD and LRegE xor LRegF and LRegB;
  LRegG := LTemp[3] + $7EFB2A98 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegB and LRegC and LRegE xor not LRegD) xor LRegB and LRegG xor LRegC and LRegD xor LRegE and LRegA;
  LRegF := LTemp[21] + $A1F1651D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegA and LRegB and LRegD xor not LRegC) xor LRegA and LRegF xor LRegB and LRegC xor LRegD and LRegH;
  LRegE := LTemp[26] + $39AF0176 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegH and LRegA and LRegC xor not LRegB) xor LRegH and LRegE xor LRegA and LRegB xor LRegC and LRegG;
  LRegD := LTemp[17] + $66CA593E + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegG and LRegH and LRegB xor not LRegA) xor LRegG and LRegD xor LRegH and LRegA xor LRegB and LRegF;
  LRegC := LTemp[11] + $82430E88 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegF and LRegG and LRegA xor not LRegH) xor LRegF and LRegC xor LRegG and LRegH xor LRegA and LRegE;
  LRegB := LTemp[20] + $8CEE8619 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegE and LRegF and LRegH xor not LRegG) xor LRegE and LRegB xor LRegF and LRegG xor LRegH and LRegD;
  LRegA := LTemp[29] + $456F9FB4 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegD and LRegE and LRegG xor not LRegF) xor LRegD and LRegA xor LRegE and LRegF xor LRegG and LRegC;
  LRegH := LTemp[19] + $7D84A5C3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegC and LRegD and LRegF xor not LRegE) xor LRegC and LRegH xor LRegD and LRegE xor LRegF and LRegB;
  LRegG := LTemp[0] + $3B8B5EBE + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegB and LRegC and LRegE xor not LRegD) xor LRegB and LRegG xor LRegC and LRegD xor LRegE and LRegA;
  LRegF := LTemp[12] + $E06F75D8 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegA and LRegB and LRegD xor not LRegC) xor LRegA and LRegF xor LRegB and LRegC xor LRegD and LRegH;
  LRegE := LTemp[7] + $85C12073 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegH and LRegA and LRegC xor not LRegB) xor LRegH and LRegE xor LRegA and LRegB xor LRegC and LRegG;
  LRegD := LTemp[13] + $401A449F + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegG and LRegH and LRegB xor not LRegA) xor LRegG and LRegD xor LRegH and LRegA xor LRegB and LRegF;
  LRegC := LTemp[8] + $56C16AA6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegF and LRegG and LRegA xor not LRegH) xor LRegF and LRegC xor LRegG and LRegH xor LRegA and LRegE;
  LRegB := LTemp[31] + $4ED3AA62 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegE and LRegF and LRegH xor not LRegG) xor LRegE and LRegB xor LRegF and LRegG xor LRegH and LRegD;
  LRegA := LTemp[10] + $363F7706 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegD and LRegE and LRegG xor not LRegF) xor LRegD and LRegA xor LRegE and LRegF xor LRegG and LRegC;
  LRegH := LTemp[5] + $1BFEDF72 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegC and LRegD and LRegF xor not LRegE) xor LRegC and LRegH xor LRegD and LRegE xor LRegF and LRegB;
  LRegG := LTemp[9] + $429B023D + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegB and LRegC and LRegE xor not LRegD) xor LRegB and LRegG xor LRegC and LRegD xor LRegE and LRegA;
  LRegF := LTemp[14] + $37D0D724 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegA and LRegB and LRegD xor not LRegC) xor LRegA and LRegF xor LRegB and LRegC xor LRegD and LRegH;
  LRegE := LTemp[30] + $D00A1248 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegH and LRegA and LRegC xor not LRegB) xor LRegH and LRegE xor LRegA and LRegB xor LRegC and LRegG;
  LRegD := LTemp[18] + $DB0FEAD3 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegG and LRegH and LRegB xor not LRegA) xor LRegG and LRegD xor LRegH and LRegA xor LRegB and LRegF;
  LRegC := LTemp[6] + $49F1C09B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegF and LRegG and LRegA xor not LRegH) xor LRegF and LRegC xor LRegG and LRegH xor LRegA and LRegE;
  LRegB := LTemp[28] + $075372C9 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegE and LRegF and LRegH xor not LRegG) xor LRegE and LRegB xor LRegF and LRegG xor LRegH and LRegD;
  LRegA := LTemp[24] + $80991B7B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  LNfOut := LRegB and (LRegD and LRegE and LRegG xor not LRegF) xor LRegD and LRegA xor LRegE and LRegF xor LRegG and LRegC;
  LRegH := LTemp[2] + $25D479D8 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegH, 11);

  LNfOut := LRegA and (LRegC and LRegD and LRegF xor not LRegE) xor LRegC and LRegH xor LRegD and LRegE xor LRegF and LRegB;
  LRegG := LTemp[23] + $F6E8DEF7 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegG, 11);

  LNfOut := LRegH and (LRegB and LRegC and LRegE xor not LRegD) xor LRegB and LRegG xor LRegC and LRegD xor LRegE and LRegA;
  LRegF := LTemp[16] + $E3FE501A + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegF, 11);

  LNfOut := LRegG and (LRegA and LRegB and LRegD xor not LRegC) xor LRegA and LRegF xor LRegB and LRegC xor LRegD and LRegH;
  LRegE := LTemp[22] + $B6794C3B + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegE, 11);

  LNfOut := LRegF and (LRegH and LRegA and LRegC xor not LRegB) xor LRegH and LRegE xor LRegA and LRegB xor LRegC and LRegG;
  LRegD := LTemp[4] + $976CE0BD + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegD, 11);

  LNfOut := LRegE and (LRegG and LRegH and LRegB xor not LRegA) xor LRegG and LRegD xor LRegH and LRegA xor LRegB and LRegF;
  LRegC := LTemp[1] + $04C006BA + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegC, 11);

  LNfOut := LRegD and (LRegF and LRegG and LRegA xor not LRegH) xor LRegF and LRegC xor LRegG and LRegH xor LRegA and LRegE;
  LRegB := LTemp[25] + $C1A94FB6 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegB, 11);

  LNfOut := LRegC and (LRegE and LRegF and LRegH xor not LRegG) xor LRegE and LRegB xor LRegF and LRegG xor LRegH and LRegD;
  LRegA := LTemp[15] + $409F60C4 + TBits.RotateRight32(LNfOut, 7) +
    TBits.RotateRight32(LRegA, 11);

  FHash[0] := FHash[0] + LRegA;
  FHash[1] := FHash[1] + LRegB;
  FHash[2] := FHash[2] + LRegC;
  FHash[3] := FHash[3] + LRegD;
  FHash[4] := FHash[4] + LRegE;
  FHash[5] := FHash[5] + LRegF;
  FHash[6] := FHash[6] + LRegG;
  FHash[7] := FHash[7] + LRegH;

  System.FillChar(LTemp, System.SizeOf(LTemp), UInt32(0));
end;

{ THaval_3_128 }

function THaval_3_128.Clone(): IHash;
var
  LHashInstance: THaval_3_128;
begin
  LHashInstance := THaval_3_128.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_3_128.Create;
begin
  inherited Create(THashSize.hsHashSize128);
end;

{ THaval_4_128 }

function THaval_4_128.Clone(): IHash;
var
  LHashInstance: THaval_4_128;
begin
  LHashInstance := THaval_4_128.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_4_128.Create;
begin
  inherited Create(THashSize.hsHashSize128);
end;

{ THaval_5_128 }

function THaval_5_128.Clone(): IHash;
var
  LHashInstance: THaval_5_128;
begin
  LHashInstance := THaval_5_128.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_5_128.Create;
begin
  inherited Create(THashSize.hsHashSize128);
end;

{ THaval_3_160 }

function THaval_3_160.Clone(): IHash;
var
  LHashInstance: THaval_3_160;
begin
  LHashInstance := THaval_3_160.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_3_160.Create;
begin
  inherited Create(THashSize.hsHashSize160);
end;

{ THaval_4_160 }

function THaval_4_160.Clone(): IHash;
var
  LHashInstance: THaval_4_160;
begin
  LHashInstance := THaval_4_160.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_4_160.Create;
begin
  inherited Create(THashSize.hsHashSize160);
end;

{ THaval_5_160 }

function THaval_5_160.Clone(): IHash;
var
  LHashInstance: THaval_5_160;
begin
  LHashInstance := THaval_5_160.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_5_160.Create;
begin
  inherited Create(THashSize.hsHashSize160);
end;

{ THaval_3_192 }

function THaval_3_192.Clone(): IHash;
var
  LHashInstance: THaval_3_192;
begin
  LHashInstance := THaval_3_192.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_3_192.Create;
begin
  inherited Create(THashSize.hsHashSize192);
end;

{ THaval_4_192 }

function THaval_4_192.Clone(): IHash;
var
  LHashInstance: THaval_4_192;
begin
  LHashInstance := THaval_4_192.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_4_192.Create;
begin
  inherited Create(THashSize.hsHashSize192);
end;

{ THaval_5_192 }

function THaval_5_192.Clone(): IHash;
var
  LHashInstance: THaval_5_192;
begin
  LHashInstance := THaval_5_192.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_5_192.Create;
begin
  inherited Create(THashSize.hsHashSize192);
end;

{ THaval_3_224 }

function THaval_3_224.Clone(): IHash;
var
  LHashInstance: THaval_3_224;
begin
  LHashInstance := THaval_3_224.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_3_224.Create;
begin
  inherited Create(THashSize.hsHashSize224);
end;

{ THaval_4_224 }

function THaval_4_224.Clone(): IHash;
var
  LHashInstance: THaval_4_224;
begin
  LHashInstance := THaval_4_224.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_4_224.Create;
begin
  inherited Create(THashSize.hsHashSize224);
end;

{ THaval_5_224 }

function THaval_5_224.Clone(): IHash;
var
  LHashInstance: THaval_5_224;
begin
  LHashInstance := THaval_5_224.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_5_224.Create;
begin
  inherited Create(THashSize.hsHashSize224);
end;

{ THaval_3_256 }

function THaval_3_256.Clone(): IHash;
var
  LHashInstance: THaval_3_256;
begin
  LHashInstance := THaval_3_256.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_3_256.Create;
begin
  inherited Create(THashSize.hsHashSize256);
end;

{ THaval_4_256 }

function THaval_4_256.Clone(): IHash;
var
  LHashInstance: THaval_4_256;
begin
  LHashInstance := THaval_4_256.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_4_256.Create;
begin
  inherited Create(THashSize.hsHashSize256);
end;

{ THaval_5_256 }

function THaval_5_256.Clone(): IHash;
var
  LHashInstance: THaval_5_256;
begin
  LHashInstance := THaval_5_256.Create();
  LHashInstance.FHash := System.Copy(FHash);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor THaval_5_256.Create;
begin
  inherited Create(THashSize.hsHashSize256);
end;

end.
