unit HlpBlake2B;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
  HlpBits,
  HlpHash,
  HlpHashResult,
  HlpIHashResult,
  HlpIBlake2BParams,
  HlpBlake2BParams,
  HlpIHash,
  HlpIHashInfo,
  HlpConverters,
  HlpArrayUtils,
  HlpHashLibTypes;

resourcestring
  SInvalidConfigLength = 'Config Length Must Be 8 Words';
  SConfigNil = 'Config Cannot Be nil';
  SInvalidXOFSize =
    'XOFSize in Bits must be Multiples of 8 and be Between %u and %u Bytes.';
  SOutputLengthInvalid = 'Output Length is above the Digest Length';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SMaximumOutputLengthExceeded = '"Maximum Length is 2^32 blocks of 64 bytes';
  SWritetoXofAfterReadError = '"%s" Write to Xof after Read not Allowed';

type
  TBlake2B = class(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private

{$REGION 'Consts'}
  const

{$IFNDEF USE_UNROLLED_VARIANT}
    NumberOfRounds = Int32(12);
{$ENDIF USE_UNROLLED_VARIANT}
    BlockSizeInBytes = Int32(128);

    IV0 = UInt64($6A09E667F3BCC908);
    IV1 = UInt64($BB67AE8584CAA73B);
    IV2 = UInt64($3C6EF372FE94F82B);
    IV3 = UInt64($A54FF53A5F1D36F1);
    IV4 = UInt64($510E527FADE682D1);
    IV5 = UInt64($9B05688C2B3E6C1F);
    IV6 = UInt64($1F83D9ABFB41BD6B);
    IV7 = UInt64($5BE0CD19137E2179);

{$IFNDEF USE_UNROLLED_VARIANT}
    Sigma: array [0 .. ((NumberOfRounds * 16) - 1)] of Int32 = (0, 1, 2, 3, 4,
      5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10, 4, 8, 9, 15, 13, 6, 1, 12,
      0, 2, 11, 7, 5, 3, 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
      7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8, 9, 0, 5, 7, 2, 4,
      10, 15, 14, 1, 11, 12, 6, 8, 3, 13, 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7,
      5, 15, 14, 1, 9, 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11, 13,
      11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10, 6, 15, 14, 9, 11, 3, 0,
      8, 12, 2, 13, 7, 1, 4, 10, 5, 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3,
      12, 13, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 14, 10,
      4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3);
{$ENDIF USE_UNROLLED_VARIANT}
{$ENDREGION}

  var
    FTreeConfig: IBlake2BTreeConfig;
    FConfig: IBlake2BConfig;
    FDoTransformKeyBlock: Boolean;

    procedure Blake2BIncrementCounter(AIncrementCount: UInt64); inline;

{$IFNDEF USE_UNROLLED_VARIANT}
    procedure G(AStateIdx0, AStateIdx1, AStateIdx2, AStateIdx3, ARound,
      AMixIdx: Int32); inline;
{$ENDIF USE_UNROLLED_VARIANT}
    procedure MixScalar();
    procedure Compress(ABlock: PByte; AStart: Int32); inline;

  strict protected
  var
    FM: array [0 .. 15] of UInt64;
    FState: THashLibUInt64Array;
    FBuffer: THashLibByteArray;
{$IFNDEF USE_UNROLLED_VARIANT}
    FV: array [0 .. 15] of UInt64;
{$ENDIF USE_UNROLLED_VARIANT}
    FFilledBufferCount: Int32;
    FCounter0, FCounter1, FFinalizationFlag0, FFinalizationFlag1: UInt64;

    procedure Finish();
    function GetName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const AConfig: IBlake2BConfig); overload;
    constructor Create(const AConfig: IBlake2BConfig;
      const ATreeConfig: IBlake2BTreeConfig;
      ADoTransformKeyBlock: Boolean = True); overload;
    procedure Initialize; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal: IHashResult; override;
    function CloneInternal(): TBlake2B;
    function Clone(): IHash; override;

  end;

type
  /// <summary>
  /// <b>TBlake2XBConfig</b> is used to configure hash function parameters and
  /// keying.
  /// </summary>
  TBlake2XBConfig = record
  private
  var
    FBlake2BConfig: IBlake2BConfig; // blake2b config object
    FBlake2BTreeConfig: IBlake2BTreeConfig; // blake2b tree config object

    function GetBlake2BConfig(): IBlake2BConfig; inline;
    procedure SetBlake2BConfig(const AValue: IBlake2BConfig); inline;
    function GetBlake2BTreeConfig(): IBlake2BTreeConfig; inline;
    procedure SetBlake2BTreeConfig(const AValue: IBlake2BTreeConfig); inline;
  public
  var

    constructor Create(ABlake2BConfig: IBlake2BConfig;
      ABlake2BTreeConfig: IBlake2BTreeConfig);

    function Clone(): TBlake2XBConfig;

    property Blake2BConfig: IBlake2BConfig read GetBlake2BConfig
      write SetBlake2BConfig;

    property Blake2BTreeConfig: IBlake2BTreeConfig read GetBlake2BTreeConfig
      write SetBlake2BTreeConfig;
  end;

type
  TBlake2XB = class sealed(TBlake2B, IXOF)
  strict private
  const
    Blake2BHashSize = Int32(64);

  const
    // Magic number to indicate an unknown length of digest
    UnknownDigestLengthInBytes = UInt32((UInt64(1) shl 32) - 1);
    // 4294967295 bytes
    MaxNumberBlocks = UInt64(1) shl 32;
    // 2^32 blocks of 64 bytes (256GiB)
    // the maximum size in bytes the digest can produce when the length is unknown
    UnknownMaxDigestLengthInBytes = UInt64(MaxNumberBlocks *
      UInt64(Blake2BHashSize));

  var
    FXOFSizeInBits: UInt64;

    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;

    function NodeOffsetWithXOFDigestLength(AXOFSizeInBytes: UInt64)
      : UInt64; inline;

    function ComputeStepLength(): Int32; inline;

    function GetResult(): THashLibByteArray;

    constructor CreateInternal(const AConfig: IBlake2BConfig;
      const ATreeConfig: IBlake2BTreeConfig);

  strict protected
  var
    FBlake2XBConfig: TBlake2XBConfig;
    FDigestPosition: UInt64;
    FRootConfig, FOutputConfig: TBlake2XBConfig;
    FRootHashDigest, FBlake2XBBuffer: THashLibByteArray;
    FFinalized: Boolean;

    function GetName: String; override;
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;

  public

    constructor Create(const ABlake2XBConfig: TBlake2XBConfig);
    procedure Initialize(); override;
    function Clone(): IHash; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal(): IHashResult; override;

    procedure DoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);

  end;

type
  TBlake2BMACNotBuildInAdapter = class sealed(THash, IBlake2BMAC,
    IBlake2BMACNotBuildIn, ICrypto, ICryptoNotBuildIn)

  strict private
  var
    FHash: IHash;
    FKey: THashLibByteArray;

    constructor Create(const ABlake2BKey, ASalt, APersonalisation
      : THashLibByteArray; AOutputLengthInBits: Int32); overload;
    constructor Create(const AHash: IHash;
      const ABlake2BKey: THashLibByteArray); overload;

  strict protected

    function GetName: String; override;

    function GetKey(): THashLibByteArray;
    procedure SetKey(const AValue: THashLibByteArray);

  public

    destructor Destroy; override;

    procedure Clear();

    procedure Initialize(); override;
    function TransformFinal(): IHashResult; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function Clone(): IHash; override;
    property Key: THashLibByteArray read GetKey write SetKey;
    property Name: String read GetName;

    class function CreateBlake2BMAC(const ABlake2BKey, ASalt, APersonalisation
      : THashLibByteArray; AOutputLengthInBits: Int32): IBlake2BMAC; static;

  end;

implementation

{ TBlake2B }

constructor TBlake2B.Create();
begin
  Create(TBlake2BConfig.Create() as IBlake2BConfig);
end;

procedure TBlake2B.Blake2BIncrementCounter(AIncrementCount: UInt64);
begin
  FCounter0 := FCounter0 + AIncrementCount;
  System.Inc(FCounter1, Ord(FCounter0 < AIncrementCount));
end;

{$IFNDEF USE_UNROLLED_VARIANT}

procedure TBlake2B.G(AStateIdx0, AStateIdx1, AStateIdx2, AStateIdx3, ARound,
  AMixIdx: Int32);
var
  LSigmaBase, LSigmaIdx0, LSigmaIdx1: Int32;
begin
  LSigmaBase := (ARound shl 4) + AMixIdx;
  LSigmaIdx0 := Sigma[LSigmaBase];
  LSigmaIdx1 := Sigma[LSigmaBase + 1];

  FV[AStateIdx0] := FV[AStateIdx0] + (FV[AStateIdx1] + FM[LSigmaIdx0]);
  FV[AStateIdx3] := TBits.RotateRight64(FV[AStateIdx3] xor FV[AStateIdx0], 32);
  FV[AStateIdx2] := FV[AStateIdx2] + FV[AStateIdx3];
  FV[AStateIdx1] := TBits.RotateRight64(FV[AStateIdx1] xor FV[AStateIdx2], 24);
  FV[AStateIdx0] := FV[AStateIdx0] + (FV[AStateIdx1] + FM[LSigmaIdx1]);
  FV[AStateIdx3] := TBits.RotateRight64(FV[AStateIdx3] xor FV[AStateIdx0], 16);
  FV[AStateIdx2] := FV[AStateIdx2] + FV[AStateIdx3];
  FV[AStateIdx1] := TBits.RotateRight64(FV[AStateIdx1] xor FV[AStateIdx2], 63);
end;

{$ENDIF USE_UNROLLED_VARIANT}

function TBlake2B.CloneInternal(): TBlake2B;
var
  LTreeConfig: IBlake2BTreeConfig;
begin
  LTreeConfig := nil;
  if FTreeConfig <> nil then
  begin
    LTreeConfig := FTreeConfig.Clone();
  end;
  Result := TBlake2B.Create(FConfig.Clone(), LTreeConfig, FDoTransformKeyBlock);
  System.Move(FM, Result.FM, System.SizeOf(FM));
  Result.FState := System.Copy(FState);
  Result.FBuffer := System.Copy(FBuffer);
{$IFNDEF USE_UNROLLED_VARIANT}
  System.Move(FV, Result.FV, System.SizeOf(FV));
{$ENDIF USE_UNROLLED_VARIANT}
  Result.FFilledBufferCount := FFilledBufferCount;
  Result.FCounter0 := FCounter0;
  Result.FCounter1 := FCounter1;
  Result.FFinalizationFlag0 := FFinalizationFlag0;
  Result.FFinalizationFlag1 := FFinalizationFlag1;
  Result.BufferSize := BufferSize;
end;

function TBlake2B.Clone(): IHash;
begin
  Result := CloneInternal();
end;

procedure TBlake2B.MixScalar;
var
{$IFDEF USE_UNROLLED_VARIANT}
  LBlock0, LBlock1, LBlock2, LBlock3, LBlock4, LBlock5, LBlock6, LBlock7, LBlock8, LBlock9, LBlock10, LBlock11, LBlock12, LBlock13, LBlock14, LBlock15, LWorking0, LWorking1,
    LWorking2, LWorking3, LWorking4, LWorking5, LWorking6, LWorking7, LWorking8, LWorking9, LWorking10, LWorking11, LWorking12, LWorking13, LWorking14, LWorking15: UInt64;

{$ELSE}
  LWordIdx, LRound: Int32;

{$ENDIF USE_UNROLLED_VARIANT}
begin
{$IFDEF USE_UNROLLED_VARIANT}
  LBlock0 := FM[0];
  LBlock1 := FM[1];
  LBlock2 := FM[2];
  LBlock3 := FM[3];
  LBlock4 := FM[4];
  LBlock5 := FM[5];
  LBlock6 := FM[6];
  LBlock7 := FM[7];
  LBlock8 := FM[8];
  LBlock9 := FM[9];
  LBlock10 := FM[10];
  LBlock11 := FM[11];
  LBlock12 := FM[12];
  LBlock13 := FM[13];
  LBlock14 := FM[14];
  LBlock15 := FM[15];

  LWorking0 := FState[0];
  LWorking1 := FState[1];
  LWorking2 := FState[2];
  LWorking3 := FState[3];
  LWorking4 := FState[4];
  LWorking5 := FState[5];
  LWorking6 := FState[6];
  LWorking7 := FState[7];

  LWorking8 := IV0;
  LWorking9 := IV1;
  LWorking10 := IV2;
  LWorking11 := IV3;
  LWorking12 := IV4 xor FCounter0;
  LWorking13 := IV5 xor FCounter1;
  LWorking14 := IV6 xor FFinalizationFlag0;
  LWorking15 := IV7 xor FFinalizationFlag1;

  // Rounds

  // ##### Round(0)
  // G(0, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock0;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock1;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(0, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock2;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock3;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(0, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock4;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock5;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(0, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock6;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(0, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock8;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock9;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(0, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock10;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock11;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(0, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock12;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock13;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(0, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock14;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock15;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(1)
  // G(1, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock14;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock10;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(1, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock4;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock8;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(1, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock9;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock15;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(1, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock13;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock6;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(1, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock1;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock12;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(1, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock0;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock2;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(1, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock11;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(1, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock5;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock3;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(2)
  // G(2, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock11;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock8;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(2, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock12;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock0;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(2, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock5;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock2;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(2, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock15;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock13;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(2, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock10;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock14;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(2, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock3;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(2, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock1;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(2, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock9;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(3)
  // G(3, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock7;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock9;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(3, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock3;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock1;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(3, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock13;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock12;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(3, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock11;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock14;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(3, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock2;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock6;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(3, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock5;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock10;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(3, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock4;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock0;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(3, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock15;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock8;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(4)
  // G(4, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock9;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock0;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(4, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock7;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(4, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock2;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock4;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(4, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock10;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock15;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(4, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock14;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock1;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(4, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock11;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock12;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(4, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock6;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock8;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(4, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock3;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock13;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(5)
  // G(5, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock2;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock12;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(5, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock6;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock10;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(5, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock0;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock11;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(5, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock8;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock3;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(5, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock4;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock13;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(5, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock7;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock5;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(5, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock15;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock14;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(5, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock1;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock9;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(6)
  // G(6, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock12;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock5;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(6, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock1;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock15;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(6, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock14;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock13;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(6, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock4;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock10;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(6, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock0;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock7;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(6, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock3;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(6, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock9;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock2;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(6, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock8;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock11;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(7)
  // G(7, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock13;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock11;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(7, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock7;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock14;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(7, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock12;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock1;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(7, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock3;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock9;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(7, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock0;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(7, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock15;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock4;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(7, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock8;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock6;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(7, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock2;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock10;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(8)
  // G(8, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock6;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock15;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(8, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock14;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock9;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(8, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock11;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock3;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(8, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock0;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock8;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(8, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock12;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock2;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(8, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock13;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock7;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(8, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock1;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock4;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(8, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock10;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock5;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(9)
  // G(9, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock10;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock2;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(9, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock8;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock4;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(9, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock7;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(9, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock1;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock5;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(9, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock15;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock11;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(9, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock9;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock14;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(9, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock3;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock12;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(9, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock13;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock0;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(10)
  // G(10, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock0;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock1;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(10, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock2;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock3;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(10, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock4;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock5;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(10, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock6;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(10, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock8;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock9;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(10, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock10;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock11;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(10, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock12;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock13;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(10, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock14;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock15;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // ##### Round(11)
  // G(11, 0, LWorking0, LWorking4, LWorking8, LWorking12)
  LWorking0 := LWorking0 + LWorking4 + LBlock14;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking0 := LWorking0 + LWorking4 + LBlock10;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // G(11, 1, LWorking1, LWorking5, LWorking9, LWorking13)
  LWorking1 := LWorking1 + LWorking5 + LBlock4;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking1 := LWorking1 + LWorking5 + LBlock8;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(11, 2, LWorking2, LWorking6, LWorking10, LWorking14)
  LWorking2 := LWorking2 + LWorking6 + LBlock9;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking2 := LWorking2 + LWorking6 + LBlock15;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(11, 3, LWorking3, LWorking7, LWorking11, LWorking15)
  LWorking3 := LWorking3 + LWorking7 + LBlock13;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking3 := LWorking3 + LWorking7 + LBlock6;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(11, 4, LWorking0, LWorking5, LWorking10, LWorking15)
  LWorking0 := LWorking0 + LWorking5 + LBlock1;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 32);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 24);
  LWorking0 := LWorking0 + LWorking5 + LBlock12;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight64(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight64(LWorking5, 63);

  // G(11, 5, LWorking1, LWorking6, LWorking11, LWorking12)
  LWorking1 := LWorking1 + LWorking6 + LBlock0;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 32);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 24);
  LWorking1 := LWorking1 + LWorking6 + LBlock2;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight64(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight64(LWorking6, 63);

  // G(11, 6, LWorking2, LWorking7, LWorking8, LWorking13)
  LWorking2 := LWorking2 + LWorking7 + LBlock11;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 32);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 24);
  LWorking2 := LWorking2 + LWorking7 + LBlock7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight64(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight64(LWorking7, 63);

  // G(11, 7, LWorking3, LWorking4, LWorking9, LWorking14)
  LWorking3 := LWorking3 + LWorking4 + LBlock5;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 32);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 24);
  LWorking3 := LWorking3 + LWorking4 + LBlock3;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight64(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight64(LWorking4, 63);

  // Finalization
  FState[0] := FState[0] xor (LWorking0 xor LWorking8);
  FState[1] := FState[1] xor (LWorking1 xor LWorking9);
  FState[2] := FState[2] xor (LWorking2 xor LWorking10);
  FState[3] := FState[3] xor (LWorking3 xor LWorking11);
  FState[4] := FState[4] xor (LWorking4 xor LWorking12);
  FState[5] := FState[5] xor (LWorking5 xor LWorking13);
  FState[6] := FState[6] xor (LWorking6 xor LWorking14);
  FState[7] := FState[7] xor (LWorking7 xor LWorking15);

{$ELSE}
  FV[0] := FState[0];
  FV[1] := FState[1];
  FV[2] := FState[2];
  FV[3] := FState[3];
  FV[4] := FState[4];
  FV[5] := FState[5];
  FV[6] := FState[6];
  FV[7] := FState[7];

  FV[8] := IV0;
  FV[9] := IV1;
  FV[10] := IV2;
  FV[11] := IV3;
  FV[12] := IV4 xor FCounter0;
  FV[13] := IV5 xor FCounter1;

  FV[14] := IV6 xor FFinalizationFlag0;

  FV[15] := IV7 xor FFinalizationFlag1;

  for LRound := 0 to System.Pred(NumberOfRounds) do

  begin
    G(0, 4, 8, 12, LRound, 0);
    G(1, 5, 9, 13, LRound, 2);
    G(2, 6, 10, 14, LRound, 4);
    G(3, 7, 11, 15, LRound, 6);
    G(3, 4, 9, 14, LRound, 14);
    G(2, 7, 8, 13, LRound, 12);
    G(0, 5, 10, 15, LRound, 8);
    G(1, 6, 11, 12, LRound, 10);
  end;

  for LWordIdx := 0 to 7 do
  begin
    FState[LWordIdx] := FState[LWordIdx] xor (FV[LWordIdx] xor FV[LWordIdx + 8]);
  end;

{$ENDIF USE_UNROLLED_VARIANT}
end;

procedure TBlake2B.Compress(ABlock: PByte; AStart: Int32);
begin
  TConverters.le64_copy(ABlock, AStart, @(FM[0]), 0, BlockSize);
  MixScalar();
end;

constructor TBlake2B.Create(const AConfig: IBlake2BConfig);
begin
  Create(AConfig, nil);
end;

constructor TBlake2B.Create(const AConfig: IBlake2BConfig;
  const ATreeConfig: IBlake2BTreeConfig; ADoTransformKeyBlock: Boolean);
begin
  FConfig := AConfig;
  FTreeConfig := ATreeConfig;
  FDoTransformKeyBlock := ADoTransformKeyBlock;

  if (FConfig = nil) then
  begin
    FConfig := TBlake2BConfig.DefaultConfig;
  end;

  System.SetLength(FState, 8);

  System.SetLength(FBuffer, BlockSizeInBytes);

  inherited Create(FConfig.HashSize, BlockSizeInBytes);
end;

procedure TBlake2B.Finish;
var
  LCount: Int32;
  LPtrBuffer: PByte;
begin
  // Last compression
  Blake2BIncrementCounter(UInt64(FFilledBufferCount));

  FFinalizationFlag0 := System.High(UInt64);

  if (FTreeConfig <> nil) and (FTreeConfig.IsLastNode) then
  begin
    FFinalizationFlag1 := System.High(UInt64);
  end;

  LCount := System.Length(FBuffer) - FFilledBufferCount;

  if LCount > 0 then
  begin
    TArrayUtils.Fill(FBuffer, FFilledBufferCount,
      LCount + FFilledBufferCount, Byte(0));
  end;
  LPtrBuffer := PByte(FBuffer);
  Compress(LPtrBuffer, 0);
end;

procedure TBlake2B.Initialize;
var
  LIdx: Int32;
  LBlock: THashLibByteArray;
  LRawConfig: THashLibUInt64Array;
begin
  LRawConfig := TBlake2BIvBuilder.ConfigB(FConfig, FTreeConfig);
  LBlock := nil;

  if FDoTransformKeyBlock then
  begin
    if ((FConfig.Key <> nil) and (System.Length(FConfig.Key) <> 0)) then
    begin
      LBlock := System.Copy(FConfig.Key, System.Low(FConfig.Key),
        System.Length(FConfig.Key));
      System.SetLength(LBlock, BlockSizeInBytes);
    end;
  end;

  if (LRawConfig = nil) then
  begin
    raise EArgumentNilHashLibException.CreateRes(@SConfigNil);
  end;
  if (System.Length(LRawConfig) <> 8) then
  begin
    raise EArgumentHashLibException.CreateRes(@SInvalidConfigLength);
  end;

  FState[0] := IV0;
  FState[1] := IV1;
  FState[2] := IV2;
  FState[3] := IV3;
  FState[4] := IV4;
  FState[5] := IV5;
  FState[6] := IV6;
  FState[7] := IV7;

  FCounter0 := 0;
  FCounter1 := 0;
  FFinalizationFlag0 := 0;
  FFinalizationFlag1 := 0;

  FFilledBufferCount := 0;

  TArrayUtils.ZeroFill(FBuffer);

  System.FillChar(FM, System.SizeOf(FM), UInt64(0));

{$IFNDEF USE_UNROLLED_VARIANT}
  System.FillChar(FV, System.SizeOf(FV), UInt64(0));
{$ENDIF USE_UNROLLED_VARIANT}
  for LIdx := 0 to 7 do
  begin
    FState[LIdx] := FState[LIdx] xor LRawConfig[LIdx];
  end;

  if FDoTransformKeyBlock then
  begin
    if (LBlock <> nil) then
    begin
      TransformBytes(LBlock, 0, System.Length(LBlock));
      TArrayUtils.ZeroFill(LBlock); // burn key from memory
    end;
  end;
end;

procedure TBlake2B.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
var
  LOffset, LBufferRemaining: Int32;
  LPtrData, LPtrBuffer: PByte;
begin
  LOffset := AIndex;
  LBufferRemaining := BlockSizeInBytes - FFilledBufferCount;

  if ((FFilledBufferCount > 0) and (ADataLength > LBufferRemaining)) then
  begin
    if LBufferRemaining > 0 then
    begin
      System.Move(AData[LOffset], FBuffer[FFilledBufferCount],
        LBufferRemaining);
    end;
    Blake2BIncrementCounter(UInt64(BlockSizeInBytes));
    LPtrBuffer := PByte(FBuffer);
    Compress(LPtrBuffer, 0);
    LOffset := LOffset + LBufferRemaining;
    ADataLength := ADataLength - LBufferRemaining;
    FFilledBufferCount := 0;
  end;

  LPtrData := PByte(AData);

  while (ADataLength > BlockSizeInBytes) do
  begin
    Blake2BIncrementCounter(UInt64(BlockSizeInBytes));
    Compress(LPtrData, LOffset);
    LOffset := LOffset + BlockSizeInBytes;
    ADataLength := ADataLength - BlockSizeInBytes;
  end;

  if (ADataLength > 0) then
  begin
    System.Move(AData[LOffset], FBuffer[FFilledBufferCount], ADataLength);
    FFilledBufferCount := FFilledBufferCount + ADataLength;
  end;
end;

function TBlake2B.TransformFinal: IHashResult;
var
  LBuffer: THashLibByteArray;
begin
  Finish();
  System.SetLength(LBuffer, HashSize);
  TConverters.le64_copy(PUInt64(FState), 0, PByte(LBuffer), 0,
    System.Length(LBuffer));
  Result := THashResult.Create(LBuffer);
  Initialize();
end;

function TBlake2B.GetName: String;
begin
  Result := Format('%s_%u', [Self.ClassName, Self.HashSize * 8]);
end;

{ TBlake2XBConfig }

function TBlake2XBConfig.GetBlake2BConfig: IBlake2BConfig;
begin
  Result := FBlake2BConfig;
end;

function TBlake2XBConfig.GetBlake2BTreeConfig: IBlake2BTreeConfig;
begin
  Result := FBlake2BTreeConfig;
end;

procedure TBlake2XBConfig.SetBlake2BConfig(const AValue: IBlake2BConfig);
begin
  FBlake2BConfig := AValue;
end;

procedure TBlake2XBConfig.SetBlake2BTreeConfig(const AValue
  : IBlake2BTreeConfig);
begin
  FBlake2BTreeConfig := AValue;
end;

function TBlake2XBConfig.Clone(): TBlake2XBConfig;
begin
  Result := Default(TBlake2XBConfig);
  if FBlake2BConfig <> nil then
  begin
    Result.Blake2BConfig := FBlake2BConfig.Clone();
  end;

  if FBlake2BTreeConfig <> nil then
  begin
    Result.Blake2BTreeConfig := FBlake2BTreeConfig.Clone();
  end;
end;

constructor TBlake2XBConfig.Create(ABlake2BConfig: IBlake2BConfig;
  ABlake2BTreeConfig: IBlake2BTreeConfig);
begin
  FBlake2BConfig := ABlake2BConfig;
  FBlake2BTreeConfig := ABlake2BTreeConfig;
end;

{ TBlake2XB }

function TBlake2XB.GetXOFSizeInBits: UInt64;
begin
  Result := FXOFSizeInBits;
end;

procedure TBlake2XB.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

function TBlake2XB.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := AXofSizeInBits shr 3;
  if ((AXofSizeInBits and $7) <> 0) or (LXofSizeInBytes < 1) or
    (LXofSizeInBytes > UInt64(UnknownDigestLengthInBytes)) then
  begin
    raise EArgumentInvalidHashLibException.CreateResFmt(@SInvalidXOFSize,
      [1, UInt64(UnknownDigestLengthInBytes)]);
  end;
  FXOFSizeInBits := AXofSizeInBits;
  Result := Self;
end;

function TBlake2XB.NodeOffsetWithXOFDigestLength(AXOFSizeInBytes
  : UInt64): UInt64;
begin
  Result := (UInt64(AXOFSizeInBytes) shl 32);
end;

function TBlake2XB.ComputeStepLength: Int32;
var
  LXofSizeInBytes, LDiff: UInt64;
begin
  LXofSizeInBytes := XOFSizeInBits shr 3;
  LDiff := LXofSizeInBytes - FDigestPosition;
  if (LXofSizeInBytes = UInt64(UnknownDigestLengthInBytes)) then
  begin
    Result := Blake2BHashSize;
    Exit;
  end;

  // Math.Min
  if UInt64(Blake2BHashSize) < LDiff then
  begin
    Result := UInt64(Blake2BHashSize)
  end
  else
  begin
    Result := LDiff;
  end;
end;

function TBlake2XB.GetName: String;
begin
  Result := Self.ClassName;
end;

function TBlake2XB.Clone(): IHash;
var
  LHashInstance: TBlake2XB;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := (TBlake2XB.CreateInternal(FRootConfig.Blake2BConfig,
    FRootConfig.Blake2BTreeConfig) as IXOF);
  LXof.XOFSizeInBits := (Self as IXOF).XOFSizeInBits;

  // Blake2XB Cloning
  LHashInstance := LXof as TBlake2XB;
  LHashInstance.FBlake2XBConfig := FBlake2XBConfig.Clone();
  LHashInstance.FDigestPosition := FDigestPosition;
  LHashInstance.FRootConfig := FRootConfig.Clone();
  LHashInstance.FOutputConfig := FOutputConfig.Clone();
  LHashInstance.FRootHashDigest := System.Copy(FRootHashDigest);
  LHashInstance.FBlake2XBBuffer := System.Copy(FBlake2XBBuffer);
  LHashInstance.FFinalized := FFinalized;

  // Internal Blake2B Cloning
  System.Move(FM, LHashInstance.FM, System.SizeOf(FM));
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := System.Copy(FBuffer);
{$IFNDEF USE_UNROLLED_VARIANT}
  System.Move(FV, LHashInstance.FV, System.SizeOf(FV));
{$ENDIF USE_UNROLLED_VARIANT}
  LHashInstance.FFilledBufferCount := FFilledBufferCount;
  LHashInstance.FCounter0 := FCounter0;
  LHashInstance.FCounter1 := FCounter1;
  LHashInstance.FFinalizationFlag0 := FFinalizationFlag0;
  LHashInstance.FFinalizationFlag1 := FFinalizationFlag1;

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TBlake2XB.CreateInternal(const AConfig: IBlake2BConfig;
  const ATreeConfig: IBlake2BTreeConfig);
begin
  inherited Create(AConfig, ATreeConfig);
end;

constructor TBlake2XB.Create(const ABlake2XBConfig: TBlake2XBConfig);
begin
  FBlake2XBConfig := ABlake2XBConfig;
  // Create root hash config.
  FRootConfig := Default(TBlake2XBConfig);

  FRootConfig.Blake2BConfig := FBlake2XBConfig.Blake2BConfig;

  if FRootConfig.Blake2BConfig = nil then
  begin
    FRootConfig.Blake2BConfig := TBlake2BConfig.Create();
  end
  else
  begin
    FRootConfig.Blake2BConfig.Key := FBlake2XBConfig.Blake2BConfig.Key;
    FRootConfig.Blake2BConfig.Salt := FBlake2XBConfig.Blake2BConfig.Salt;
    FRootConfig.Blake2BConfig.Personalisation :=
      FBlake2XBConfig.Blake2BConfig.Personalisation;
  end;

  FRootConfig.Blake2BTreeConfig := FBlake2XBConfig.Blake2BTreeConfig;

  if FRootConfig.Blake2BTreeConfig = nil then
  begin
    FRootConfig.Blake2BTreeConfig := TBlake2BTreeConfig.Create();
    FRootConfig.Blake2BTreeConfig.FanOut := 1;
    FRootConfig.Blake2BTreeConfig.MaxDepth := 1;

    FRootConfig.Blake2BTreeConfig.LeafSize := 0;
    FRootConfig.Blake2BTreeConfig.NodeOffset := 0;
    FRootConfig.Blake2BTreeConfig.NodeDepth := 0;
    FRootConfig.Blake2BTreeConfig.InnerHashSize := 0;
    FRootConfig.Blake2BTreeConfig.IsLastNode := False;
  end;

  // Create initial config for output hashes.
  FOutputConfig := Default(TBlake2XBConfig);

  FOutputConfig.Blake2BConfig := TBlake2BConfig.Create();
  FOutputConfig.Blake2BConfig.Salt := FRootConfig.Blake2BConfig.Salt;
  FOutputConfig.Blake2BConfig.Personalisation :=
    FRootConfig.Blake2BConfig.Personalisation;

  FOutputConfig.Blake2BTreeConfig := TBlake2BTreeConfig.Create();

  CreateInternal(FRootConfig.Blake2BConfig, FRootConfig.Blake2BTreeConfig);

  System.SetLength(FBlake2XBBuffer, Blake2BHashSize);
end;

procedure TBlake2XB.Initialize;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := XOFSizeInBits shr 3;

  FRootConfig.Blake2BTreeConfig.NodeOffset := NodeOffsetWithXOFDigestLength
    (LXofSizeInBytes);

  FOutputConfig.Blake2BTreeConfig.NodeOffset := NodeOffsetWithXOFDigestLength
    (LXofSizeInBytes);

  FRootHashDigest := nil;
  FDigestPosition := 0;
  FFinalized := False;
  TArrayUtils.ZeroFill(FBlake2XBBuffer);
  inherited Initialize();
end;

procedure TBlake2XB.DoOutput(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
var
  LDiff, LCount, LBlockOffset: UInt64;
  LHash: IHash;
begin

  if (UInt64(System.Length(ADestination)) - ADestinationOffset) < AOutputLength
  then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes(@SOutputBufferTooShort);
  end;

  if ((XOFSizeInBits shr 3) <> UnknownDigestLengthInBytes) then
  begin
    if ((FDigestPosition + AOutputLength) > (XOFSizeInBits shr 3)) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateRes
        (@SOutputLengthInvalid);
    end;
  end
  else if (FDigestPosition = UnknownMaxDigestLengthInBytes) then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes
      (@SMaximumOutputLengthExceeded);
  end;

  if not FFinalized then
  begin
    Finish();
    FFinalized := True;
  end;

  if (FRootHashDigest = nil) then
  begin
    // Get root digest
    System.SetLength(FRootHashDigest, Blake2BHashSize);
    TConverters.le64_copy(PUInt64(FState), 0, PByte(FRootHashDigest), 0,
      System.Length(FRootHashDigest));
  end;

  while AOutputLength > 0 do
  begin
    if (FDigestPosition and (Blake2BHashSize - 1)) = 0 then
    begin
      FOutputConfig.Blake2BConfig.HashSize := ComputeStepLength();
      FOutputConfig.Blake2BTreeConfig.InnerHashSize := Blake2BHashSize;

      LHash := TBlake2B.Create(FOutputConfig.Blake2BConfig, FOutputConfig.Blake2BTreeConfig);
      FBlake2XBBuffer := LHash.ComputeBytes(FRootHashDigest).GetBytes();
      FOutputConfig.Blake2BTreeConfig.NodeOffset :=
        FOutputConfig.Blake2BTreeConfig.NodeOffset + 1;
    end;

    LBlockOffset := FDigestPosition and (Blake2BHashSize - 1);

    LDiff := UInt64(System.Length(FBlake2XBBuffer)) - LBlockOffset;

    // Math.Min
    if AOutputLength < LDiff then
    begin
      LCount := AOutputLength
    end
    else
    begin
      LCount := LDiff;
    end;

    System.Move(FBlake2XBBuffer[LBlockOffset],
      ADestination[ADestinationOffset], LCount);

    System.Dec(AOutputLength, LCount);
    System.Inc(ADestinationOffset, LCount);
    System.Inc(FDigestPosition, LCount);
  end;
end;

function TBlake2XB.GetResult: THashLibByteArray;
var
  LXofSizeInBytes: UInt64;
begin
  System.SetLength(Result, XOFSizeInBits shr 3);

  LXofSizeInBytes := XOFSizeInBits shr 3;

  System.SetLength(Result, LXofSizeInBytes);

  DoOutput(Result, 0, LXofSizeInBytes);
end;

procedure TBlake2XB.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
begin
  if FFinalized then
  begin
    raise EInvalidOperationHashLibException.CreateResFmt
      (@SWritetoXofAfterReadError, [Name]);
  end;
  inherited TransformBytes(AData, AIndex, ADataLength);
end;

function TBlake2XB.TransformFinal: IHashResult;
var
  LBuffer: THashLibByteArray;
begin
  LBuffer := GetResult();
{$IFDEF DEBUG}
  System.Assert(UInt64(System.Length(LBuffer)) = (XOFSizeInBits shr 3));
{$ENDIF DEBUG}
  Initialize();
  Result := THashResult.Create(LBuffer);
end;

{ TBlake2BMACNotBuildInAdapter }

procedure TBlake2BMACNotBuildInAdapter.Clear();
begin
  TArrayUtils.ZeroFill(FKey);
end;

function TBlake2BMACNotBuildInAdapter.Clone(): IHash;
var
  LHashInstance: TBlake2BMACNotBuildInAdapter;
begin
  LHashInstance := TBlake2BMACNotBuildInAdapter.Create(FHash.Clone(), FKey);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TBlake2BMACNotBuildInAdapter.Create(const ABlake2BKey, ASalt,
  APersonalisation: THashLibByteArray; AOutputLengthInBits: Int32);
var
  LConfig: IBlake2BConfig;
begin
  LConfig := TBlake2BConfig.Create(AOutputLengthInBits shr 3);
  LConfig.Key := ABlake2BKey;
  LConfig.Salt := ASalt;
  LConfig.Personalisation := APersonalisation;
  Create(TBlake2B.Create(LConfig, nil) as IHash, ABlake2BKey);
end;

constructor TBlake2BMACNotBuildInAdapter.Create(const AHash: IHash;
  const ABlake2BKey: THashLibByteArray);
begin
  inherited Create(AHash.HashSize, AHash.BlockSize);
  SetKey(ABlake2BKey);
  FHash := AHash;
end;

class function TBlake2BMACNotBuildInAdapter.CreateBlake2BMAC(const ABlake2BKey,
  ASalt, APersonalisation: THashLibByteArray; AOutputLengthInBits: Int32)
  : IBlake2BMAC;
begin
  Result := TBlake2BMACNotBuildInAdapter.Create(ABlake2BKey, ASalt,
    APersonalisation, AOutputLengthInBits) as IBlake2BMAC;
end;

destructor TBlake2BMACNotBuildInAdapter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TBlake2BMACNotBuildInAdapter.GetKey: THashLibByteArray;
begin
  Result := System.Copy(FKey);
end;

function TBlake2BMACNotBuildInAdapter.GetName: String;
begin
  Result := Format('%s', ['TBlake2BMAC']);
end;

procedure TBlake2BMACNotBuildInAdapter.Initialize;
begin
  FHash.Initialize;
end;

procedure TBlake2BMACNotBuildInAdapter.SetKey(const AValue: THashLibByteArray);
begin
  if (AValue = nil) then
  begin
    FKey := nil;
  end
  else
  begin
    FKey := System.Copy(AValue);
  end;
end;

procedure TBlake2BMACNotBuildInAdapter.TransformBytes
  (const AData: THashLibByteArray; AIndex, ALength: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF}
  FHash.TransformBytes(AData, AIndex, ALength);
end;

function TBlake2BMACNotBuildInAdapter.TransformFinal: IHashResult;
begin
  Result := FHash.TransformFinal();
end;

end.
