unit HlpBlake2S;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
  HlpBits,
  HlpHash,
  HlpHashResult,
  HlpIHashResult,
  HlpIBlake2SParams,
  HlpBlake2SParams,
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
  SMaximumOutputLengthExceeded = '"Maximum Length is 2^32 blocks of 32 bytes';
  SWritetoXofAfterReadError = '"%s" Write to Xof after Read not Allowed';

type
  TBlake2S = class(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private

{$REGION 'Consts'}
  const

{$IFNDEF USE_UNROLLED_VARIANT}
    NumberOfRounds = Int32(10);
{$ENDIF USE_UNROLLED_VARIANT}
    BlockSizeInBytes = Int32(64);

    IV0 = UInt32($66A09E667);
    IV1 = UInt32($BB67AE85);
    IV2 = UInt32($3C6EF372);
    IV3 = UInt32($A54FF53A);
    IV4 = UInt32($510E527F);
    IV5 = UInt32($9B05688C);
    IV6 = UInt32($1F83D9AB);
    IV7 = UInt32($5BE0CD19);

{$IFNDEF USE_UNROLLED_VARIANT}
    Sigma: array [0 .. 9, 0 .. 15] of Byte = ((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      11, 12, 13, 14, 15), (14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5,
      3), (11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
      (7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
      (9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
      (2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
      (12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
      (13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
      (6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
      (10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0));
{$ENDIF USE_UNROLLED_VARIANT}
{$ENDREGION}

  var
    FTreeConfig: IBlake2STreeConfig;
    FConfig: IBlake2SConfig;
    FDoTransformKeyBlock: Boolean;

    procedure Blake2SIncrementCounter(AIncrementCount: UInt32); inline;

{$IFNDEF USE_UNROLLED_VARIANT}
    procedure G(AStateIdx0, AStateIdx1, AStateIdx2, AStateIdx3, ARound,
      AMixIdx: Int32); inline;
{$ENDIF USE_UNROLLED_VARIANT}
    procedure MixScalar();
    procedure Compress(ABlock: PByte; AStart: Int32); inline;

  strict protected
  var
    FState: THashLibUInt32Array;
    FM: array [0 .. 15] of UInt32;
    FBuffer: THashLibByteArray;
{$IFNDEF USE_UNROLLED_VARIANT}
    FV: array [0 .. 15] of UInt32;
{$ENDIF USE_UNROLLED_VARIANT}
    FFilledBufferCount: Int32;
    FCounter0, FCounter1, FFinalizationFlag0, FFinalizationFlag1: UInt32;

    procedure Finish();
    function GetName: String; override;

  public
    constructor Create(); overload;
    constructor Create(const AConfig: IBlake2SConfig); overload;
    constructor Create(const AConfig: IBlake2SConfig;
      const ATreeConfig: IBlake2STreeConfig;
      ADoTransformKeyBlock: Boolean = True); overload;
    procedure Initialize; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal: IHashResult; override;
    function CloneInternal(): TBlake2S;
    function Clone(): IHash; override;

  end;

type
  /// <summary>
  /// <b>TBlake2XSConfig</b> is used to configure hash function parameters and
  /// keying.
  /// </summary>
  TBlake2XSConfig = record
  private
  var
    FBlake2SConfig: IBlake2SConfig; // blake2s config object
    FBlake2STreeConfig: IBlake2STreeConfig; // blake2s tree config object

    function GetBlake2SConfig(): IBlake2SConfig; inline;
    procedure SetBlake2SConfig(const AValue: IBlake2SConfig); inline;
    function GetBlake2STreeConfig(): IBlake2STreeConfig; inline;
    procedure SetBlake2STreeConfig(const AValue: IBlake2STreeConfig); inline;
  public
  var

    constructor Create(ABlake2SConfig: IBlake2SConfig;
      ABlake2STreeConfig: IBlake2STreeConfig);

    function Clone(): TBlake2XSConfig;

    property Blake2SConfig: IBlake2SConfig read GetBlake2SConfig
      write SetBlake2SConfig;

    property Blake2STreeConfig: IBlake2STreeConfig read GetBlake2STreeConfig
      write SetBlake2STreeConfig;
  end;

type
  TBlake2XS = class sealed(TBlake2S, IXOF)
  strict private
  const
    Blake2SHashSize = Int32(32);

  const
    // Magic number to indicate an unknown length of digest
    UnknownDigestLengthInBytes = UInt16((UInt32(1) shl 16) - 1); // 65535 bytes
    MaxNumberBlocks = UInt64(1) shl 32;
    // 2^32 blocks of 32 bytes (128GiB)
    // the maximum size in bytes the digest can produce when the length is unknown
    UnknownMaxDigestLengthInBytes = UInt64(MaxNumberBlocks *
      UInt64(Blake2SHashSize));

  var
    FXOFSizeInBits: UInt64;

    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;

    function NodeOffsetWithXOFDigestLength(AXOFSizeInBytes: UInt64)
      : UInt64; inline;

    function ComputeStepLength(): Int32; inline;

    function GetResult(): THashLibByteArray;

    constructor CreateInternal(const AConfig: IBlake2SConfig;
      const ATreeConfig: IBlake2STreeConfig);

  strict protected
  var
    FBlake2XSConfig: TBlake2XSConfig;
    FDigestPosition: UInt64;
    FRootConfig, FOutputConfig: TBlake2XSConfig;
    FRootHashDigest, FBlake2XSBuffer: THashLibByteArray;
    FFinalized: Boolean;

    function GetName: String; override;
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;
  public

    constructor Create(const ABlake2XSConfig: TBlake2XSConfig);
    procedure Initialize(); override;
    function Clone(): IHash; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal(): IHashResult; override;

    procedure DoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);

  end;

type
  TBlake2SMACNotBuildInAdapter = class sealed(THash, IBlake2SMAC,
    IBlake2SMACNotBuildIn, ICrypto, ICryptoNotBuildIn)

  strict private
  var
    FHash: IHash;
    FKey: THashLibByteArray;

    constructor Create(const ABlake2SKey, ASalt, APersonalisation
      : THashLibByteArray; AOutputLengthInBits: Int32); overload;
    constructor Create(const AHash: IHash;
      const ABlake2SKey: THashLibByteArray); overload;

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

    class function CreateBlake2SMAC(const ABlake2SKey, ASalt, APersonalisation
      : THashLibByteArray; AOutputLengthInBits: Int32): IBlake2SMAC; static;

  end;

implementation

{ TBlake2S }

constructor TBlake2S.Create();
begin
  Create(TBlake2SConfig.Create() as IBlake2SConfig);
end;

procedure TBlake2S.Blake2SIncrementCounter(AIncrementCount: UInt32);
begin
  FCounter0 := FCounter0 + AIncrementCount;
  System.Inc(FCounter1, Ord(FCounter0 < AIncrementCount));
end;

{$IFNDEF USE_UNROLLED_VARIANT}

procedure TBlake2S.G(AStateIdx0, AStateIdx1, AStateIdx2, AStateIdx3, ARound,
  AMixIdx: Int32);
begin
  FV[AStateIdx0] := FV[AStateIdx0] + (FV[AStateIdx1] +
    FM[Sigma[ARound][2 * AMixIdx + 0]]);
  FV[AStateIdx3] := TBits.RotateRight32(FV[AStateIdx3] xor FV[AStateIdx0], 16);
  FV[AStateIdx2] := FV[AStateIdx2] + FV[AStateIdx3];
  FV[AStateIdx1] := TBits.RotateRight32(FV[AStateIdx1] xor FV[AStateIdx2], 12);
  FV[AStateIdx0] := FV[AStateIdx0] + (FV[AStateIdx1] +
    FM[Sigma[ARound][2 * AMixIdx + 1]]);
  FV[AStateIdx3] := TBits.RotateRight32(FV[AStateIdx3] xor FV[AStateIdx0], 8);
  FV[AStateIdx2] := FV[AStateIdx2] + FV[AStateIdx3];
  FV[AStateIdx1] := TBits.RotateRight32(FV[AStateIdx1] xor FV[AStateIdx2], 7);
end;

{$ENDIF USE_UNROLLED_VARIANT}

function TBlake2S.CloneInternal(): TBlake2S;
var
  LTreeConfig: IBlake2STreeConfig;
begin
  LTreeConfig := nil;
  if FTreeConfig <> nil then
  begin
    LTreeConfig := FTreeConfig.Clone();
  end;
  Result := TBlake2S.Create(FConfig.Clone(), LTreeConfig, FDoTransformKeyBlock);
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

function TBlake2S.Clone(): IHash;
begin
  Result := CloneInternal();
end;

procedure TBlake2S.MixScalar;
var
{$IFDEF USE_UNROLLED_VARIANT}
  LBlock0, LBlock1, LBlock2, LBlock3, LBlock4, LBlock5, LBlock6, LBlock7, LBlock8, LBlock9, LBlock10, LBlock11, LBlock12, LBlock13, LBlock14, LBlock15, LWorking0, LWorking1,
    LWorking2, LWorking3, LWorking4, LWorking5, LWorking6, LWorking7, LWorking8, LWorking9, LWorking10, LWorking11, LWorking12, LWorking13, LWorking14, LWorking15: UInt32;

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
  // *
  // Round 1.
  LWorking0 := LWorking0 + LBlock0;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock2;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock4;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock6;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock5;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock7;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock3;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock1;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock8;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock10;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock12;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock14;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock13;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock15;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock11;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock9;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 2.
  LWorking0 := LWorking0 + LBlock14;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock4;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock9;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock13;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock15;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock6;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock8;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock10;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock1;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock0;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock11;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock5;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock7;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock3;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock2;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock12;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 3.
  LWorking0 := LWorking0 + LBlock11;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock12;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock5;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock15;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock2;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock13;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock0;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock8;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock10;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock3;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock7;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock9;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock1;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock4;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock6;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock14;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 4.
  LWorking0 := LWorking0 + LBlock7;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock3;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock13;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock11;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock12;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock14;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock1;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock9;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock2;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock5;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock4;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock15;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock0;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock8;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock10;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock6;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 5.
  LWorking0 := LWorking0 + LBlock9;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock5;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock2;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock10;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock4;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock15;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock7;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock0;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock14;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock11;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock6;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock3;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock8;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock13;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock12;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock1;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 6.
  LWorking0 := LWorking0 + LBlock2;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock6;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock0;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock8;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock11;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock3;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock10;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock12;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock4;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock7;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock15;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock1;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock14;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock9;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock5;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock13;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 7.
  LWorking0 := LWorking0 + LBlock12;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock1;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock14;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock4;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock13;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock10;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock15;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock5;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock0;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock6;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock9;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock8;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock2;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock11;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock3;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock7;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 8.
  LWorking0 := LWorking0 + LBlock13;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock7;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock12;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock3;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock1;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock9;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock14;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock11;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock5;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock15;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock8;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock2;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock6;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock10;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock4;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock0;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 9.
  LWorking0 := LWorking0 + LBlock6;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock14;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock11;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock0;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock3;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock8;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock9;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock15;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock12;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock13;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock1;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock10;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock4;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock5;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock7;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock2;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);

  // Round 10.
  LWorking0 := LWorking0 + LBlock10;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking1 := LWorking1 + LBlock8;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking2 := LWorking2 + LBlock7;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking3 := LWorking3 + LBlock1;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking2 := LWorking2 + LBlock6;
  LWorking2 := LWorking2 + LWorking6;
  LWorking14 := LWorking14 xor LWorking2;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking10 := LWorking10 + LWorking14;
  LWorking6 := LWorking6 xor LWorking10;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking3 := LWorking3 + LBlock5;
  LWorking3 := LWorking3 + LWorking7;
  LWorking15 := LWorking15 xor LWorking3;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking11 := LWorking11 + LWorking15;
  LWorking7 := LWorking7 xor LWorking11;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking1 := LWorking1 + LBlock4;
  LWorking1 := LWorking1 + LWorking5;
  LWorking13 := LWorking13 xor LWorking1;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking9 := LWorking9 + LWorking13;
  LWorking5 := LWorking5 xor LWorking9;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  LWorking0 := LWorking0 + LBlock2;
  LWorking0 := LWorking0 + LWorking4;
  LWorking12 := LWorking12 xor LWorking0;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking8 := LWorking8 + LWorking12;
  LWorking4 := LWorking4 xor LWorking8;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking0 := LWorking0 + LBlock15;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 16);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 12);
  LWorking1 := LWorking1 + LBlock9;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 16);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 12);
  LWorking2 := LWorking2 + LBlock3;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 16);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 12);
  LWorking3 := LWorking3 + LBlock13;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 16);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 12);
  LWorking2 := LWorking2 + LBlock12;
  LWorking2 := LWorking2 + LWorking7;
  LWorking13 := LWorking13 xor LWorking2;
  LWorking13 := TBits.RotateRight32(LWorking13, 8);
  LWorking8 := LWorking8 + LWorking13;
  LWorking7 := LWorking7 xor LWorking8;
  LWorking7 := TBits.RotateRight32(LWorking7, 7);
  LWorking3 := LWorking3 + LBlock0;
  LWorking3 := LWorking3 + LWorking4;
  LWorking14 := LWorking14 xor LWorking3;
  LWorking14 := TBits.RotateRight32(LWorking14, 8);
  LWorking9 := LWorking9 + LWorking14;
  LWorking4 := LWorking4 xor LWorking9;
  LWorking4 := TBits.RotateRight32(LWorking4, 7);
  LWorking1 := LWorking1 + LBlock14;
  LWorking1 := LWorking1 + LWorking6;
  LWorking12 := LWorking12 xor LWorking1;
  LWorking12 := TBits.RotateRight32(LWorking12, 8);
  LWorking11 := LWorking11 + LWorking12;
  LWorking6 := LWorking6 xor LWorking11;
  LWorking6 := TBits.RotateRight32(LWorking6, 7);
  LWorking0 := LWorking0 + LBlock11;
  LWorking0 := LWorking0 + LWorking5;
  LWorking15 := LWorking15 xor LWorking0;
  LWorking15 := TBits.RotateRight32(LWorking15, 8);
  LWorking10 := LWorking10 + LWorking15;
  LWorking5 := LWorking5 xor LWorking10;
  LWorking5 := TBits.RotateRight32(LWorking5, 7);
  // */
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
    G(1, 5, 9, 13, LRound, 1);
    G(2, 6, 10, 14, LRound, 2);
    G(3, 7, 11, 15, LRound, 3);
    G(0, 5, 10, 15, LRound, 4);
    G(1, 6, 11, 12, LRound, 5);
    G(2, 7, 8, 13, LRound, 6);
    G(3, 4, 9, 14, LRound, 7);

  end;

  for LWordIdx := 0 to 7 do
  begin
    FState[LWordIdx] := FState[LWordIdx] xor (FV[LWordIdx] xor FV[LWordIdx + 8]);
  end;

{$ENDIF USE_UNROLLED_VARIANT}
end;

procedure TBlake2S.Compress(ABlock: PByte; AStart: Int32);
begin
  TConverters.le32_copy(ABlock, AStart, @(FM[0]), 0, BlockSize);
  MixScalar();
end;

constructor TBlake2S.Create(const AConfig: IBlake2SConfig);
begin
  Create(AConfig, nil);
end;

constructor TBlake2S.Create(const AConfig: IBlake2SConfig;
  const ATreeConfig: IBlake2STreeConfig; ADoTransformKeyBlock: Boolean);
begin
  FConfig := AConfig;
  FTreeConfig := ATreeConfig;
  FDoTransformKeyBlock := ADoTransformKeyBlock;

  if (FConfig = nil) then
  begin
    FConfig := TBlake2SConfig.DefaultConfig;
  end;

  System.SetLength(FState, 8);

  System.SetLength(FBuffer, BlockSizeInBytes);

  inherited Create(FConfig.HashSize, BlockSizeInBytes);
end;

procedure TBlake2S.Finish;
var
  LCount: Int32;
  LPtrBuffer: PByte;
begin
  // Last compression
  Blake2SIncrementCounter(UInt32(FFilledBufferCount));

  FFinalizationFlag0 := System.High(UInt32);

  if (FTreeConfig <> nil) and (FTreeConfig.IsLastNode) then
  begin
    FFinalizationFlag1 := System.High(UInt32);
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

procedure TBlake2S.Initialize;
var
  LIdx: Int32;
  LBlock: THashLibByteArray;
  LRawConfig: THashLibUInt32Array;
begin
  LRawConfig := TBlake2SIvBuilder.ConfigS(FConfig, FTreeConfig);
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

  System.FillChar(FM, System.SizeOf(FM), UInt32(0));

{$IFNDEF USE_UNROLLED_VARIANT}
  System.FillChar(FV, System.SizeOf(FV), UInt32(0));
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

procedure TBlake2S.TransformBytes(const AData: THashLibByteArray;
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
    Blake2SIncrementCounter(UInt32(BlockSizeInBytes));
    LPtrBuffer := PByte(FBuffer);
    Compress(LPtrBuffer, 0);
    LOffset := LOffset + LBufferRemaining;
    ADataLength := ADataLength - LBufferRemaining;
    FFilledBufferCount := 0;
  end;

  LPtrData := PByte(AData);

  while (ADataLength > BlockSizeInBytes) do
  begin
    Blake2SIncrementCounter(UInt32(BlockSizeInBytes));
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

function TBlake2S.TransformFinal: IHashResult;
var
  LBuffer: THashLibByteArray;
begin
  Finish();
  System.SetLength(LBuffer, HashSize);
  TConverters.le32_copy(PCardinal(FState), 0, PByte(LBuffer), 0,
    System.Length(LBuffer));
  Result := THashResult.Create(LBuffer);
  Initialize();
end;

function TBlake2S.GetName: String;
begin
  Result := Format('%s_%u', [Self.ClassName, Self.HashSize * 8]);
end;

{ TBlake2XSConfig }

function TBlake2XSConfig.GetBlake2SConfig: IBlake2SConfig;
begin
  Result := FBlake2SConfig;
end;

function TBlake2XSConfig.GetBlake2STreeConfig: IBlake2STreeConfig;
begin
  Result := FBlake2STreeConfig;
end;

procedure TBlake2XSConfig.SetBlake2SConfig(const AValue: IBlake2SConfig);
begin
  FBlake2SConfig := AValue;
end;

procedure TBlake2XSConfig.SetBlake2STreeConfig(const AValue
  : IBlake2STreeConfig);
begin
  FBlake2STreeConfig := AValue;
end;

function TBlake2XSConfig.Clone(): TBlake2XSConfig;
begin
  Result := Default(TBlake2XSConfig);
  if FBlake2SConfig <> nil then
  begin
    Result.Blake2SConfig := FBlake2SConfig.Clone();
  end;

  if FBlake2STreeConfig <> nil then
  begin
    Result.Blake2STreeConfig := FBlake2STreeConfig.Clone();
  end;
end;

constructor TBlake2XSConfig.Create(ABlake2SConfig: IBlake2SConfig;
  ABlake2STreeConfig: IBlake2STreeConfig);
begin
  FBlake2SConfig := ABlake2SConfig;
  FBlake2STreeConfig := ABlake2STreeConfig;
end;

{ TBlake2XS }

function TBlake2XS.GetXOFSizeInBits: UInt64;
begin
  Result := FXOFSizeInBits;
end;

procedure TBlake2XS.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

function TBlake2XS.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
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

function TBlake2XS.NodeOffsetWithXOFDigestLength(AXOFSizeInBytes
  : UInt64): UInt64;
begin
  Result := (UInt64(AXOFSizeInBytes) shl 32);
end;

function TBlake2XS.ComputeStepLength: Int32;
var
  LXofSizeInBytes, LDiff: UInt64;
begin
  LXofSizeInBytes := XOFSizeInBits shr 3;
  LDiff := LXofSizeInBytes - FDigestPosition;
  if (LXofSizeInBytes = UInt64(UnknownDigestLengthInBytes)) then
  begin
    Result := Blake2SHashSize;
    Exit;
  end;

  // Math.Min
  if UInt64(Blake2SHashSize) < LDiff then
  begin
    Result := UInt64(Blake2SHashSize)
  end
  else
  begin
    Result := LDiff;
  end;
end;

function TBlake2XS.GetName: String;
begin
  Result := Self.ClassName;
end;

function TBlake2XS.Clone(): IHash;
var
  LHashInstance: TBlake2XS;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := (TBlake2XS.CreateInternal(FRootConfig.Blake2SConfig,
    FRootConfig.Blake2STreeConfig) as IXOF);
  LXof.XOFSizeInBits := (Self as IXOF).XOFSizeInBits;
  // Blake2XS Cloning
  LHashInstance := LXof as TBlake2XS;
  LHashInstance.FBlake2XSConfig := FBlake2XSConfig.Clone();
  LHashInstance.FDigestPosition := FDigestPosition;
  LHashInstance.FRootConfig := FRootConfig.Clone();
  LHashInstance.FOutputConfig := FOutputConfig.Clone();
  LHashInstance.FRootHashDigest := System.Copy(FRootHashDigest);
  LHashInstance.FBlake2XSBuffer := System.Copy(FBlake2XSBuffer);
  LHashInstance.FFinalized := FFinalized;

  // Internal Blake2S Cloning
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

constructor TBlake2XS.CreateInternal(const AConfig: IBlake2SConfig;
  const ATreeConfig: IBlake2STreeConfig);
begin
  inherited Create(AConfig, ATreeConfig);
end;

constructor TBlake2XS.Create(const ABlake2XSConfig: TBlake2XSConfig);
begin
  FBlake2XSConfig := ABlake2XSConfig;
  // Create root hash config.
  FRootConfig := Default(TBlake2XSConfig);

  FRootConfig.Blake2SConfig := FBlake2XSConfig.Blake2SConfig;

  if FRootConfig.Blake2SConfig = nil then
  begin
    FRootConfig.Blake2SConfig := TBlake2SConfig.Create();
  end
  else
  begin
    FRootConfig.Blake2SConfig.Key := FBlake2XSConfig.Blake2SConfig.Key;
    FRootConfig.Blake2SConfig.Salt := FBlake2XSConfig.Blake2SConfig.Salt;
    FRootConfig.Blake2SConfig.Personalisation :=
      FBlake2XSConfig.Blake2SConfig.Personalisation;
  end;

  FRootConfig.Blake2STreeConfig := FBlake2XSConfig.Blake2STreeConfig;

  if FRootConfig.Blake2STreeConfig = nil then
  begin
    FRootConfig.Blake2STreeConfig := TBlake2STreeConfig.Create();
    FRootConfig.Blake2STreeConfig.FanOut := 1;
    FRootConfig.Blake2STreeConfig.MaxDepth := 1;

    FRootConfig.Blake2STreeConfig.LeafSize := 0;
    FRootConfig.Blake2STreeConfig.NodeOffset := 0;
    FRootConfig.Blake2STreeConfig.NodeDepth := 0;
    FRootConfig.Blake2STreeConfig.InnerHashSize := 0;
    FRootConfig.Blake2STreeConfig.IsLastNode := False;
  end;

  // Create initial config for output hashes.
  FOutputConfig := Default(TBlake2XSConfig);

  FOutputConfig.Blake2SConfig := TBlake2SConfig.Create();
  FOutputConfig.Blake2SConfig.Salt := FRootConfig.Blake2SConfig.Salt;
  FOutputConfig.Blake2SConfig.Personalisation :=
    FRootConfig.Blake2SConfig.Personalisation;

  FOutputConfig.Blake2STreeConfig := TBlake2STreeConfig.Create();

  CreateInternal(FRootConfig.Blake2SConfig, FRootConfig.Blake2STreeConfig);
  System.SetLength(FBlake2XSBuffer, Blake2SHashSize);
end;

procedure TBlake2XS.Initialize;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := XOFSizeInBits shr 3;

  FRootConfig.Blake2STreeConfig.NodeOffset := NodeOffsetWithXOFDigestLength
    (LXofSizeInBytes);

  FOutputConfig.Blake2STreeConfig.NodeOffset := NodeOffsetWithXOFDigestLength
    (LXofSizeInBytes);
  FRootHashDigest := nil;
  FDigestPosition := 0;
  FFinalized := False;
  TArrayUtils.ZeroFill(FBlake2XSBuffer);
  inherited Initialize();
end;

procedure TBlake2XS.DoOutput(const ADestination: THashLibByteArray;
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
    System.SetLength(FRootHashDigest, Blake2SHashSize);
    TConverters.le32_copy(PCardinal(FState), 0, PByte(FRootHashDigest), 0,
      System.Length(FRootHashDigest));
  end;

  while AOutputLength > 0 do
  begin
    if (FDigestPosition and (Blake2SHashSize - 1)) = 0 then
    begin
      FOutputConfig.Blake2SConfig.HashSize := ComputeStepLength();
      FOutputConfig.Blake2STreeConfig.InnerHashSize := Blake2SHashSize;

      LHash := TBlake2S.Create(FOutputConfig.Blake2SConfig, FOutputConfig.Blake2STreeConfig);
      FBlake2XSBuffer := LHash.ComputeBytes(FRootHashDigest).GetBytes();
      FOutputConfig.Blake2STreeConfig.NodeOffset :=
        FOutputConfig.Blake2STreeConfig.NodeOffset + 1;
    end;

    LBlockOffset := FDigestPosition and (Blake2SHashSize - 1);

    LDiff := UInt64(System.Length(FBlake2XSBuffer)) - LBlockOffset;

    // Math.Min
    if AOutputLength < LDiff then
    begin
      LCount := AOutputLength
    end
    else
    begin
      LCount := LDiff;
    end;

    System.Move(FBlake2XSBuffer[LBlockOffset],
      ADestination[ADestinationOffset], LCount);

    System.Dec(AOutputLength, LCount);
    System.Inc(ADestinationOffset, LCount);
    System.Inc(FDigestPosition, LCount);
  end;
end;

function TBlake2XS.GetResult: THashLibByteArray;
var
  LXofSizeInBytes: UInt64;
begin
  System.SetLength(Result, XOFSizeInBits shr 3);

  LXofSizeInBytes := XOFSizeInBits shr 3;

  System.SetLength(Result, LXofSizeInBytes);

  DoOutput(Result, 0, LXofSizeInBytes);
end;

procedure TBlake2XS.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
begin
  if FFinalized then
  begin
    raise EInvalidOperationHashLibException.CreateResFmt
      (@SWritetoXofAfterReadError, [Name]);
  end;
  inherited TransformBytes(AData, AIndex, ADataLength);
end;

function TBlake2XS.TransformFinal: IHashResult;
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

{ TBlake2SMACNotBuildInAdapter }

procedure TBlake2SMACNotBuildInAdapter.Clear();
begin
  TArrayUtils.ZeroFill(FKey);
end;

function TBlake2SMACNotBuildInAdapter.Clone(): IHash;
var
  LHashInstance: TBlake2SMACNotBuildInAdapter;
begin
  LHashInstance := TBlake2SMACNotBuildInAdapter.Create(FHash.Clone(), FKey);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TBlake2SMACNotBuildInAdapter.Create(const ABlake2SKey, ASalt,
  APersonalisation: THashLibByteArray; AOutputLengthInBits: Int32);
var
  LConfig: IBlake2SConfig;
begin
  LConfig := TBlake2SConfig.Create(AOutputLengthInBits shr 3);
  LConfig.Key := ABlake2SKey;
  LConfig.Salt := ASalt;
  LConfig.Personalisation := APersonalisation;
  Create(TBlake2S.Create(LConfig, nil) as IHash, ABlake2SKey);
end;

constructor TBlake2SMACNotBuildInAdapter.Create(const AHash: IHash;
  const ABlake2SKey: THashLibByteArray);
begin
  inherited Create(AHash.HashSize, AHash.BlockSize);
  SetKey(ABlake2SKey);
  FHash := AHash;
end;

class function TBlake2SMACNotBuildInAdapter.CreateBlake2SMAC(const ABlake2SKey,
  ASalt, APersonalisation: THashLibByteArray; AOutputLengthInBits: Int32)
  : IBlake2SMAC;
begin
  Result := TBlake2SMACNotBuildInAdapter.Create(ABlake2SKey, ASalt,
    APersonalisation, AOutputLengthInBits) as IBlake2SMAC;
end;

destructor TBlake2SMACNotBuildInAdapter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TBlake2SMACNotBuildInAdapter.GetKey: THashLibByteArray;
begin
  Result := System.Copy(FKey);
end;

function TBlake2SMACNotBuildInAdapter.GetName: String;
begin
  Result := Format('%s', ['TBlake2SMAC']);
end;

procedure TBlake2SMACNotBuildInAdapter.Initialize;
begin
  FHash.Initialize;
end;

procedure TBlake2SMACNotBuildInAdapter.SetKey(const AValue: THashLibByteArray);
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

procedure TBlake2SMACNotBuildInAdapter.TransformBytes
  (const AData: THashLibByteArray; AIndex, ALength: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF}
  FHash.TransformBytes(AData, AIndex, ALength);
end;

function TBlake2SMACNotBuildInAdapter.TransformFinal: IHashResult;
begin
  Result := FHash.TransformFinal();
end;

end.
