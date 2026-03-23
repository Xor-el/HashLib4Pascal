unit HlpBlake2S;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
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

  const
    BlockSizeInBytes = Int32(64);

    IV0 = UInt32($6A09E667);
    IV1 = UInt32($BB67AE85);
    IV2 = UInt32($3C6EF372);
    IV3 = UInt32($A54FF53A);
    IV4 = UInt32($510E527F);
    IV5 = UInt32($9B05688C);
    IV6 = UInt32($1F83D9AB);
    IV7 = UInt32($5BE0CD19);

  var
    FTreeConfig: IBlake2STreeConfig;
    FConfig: IBlake2SConfig;
    FDoTransformKeyBlock: Boolean;

    procedure Blake2SIncrementCounter(AIncrementCount: UInt32); inline;
    procedure Compress(ABlock: PByte; AStart: Int32); inline;

  strict protected
  var
    FState: THashLibUInt32Array;
    FM: array [0 .. 15] of UInt32;
    FBuffer: THashLibByteArray;
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

uses
  HlpBlake2SDispatch;

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

procedure TBlake2S.Compress(ABlock: PByte; AStart: Int32);
var
  LCounterFlags: array [0 .. 3] of UInt32;
begin
  TConverters.le32_copy(ABlock, AStart, @(FM[0]), 0, BlockSize);
  LCounterFlags[0] := FCounter0;
  LCounterFlags[1] := FCounter1;
  LCounterFlags[2] := FFinalizationFlag0;
  LCounterFlags[3] := FFinalizationFlag1;
  HlpBlake2SDispatch.Blake2S_Compress(@FState[0], @FM[0],
    @LCounterFlags[0], @HlpBlake2SDispatch.Blake2SIV[0]);
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
