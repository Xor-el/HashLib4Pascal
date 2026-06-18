unit HlpSHA3;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBinaryPrimitives,
  SysUtils,
  HlpHash,
  HlpIHashInfo,
  HlpIHash,
  HlpHashResult,
  HlpIHashResult,
  HlpHashCryptoNotBuildIn,
  HlpConverters,
  HlpHashSize,
  HlpArrayUtils,
  HlpHashLibTypes,
  HlpSHA3Dispatch;

resourcestring
  SInvalidXOFSize =
    'XOFSize in Bits must be Multiples of 8 and be Greater than Zero Bytes';
  SOutputLengthInvalid = 'Output Length is above the Digest Length';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SWritetoXofAfterReadError = '"%s" Write to Xof after Read not Allowed';

type
  TSHA3 = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)

  type
    THashMode = (Keccak = $1, CShake = $4, SHA3 = $6, Shake = $1F);
  strict protected
  var
    FState: THashLibUInt64Array;

    function GetName: String; override;
    constructor Create(AHashSize: THashSize);

    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

    function GetHashMode(): TSHA3.THashMode; virtual;

  public
    procedure Initialize; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

  end;

type
  TSHA3_224 = class sealed(TSHA3)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TSHA3_256 = class sealed(TSHA3)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TSHA3_384 = class sealed(TSHA3)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TSHA3_512 = class sealed(TSHA3)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TKeccak = class abstract(TSHA3)

  strict protected

    function GetHashMode(): TSHA3.THashMode; override;
  end;

type
  TKeccak_224 = class sealed(TKeccak)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TKeccak_256 = class sealed(TKeccak)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TKeccak_288 = class sealed(TKeccak)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TKeccak_384 = class sealed(TKeccak)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TKeccak_512 = class sealed(TKeccak)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TShake = class abstract(TSHA3, IXOF, IXOFStream)
  strict private
    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
  strict protected
  var
    FXOFSizeInBits: UInt64;
    FReader: IXofReader;
    constructor Create(AHashSize: THashSize);
    function GetHashMode(): TSHA3.THashMode; override;
    procedure EnsureReader();
    procedure CheckOutputBuffer(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64); inline;
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;

  public
    procedure Initialize(); override;
    function GetResult(): THashLibByteArray; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal(): IHashResult; override;
    procedure DoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);
    procedure Squeeze(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64); overload;
    function Squeeze(AOutputLength: UInt64): THashLibByteArray; overload;
    function GetBytesSqueezed: UInt64;
  end;

type
  TShake_128 = class sealed(TShake)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TShake_256 = class sealed(TShake)

  public

    constructor Create();
    function Clone(): IHash; override;
  end;

type
  TCShake = class abstract(TShake)

  strict private

    // LeftEncode returns max 9 bytes
    class function LeftEncode(AInput: UInt64): THashLibByteArray; static;

  strict protected

  var
    FN, FS, FInitBlock: THashLibByteArray;

    function GetHashMode(): TSHA3.THashMode; override;

    /// <param name="AHashSize">
    /// the HashSize of the underlying Shake function
    /// </param>
    /// <param name="AN">
    /// the function name string (N in SP 800-185), reserved for use by NIST.
    /// Avoid using if not required
    /// </param>
    /// <param name="AS">
    /// the customization string (S in SP 800-185), available for local use
    /// </param>
    constructor Create(AHashSize: THashSize; const AN, &AS: THashLibByteArray);

  public

    procedure Initialize(); override;

    class function RightEncode(AInput: UInt64): THashLibByteArray; static;
    class function BytePad(const AInput: THashLibByteArray; AWidthInBytes: Int32)
      : THashLibByteArray; static;
    class function EncodeString(const AInput: THashLibByteArray)
      : THashLibByteArray; static;
  end;

type
  TCShake_128 = class sealed(TCShake)

  public

    constructor Create(const AN, &AS: THashLibByteArray);
    function Clone(): IHash; override;
  end;

type
  TCShake_256 = class sealed(TCShake)

  public

    constructor Create(const AN, &AS: THashLibByteArray);
    function Clone(): IHash; override;
  end;

type
  TKMACNotBuildInAdapter = class abstract(THash, IKMAC, IKMACNotBuildIn,
    ICrypto, ICryptoNotBuildIn)

  strict protected
  var
    FHash: IHash;
    FKey: THashLibByteArray;
    // KMAC appends RightEncode(L) exactly once, immediately before the first
    // output byte is produced; this guards against re-appending on subsequent
    // (multi-chunk) DoOutput / Squeeze calls.
    FRightEncodeAppended: Boolean;

    function HashInstanceAsXof: IXOF;
    function GetName: String; override;

    function GetKey(): THashLibByteArray;
    procedure SetKey(const AValue: THashLibByteArray);

    procedure EnsureRightEncodeAppended();

    procedure DoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);

    constructor Create(AHashSize: Int32);

    function GetResult(): THashLibByteArray;

  public

    destructor Destroy; override;

    procedure Clear();

    procedure Initialize(); override;
    function TransformFinal(): IHashResult; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

    // IXOFStream (exposed by the KMAC-XOF subclasses): produce an unbounded
    // stream of output, delegating to the inner cSHAKE stream engine.
    procedure Squeeze(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64); overload;
    function Squeeze(AOutputLength: UInt64): THashLibByteArray; overload;
    function GetBytesSqueezed: UInt64;

    property Key: THashLibByteArray read GetKey write SetKey;
    property Name: String read GetName;

  end;

type
  TKMAC128 = class(TKMACNotBuildInAdapter, IKMAC)

  strict private
    constructor Create(const AKMACKey, ACustomization: THashLibByteArray;
      AOutputLengthInBits: UInt64); overload;
    constructor Create(const AHash: IHash; const AKMACKey: THashLibByteArray;
      AOutputLengthInBits: UInt64); overload;

  public
    function Clone(): IHash; override;
    class function CreateKMAC128(const AKMACKey, ACustomization
      : THashLibByteArray; AOutputLengthInBits: UInt64): IKMAC; static;
  end;

type
  TKMAC128XOF = class sealed(TKMAC128, IKMAC, IXOF, IXOFStream)
  strict private

    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;

    constructor Create(const AKMACKey, ACustomization
      : THashLibByteArray); overload;
    constructor Create(const AHash: IHash;
      const AKMACKey: THashLibByteArray); overload;

  strict protected
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;

  public
    function Clone(): IHash; override;
    class function CreateKMAC128XOF(const AKMACKey, ACustomization
      : THashLibByteArray; AXofSizeInBits: UInt64): IKMAC; static;
    class function CreateKMAC128XOFStream(const AKMACKey, ACustomization
      : THashLibByteArray): IXOFStream; static;

  end;

type
  TKMAC256 = class(TKMACNotBuildInAdapter, IKMAC)

  strict private
    constructor Create(const AKMACKey, ACustomization: THashLibByteArray;
      AOutputLengthInBits: UInt64); overload;
    constructor Create(const AHash: IHash; const AKMACKey: THashLibByteArray;
      AOutputLengthInBits: UInt64); overload;

  public
    function Clone(): IHash; override;
    class function CreateKMAC256(const AKMACKey, ACustomization
      : THashLibByteArray; AOutputLengthInBits: UInt64): IKMAC; static;
  end;

type
  TKMAC256XOF = class sealed(TKMAC256, IKMAC, IXOF, IXOFStream)
  strict private

    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;

    constructor Create(const AKMACKey, ACustomization
      : THashLibByteArray); overload;
    constructor Create(const AHash: IHash;
      const AKMACKey: THashLibByteArray); overload;

  strict protected
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;

  public
    function Clone(): IHash; override;
    class function CreateKMAC256XOF(const AKMACKey, ACustomization
      : THashLibByteArray; AXofSizeInBits: UInt64): IKMAC; static;
    class function CreateKMAC256XOFStream(const AKMACKey, ACustomization
      : THashLibByteArray): IXOFStream; static;

  end;

implementation

type
  // Self-contained SHAKE/Keccak squeeze engine. Owns a copy of the finalized
  // Keccak state and produces an unbounded byte stream; the size cap (if any)
  // is enforced by the owning XOF, not here. Shared by SHAKE, CShake and
  // (via the inner cSHAKE) KMAC-XOF.
  TKeccakXofReader = class sealed(TInterfacedObject, IXofReader)
  strict private
  var
    FState: THashLibUInt64Array;
    FShakeBuffer: THashLibByteArray;
    FBlockSize: Int32;
    FBufferPosition, FDigestPosition: UInt64;
  public
    constructor Create(const AState: THashLibUInt64Array; ABlockSize: Int32);
    procedure Read(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);
    function GetPosition: UInt64;
    function Clone(): IXofReader;
  end;

{ TKeccakXofReader }

constructor TKeccakXofReader.Create(const AState: THashLibUInt64Array;
  ABlockSize: Int32);
begin
  inherited Create();
  FState := System.Copy(AState);
  System.SetLength(FShakeBuffer, 8);
  FBlockSize := ABlockSize;
  FBufferPosition := 0;
  FDigestPosition := 0;
end;

function TKeccakXofReader.GetPosition: UInt64;
begin
  Result := FDigestPosition;
end;

procedure TKeccakXofReader.Read(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
var
  LDiff, LCount, LBlockOffset: UInt64;
begin
  while AOutputLength > 0 do
  begin
    if (FDigestPosition and 7) = 0 then
    begin

      if (FBufferPosition * 8) >= UInt64(FBlockSize) then
      begin
        KeccakF1600_Permute(@FState[0]);
        FBufferPosition := 0;
      end;

      TBinaryPrimitives.WriteUInt64LittleEndian(FShakeBuffer, 0,
        FState[FBufferPosition]);
      System.Inc(FBufferPosition);
    end;

    LBlockOffset := FDigestPosition and 7;

    LDiff := UInt64(System.Length(FShakeBuffer)) - LBlockOffset;

    // Math.Min
    if AOutputLength < LDiff then
    begin
      LCount := AOutputLength
    end
    else
    begin
      LCount := LDiff;
    end;

    System.Move(FShakeBuffer[LBlockOffset], ADestination[ADestinationOffset],
      LCount);

    System.Dec(AOutputLength, LCount);
    System.Inc(ADestinationOffset, LCount);
    System.Inc(FDigestPosition, LCount);
  end;
end;

function TKeccakXofReader.Clone(): IXofReader;
var
  LReader: TKeccakXofReader;
begin
  LReader := TKeccakXofReader.Create(FState, FBlockSize);
  LReader.FShakeBuffer := System.Copy(FShakeBuffer);
  LReader.FBufferPosition := FBufferPosition;
  LReader.FDigestPosition := FDigestPosition;
  Result := LReader;
end;

{ TSHA3 }

function TSHA3.GetHashMode(): TSHA3.THashMode;
begin
  Result := TSHA3.THashMode.SHA3;
end;

constructor TSHA3.Create(AHashSize: THashSize);
begin
  inherited Create(Int32(AHashSize), 200 - (Int32(AHashSize) * 2));
  System.SetLength(FState, 25);
end;

procedure TSHA3.Finish;
var
  LBufferPosition: Int32;
  LBlock: THashLibByteArray;
begin
  LBufferPosition := FBuffer.Position;
  LBlock := FBuffer.GetBytesZeroPadded();

  LBlock[LBufferPosition] := Int32(GetHashMode());
  LBlock[BlockSize - 1] := LBlock[BlockSize - 1] xor $80;

  TransformBlock(PByte(LBlock), System.Length(LBlock), 0);
end;

function TSHA3.GetName: String;
begin
  Result := Self.ClassName;
end;

function TSHA3.GetResult: THashLibByteArray;
begin
  System.SetLength(Result, HashSize);

  TBinaryPrimitives.CopyUInt64LittleEndian(PUInt64(FState), 0, PByte(Result), 0,
    System.Length(Result));
end;

procedure TSHA3.Initialize;
begin
  TArrayUtils.ZeroFill(FState);
  inherited Initialize();
end;

procedure TSHA3.TransformBlock(AData: PByte; ADataLength: Int32; AIndex: Int32);
begin
  KeccakF1600_Absorb(@FState[0], AData + AIndex, 1, BlockSize);
end;

procedure TSHA3.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LPtrData: PByte;
  LBlockCount: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LPtrData := PByte(AData);

  if (not FBuffer.IsEmpty) then
  begin
    if (FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount)) then
    begin
      TransformBuffer();
    end;
  end;

  LBlockCount := ALength div FBuffer.Length;
  if LBlockCount > 0 then
  begin
    FProcessedBytesCount := FProcessedBytesCount +
      UInt64(LBlockCount) * UInt64(FBuffer.Length);
    KeccakF1600_Absorb(@FState[0], LPtrData + AIndex, LBlockCount, BlockSize);
    AIndex := AIndex + (LBlockCount * FBuffer.Length);
    ALength := ALength - (LBlockCount * FBuffer.Length);
  end;

  if (ALength > 0) then
  begin
    FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount);
  end;
end;

{ TSHA3_224 }

function TSHA3_224.Clone(): IHash;
var
  LHashInstance: TSHA3_224;
begin
  LHashInstance := TSHA3_224.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TSHA3_224.Create;
begin
  inherited Create(THashSize.Size224);
end;

{ TSHA3_256 }

function TSHA3_256.Clone(): IHash;
var
  LHashInstance: TSHA3_256;
begin
  LHashInstance := TSHA3_256.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TSHA3_256.Create;
begin
  inherited Create(THashSize.Size256);
end;

{ TSHA3_384 }

function TSHA3_384.Clone(): IHash;
var
  LHashInstance: TSHA3_384;
begin
  LHashInstance := TSHA3_384.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TSHA3_384.Create;
begin
  inherited Create(THashSize.Size384);
end;

{ TSHA3_512 }

function TSHA3_512.Clone(): IHash;
var
  LHashInstance: TSHA3_512;
begin
  LHashInstance := TSHA3_512.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TSHA3_512.Create;
begin
  inherited Create(THashSize.Size512);
end;

{ TKeccak_224 }

function TKeccak_224.Clone(): IHash;
var
  LHashInstance: TKeccak_224;
begin
  LHashInstance := TKeccak_224.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKeccak_224.Create;
begin
  inherited Create(THashSize.Size224);
end;

{ TKeccak_256 }

function TKeccak_256.Clone(): IHash;
var
  LHashInstance: TKeccak_256;
begin
  LHashInstance := TKeccak_256.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKeccak_256.Create;
begin
  inherited Create(THashSize.Size256);
end;

{ TKeccak_288 }

function TKeccak_288.Clone(): IHash;
var
  LHashInstance: TKeccak_288;
begin
  LHashInstance := TKeccak_288.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKeccak_288.Create;
begin
  inherited Create(THashSize.Size288);
end;

{ TKeccak_384 }

function TKeccak_384.Clone(): IHash;
var
  LHashInstance: TKeccak_384;
begin
  LHashInstance := TKeccak_384.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKeccak_384.Create;
begin
  inherited Create(THashSize.Size384);
end;

{ TKeccak_512 }

function TKeccak_512.Clone(): IHash;
var
  LHashInstance: TKeccak_512;
begin
  LHashInstance := TKeccak_512.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKeccak_512.Create;
begin
  inherited Create(THashSize.Size512);
end;

{ TShake }

function TShake.GetHashMode(): TSHA3.THashMode;
begin
  Result := TSHA3.THashMode.Shake;
end;

function TShake.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := AXofSizeInBits shr 3;
  if (((AXofSizeInBits and $7) <> 0) or (LXofSizeInBytes < 1)) then
  begin
    raise EArgumentInvalidHashLibException.CreateRes(@SInvalidXOFSize);
  end;
  FXOFSizeInBits := AXofSizeInBits;
  Result := Self;
end;

function TShake.GetXOFSizeInBits: UInt64;
begin
  Result := FXOFSizeInBits;
end;

procedure TShake.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

constructor TShake.Create(AHashSize: THashSize);
begin
  inherited Create(AHashSize);
  FReader := nil;
end;

procedure TShake.EnsureReader();
begin
  if FReader = nil then
  begin
    Finish();
    FReader := TKeccakXofReader.Create(FState, BlockSize);
  end;
end;

procedure TShake.CheckOutputBuffer(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
begin
  if (UInt64(System.Length(ADestination)) - ADestinationOffset) < AOutputLength
  then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes(@SOutputBufferTooShort);
  end;
end;

procedure TShake.DoOutput(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
var
  LPosition: UInt64;
begin

  CheckOutputBuffer(ADestination, ADestinationOffset, AOutputLength);

  if FReader = nil then
  begin
    LPosition := 0;
  end
  else
  begin
    LPosition := FReader.Position;
  end;

  if ((LPosition + AOutputLength) > (XOFSizeInBits shr 3)) then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes(@SOutputLengthInvalid);
  end;

  EnsureReader();
  FReader.Read(ADestination, ADestinationOffset, AOutputLength);
end;

procedure TShake.Squeeze(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
begin
  CheckOutputBuffer(ADestination, ADestinationOffset, AOutputLength);

  EnsureReader();
  FReader.Read(ADestination, ADestinationOffset, AOutputLength);
end;

function TShake.Squeeze(AOutputLength: UInt64): THashLibByteArray;
begin
  System.SetLength(Result, AOutputLength);
  if AOutputLength > 0 then
  begin
    Squeeze(Result, 0, AOutputLength);
  end;
end;

function TShake.GetBytesSqueezed: UInt64;
begin
  if FReader = nil then
  begin
    Result := 0;
  end
  else
  begin
    Result := FReader.Position;
  end;
end;

function TShake.GetResult: THashLibByteArray;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := FXOFSizeInBits shr 3;

  System.SetLength(Result, LXofSizeInBytes);

  DoOutput(Result, 0, LXofSizeInBytes);
end;

procedure TShake.Initialize;
begin
  inherited Initialize();
  FReader := nil;
end;

procedure TShake.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
begin
  if FReader <> nil then
  begin
    raise EInvalidOperationHashLibException.CreateResFmt
      (@SWritetoXofAfterReadError, [Name]);
  end;
  inherited TransformBytes(AData, AIndex, ADataLength);
end;

function TShake.TransformFinal: IHashResult;
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

{ TShake_128 }

function TShake_128.Clone(): IHash;
var
  LHashInstance: TShake_128;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := TShake_128.Create();

  // Shake_128 Cloning
  LHashInstance := LXof as TShake_128;
  LHashInstance.FXOFSizeInBits := FXOFSizeInBits;
  if FReader <> nil then
  begin
    LHashInstance.FReader := FReader.Clone();
  end;

  // Internal Sha3 Cloning
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TShake_128.Create;
begin
  inherited Create(THashSize.Size128);
end;

{ TShake_256 }

function TShake_256.Clone(): IHash;
var
  LHashInstance: TShake_256;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := TShake_256.Create();

  // Shake_256 Cloning
  LHashInstance := LXof as TShake_256;
  LHashInstance.FXOFSizeInBits := FXOFSizeInBits;
  if FReader <> nil then
  begin
    LHashInstance.FReader := FReader.Clone();
  end;

  // Internal Sha3 Cloning
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TShake_256.Create;
begin
  inherited Create(THashSize.Size256);
end;

{ TCShake }

function TCShake.GetHashMode(): TSHA3.THashMode;
begin
  if (System.Length(FN) = 0) and (System.Length(FS) = 0) then
  begin
    Result := TSHA3.THashMode.Shake;
  end
  else
  begin
    Result := TSHA3.THashMode.CShake;
  end;
end;

class function TCShake.LeftEncode(AInput: UInt64): THashLibByteArray;
var
  LLengthByteCount: Byte;
  LScanValue: UInt64;
  LIdx: Int32;
begin
  LLengthByteCount := 1;
  LScanValue := AInput;
  LScanValue := LScanValue shr 8;

  while (LScanValue <> 0) do
  begin
    System.Inc(LLengthByteCount);
    LScanValue := LScanValue shr 8;
  end;

  System.SetLength(Result, LLengthByteCount + 1);
  Result[0] := LLengthByteCount;
  for LIdx := 1 to LLengthByteCount do
  begin
    Result[LIdx] := Byte(AInput shr (8 * (LLengthByteCount - LIdx)));
  end;
end;

class function TCShake.RightEncode(AInput: UInt64): THashLibByteArray;
var
  LLengthByteCount: Byte;
  LScanValue: UInt64;
  LIdx: Int32;
begin
  LLengthByteCount := 1;
  LScanValue := AInput;
  LScanValue := LScanValue shr 8;

  while (LScanValue <> 0) do
  begin
    System.Inc(LLengthByteCount);
    LScanValue := LScanValue shr 8;
  end;

  System.SetLength(Result, LLengthByteCount + 1);
  Result[LLengthByteCount] := LLengthByteCount;
  for LIdx := 1 to LLengthByteCount do
  begin
    Result[LIdx - 1] := Byte(AInput shr (8 * (LLengthByteCount - LIdx)));
  end;
end;

class function TCShake.BytePad(const AInput: THashLibByteArray;
  AWidthInBytes: Int32): THashLibByteArray;
var
  LBuffer: THashLibByteArray;
  LPadLength: Int32;
begin
  LBuffer := TArrayUtils.Concatenate(LeftEncode(UInt64(AWidthInBytes)), AInput);
  LPadLength := AWidthInBytes - (System.Length(LBuffer) mod AWidthInBytes);
  System.SetLength(Result, LPadLength);
  Result := TArrayUtils.Concatenate(LBuffer, Result);
end;

class function TCShake.EncodeString(const AInput: THashLibByteArray)
  : THashLibByteArray;
begin
  if System.Length(AInput) = 0 then
  begin
    Result := LeftEncode(0);
    Exit;
  end;
  Result := TArrayUtils.Concatenate(LeftEncode(UInt64(System.Length(AInput) * 8)
    ), AInput);
end;

constructor TCShake.Create(AHashSize: THashSize; const AN, &AS
  : THashLibByteArray);
begin
  inherited Create(AHashSize);

  FN := AN;
  FS := &AS;

  if (System.Length(FN) = 0) and (System.Length(FS) = 0) then
  begin
    FInitBlock := nil;
  end
  else
  begin
    FInitBlock := TArrayUtils.Concatenate(EncodeString(AN), EncodeString(&AS));
  end;
end;

procedure TCShake.Initialize;
begin
  inherited Initialize();

  if FInitBlock <> nil then
  begin
    TransformBytes(BytePad(FInitBlock, BlockSize));
  end;
end;

{ TCShake_128 }

function TCShake_128.Clone(): IHash;
var
  LHashInstance: TCShake_128;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := TCShake_128.Create(System.Copy(FN), System.Copy(FS));

  // CShake_128 Cloning
  LHashInstance := LXof as TCShake_128;
  LHashInstance.FXOFSizeInBits := FXOFSizeInBits;
  LHashInstance.FInitBlock := System.Copy(FInitBlock);

  if FReader <> nil then
  begin
    LHashInstance.FReader := FReader.Clone();
  end;

  // Internal Sha3 Cloning
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TCShake_128.Create(const AN, &AS: THashLibByteArray);
begin
  inherited Create(THashSize.Size128, AN, &AS);
end;

{ TCShake_256 }

function TCShake_256.Clone(): IHash;
var
  LHashInstance: TCShake_256;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := TCShake_256.Create(System.Copy(FN), System.Copy(FS));

  // CShake_256 Cloning
  LHashInstance := LXof as TCShake_256;
  LHashInstance.FXOFSizeInBits := FXOFSizeInBits;
  LHashInstance.FInitBlock := System.Copy(FInitBlock);

  if FReader <> nil then
  begin
    LHashInstance.FReader := FReader.Clone();
  end;

  // Internal Sha3 Cloning
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TCShake_256.Create(const AN, &AS: THashLibByteArray);
begin
  inherited Create(THashSize.Size256, AN, &AS);
end;

{ TKMACNotBuildInAdapter }

function TKMACNotBuildInAdapter.HashInstanceAsXof: IXOF;
var
  LXof: IXOF;
begin
  if not Supports(FHash, IXOF, LXof) then
    raise EInvalidOperationHashLibException.Create(
      'Internal error: KMAC hash must implement IXOF');
  Result := LXof;
end;

procedure TKMACNotBuildInAdapter.Clear();
begin
  TArrayUtils.ZeroFill(FKey);
end;

constructor TKMACNotBuildInAdapter.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 200 - (AHashSize * 2));
end;

destructor TKMACNotBuildInAdapter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

procedure TKMACNotBuildInAdapter.EnsureRightEncodeAppended();
var
  LXof: IXOF;
begin
  if FRightEncodeAppended then
  begin
    Exit;
  end;

  LXof := HashInstanceAsXof;
  if Supports(Self, IXOF) then
  begin
    // KMAC-XOF: arbitrary output length is encoded as RightEncode(0)
    TransformBytes(TCShake.RightEncode(0));
  end
  else
  begin
    // fixed-length KMAC: the declared output length L (in bits) is encoded
    TransformBytes(TCShake.RightEncode(LXof.XOFSizeInBits));
  end;

  FRightEncodeAppended := True;
end;

procedure TKMACNotBuildInAdapter.DoOutput(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
begin
  EnsureRightEncodeAppended();
  HashInstanceAsXof.DoOutput(ADestination, ADestinationOffset, AOutputLength);
end;

procedure TKMACNotBuildInAdapter.Squeeze(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
var
  LStream: IXOFStream;
begin
  EnsureRightEncodeAppended();
  if not Supports(FHash, IXOFStream, LStream) then
  begin
    raise EInvalidOperationHashLibException.Create
      ('Internal error: KMAC hash must implement IXOFStream');
  end;
  LStream.Squeeze(ADestination, ADestinationOffset, AOutputLength);
end;

function TKMACNotBuildInAdapter.Squeeze(AOutputLength: UInt64)
  : THashLibByteArray;
begin
  System.SetLength(Result, AOutputLength);
  if AOutputLength > 0 then
  begin
    Squeeze(Result, 0, AOutputLength);
  end;
end;

function TKMACNotBuildInAdapter.GetBytesSqueezed: UInt64;
var
  LStream: IXOFStream;
begin
  if Supports(FHash, IXOFStream, LStream) then
  begin
    Result := LStream.BytesSqueezed;
  end
  else
  begin
    Result := 0;
  end;
end;

function TKMACNotBuildInAdapter.GetKey: THashLibByteArray;
begin
  Result := System.Copy(FKey);
end;

function TKMACNotBuildInAdapter.GetName: String;
begin
  Result := Self.ClassName;
end;

procedure TKMACNotBuildInAdapter.Initialize;
begin
  FRightEncodeAppended := False;
  FHash.Initialize;
  TransformBytes(TCShake.BytePad(TCShake.EncodeString(FKey), BlockSize));
end;

procedure TKMACNotBuildInAdapter.SetKey(const AValue: THashLibByteArray);
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

procedure TKMACNotBuildInAdapter.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  FHash.TransformBytes(AData, AIndex, ALength);
end;

function TKMACNotBuildInAdapter.GetResult: THashLibByteArray;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := HashInstanceAsXof.XOFSizeInBits shr 3;
  System.SetLength(Result, LXofSizeInBytes);
  DoOutput(Result, 0, LXofSizeInBytes);
end;

function TKMACNotBuildInAdapter.TransformFinal: IHashResult;
var
  LBuffer: THashLibByteArray;
begin
  LBuffer := GetResult();
{$IFDEF DEBUG}
  System.Assert(UInt64(System.Length(LBuffer)) = (HashInstanceAsXof.XOFSizeInBits shr 3));
{$ENDIF DEBUG}
  Initialize();
  Result := THashResult.Create(LBuffer);
end;

{ TKMAC128 }

function TKMAC128.Clone(): IHash;
var
  LHashInstance: TKMAC128;
begin
  LHashInstance := TKMAC128.Create(FHash.Clone(), FKey,
    HashInstanceAsXof.XOFSizeInBits);
  LHashInstance.FRightEncodeAppended := FRightEncodeAppended;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKMAC128.Create(const AKMACKey, ACustomization: THashLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Create(TCShake_128.Create(TConverters.ConvertStringToBytes('KMAC',
    TEncoding.UTF8), ACustomization) as IHash, AKMACKey, AOutputLengthInBits);
end;

constructor TKMAC128.Create(const AHash: IHash;
  const AKMACKey: THashLibByteArray; AOutputLengthInBits: UInt64);
begin
  inherited Create(Int32(THashSize.Size128));
  SetKey(AKMACKey);
  FHash := AHash;
  HashInstanceAsXof.XOFSizeInBits := AOutputLengthInBits;
end;

class function TKMAC128.CreateKMAC128(const AKMACKey, ACustomization
  : THashLibByteArray; AOutputLengthInBits: UInt64): IKMAC;
begin
  Result := TKMAC128.Create(AKMACKey, ACustomization, AOutputLengthInBits);
end;

{ TKMAC128XOF }

function TKMAC128XOF.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := AXofSizeInBits shr 3;
  if (((AXofSizeInBits and $7) <> 0) or (LXofSizeInBytes < 1)) then
  begin
    raise EArgumentInvalidHashLibException.CreateRes(@SInvalidXOFSize);
  end;

  HashInstanceAsXof.XOFSizeInBits := AXofSizeInBits;
  Result := Self;
end;

function TKMAC128XOF.GetXOFSizeInBits: UInt64;
begin
  Result := HashInstanceAsXof.XOFSizeInBits;
end;

procedure TKMAC128XOF.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

function TKMAC128XOF.Clone(): IHash;
var
  LHashInstance: TKMAC128XOF;
begin
  LHashInstance := TKMAC128XOF.Create(FHash.Clone(), FKey);
  LHashInstance.FRightEncodeAppended := FRightEncodeAppended;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKMAC128XOF.Create(const AHash: IHash;
  const AKMACKey: THashLibByteArray);
begin
  inherited Create(Int32(THashSize.Size128));
  SetKey(AKMACKey);
  FHash := AHash;
end;

constructor TKMAC128XOF.Create(const AKMACKey, ACustomization
  : THashLibByteArray);
begin
  Create(TCShake_128.Create(TConverters.ConvertStringToBytes('KMAC',
    TEncoding.UTF8), ACustomization) as IHash, AKMACKey);
end;

class function TKMAC128XOF.CreateKMAC128XOF(const AKMACKey, ACustomization
  : THashLibByteArray; AXofSizeInBits: UInt64): IKMAC;
var
  LXof: IXOF;
begin
  LXof := TKMAC128XOF.Create(AKMACKey, ACustomization);
  LXof.XOFSizeInBits := AXofSizeInBits;
  Result := LXof as IKMAC;
end;

class function TKMAC128XOF.CreateKMAC128XOFStream(const AKMACKey, ACustomization
  : THashLibByteArray): IXOFStream;
begin
  // streaming KMAC-XOF: no output size is declared; Squeeze pulls on demand
  Result := TKMAC128XOF.Create(AKMACKey, ACustomization) as IXOFStream;
end;

{ TKMAC256 }

function TKMAC256.Clone(): IHash;
var
  LHashInstance: TKMAC256;
begin
  LHashInstance := TKMAC256.Create(FHash.Clone(), FKey,
    HashInstanceAsXof.XOFSizeInBits);
  LHashInstance.FRightEncodeAppended := FRightEncodeAppended;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKMAC256.Create(const AKMACKey, ACustomization: THashLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Create(TCShake_256.Create(TConverters.ConvertStringToBytes('KMAC',
    TEncoding.UTF8), ACustomization) as IHash, AKMACKey, AOutputLengthInBits);
end;

constructor TKMAC256.Create(const AHash: IHash;
  const AKMACKey: THashLibByteArray; AOutputLengthInBits: UInt64);
begin
  inherited Create(Int32(THashSize.Size256));
  SetKey(AKMACKey);
  FHash := AHash;
  HashInstanceAsXof.XOFSizeInBits := AOutputLengthInBits;
end;

class function TKMAC256.CreateKMAC256(const AKMACKey, ACustomization
  : THashLibByteArray; AOutputLengthInBits: UInt64): IKMAC;
begin
  Result := TKMAC256.Create(AKMACKey, ACustomization, AOutputLengthInBits);
end;

{ TKMAC256XOF }

function TKMAC256XOF.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
var
  LXofSizeInBytes: UInt64;
begin
  LXofSizeInBytes := AXofSizeInBits shr 3;
  if (((AXofSizeInBits and $7) <> 0) or (LXofSizeInBytes < 1)) then
  begin
    raise EArgumentInvalidHashLibException.CreateRes(@SInvalidXOFSize);
  end;

  HashInstanceAsXof.XOFSizeInBits := AXofSizeInBits;
  Result := Self;
end;

function TKMAC256XOF.GetXOFSizeInBits: UInt64;
begin
  Result := HashInstanceAsXof.XOFSizeInBits;
end;

procedure TKMAC256XOF.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

function TKMAC256XOF.Clone(): IHash;
var
  LHashInstance: TKMAC256XOF;
begin
  LHashInstance := TKMAC256XOF.Create(FHash.Clone(), FKey);
  LHashInstance.FRightEncodeAppended := FRightEncodeAppended;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TKMAC256XOF.Create(const AHash: IHash;
  const AKMACKey: THashLibByteArray);
begin
  inherited Create(Int32(THashSize.Size256));
  SetKey(AKMACKey);
  FHash := AHash;
end;

constructor TKMAC256XOF.Create(const AKMACKey, ACustomization
  : THashLibByteArray);
begin
  Create(TCShake_256.Create(TConverters.ConvertStringToBytes('KMAC',
    TEncoding.UTF8), ACustomization) as IHash, AKMACKey);
end;

class function TKMAC256XOF.CreateKMAC256XOF(const AKMACKey, ACustomization
  : THashLibByteArray; AXofSizeInBits: UInt64): IKMAC;
var
  LXof: IXOF;
begin
  LXof := TKMAC256XOF.Create(AKMACKey, ACustomization);
  LXof.XOFSizeInBits := AXofSizeInBits;
  Result := LXof as IKMAC;
end;

class function TKMAC256XOF.CreateKMAC256XOFStream(const AKMACKey, ACustomization
  : THashLibByteArray): IXOFStream;
begin
  // streaming KMAC-XOF: no output size is declared; Squeeze pulls on demand
  Result := TKMAC256XOF.Create(AKMACKey, ACustomization) as IXOFStream;
end;

{ TKeccak }

function TKeccak.GetHashMode(): TSHA3.THashMode;
begin
  Result := TSHA3.THashMode.Keccak;
end;

end.
