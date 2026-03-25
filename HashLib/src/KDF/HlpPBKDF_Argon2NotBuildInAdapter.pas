unit HlpPBKDF_Argon2NotBuildInAdapter;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
{$IFDEF HASHLIB_USE_PPL}
  System.Threading,
{$ENDIF HASHLIB_USE_PPL}
  HlpKDF,
  HlpIHash,
  HlpIHashInfo,
  HlpBlake2B,
  HlpIBlake2BParams,
  HlpBlake2BParams,
  HlpConverters,
  HlpArgon2TypeAndVersion,
  HlpArgon2Dispatch,
  HlpArrayUtils,
  HlpHashLibTypes;

resourcestring
  SInvalidOutputByteCount = '"(AByteCount)" Argument Less Than "%d".';
  SBlockInstanceNotInitialized = 'Block Instance not Initialized';
  SInputLengthInvalid = 'Input Length "%d" is not Equal to BlockSize "%d"';
  SLanesTooSmall = 'Lanes Must be Greater Than "%d"';
  SLanesTooBig = 'Lanes Must be Less Than "%d"';
  SMemoryTooSmall = 'Memory is Less Than: "%d", Expected "%d"';
  SIterationsTooSmall = 'Iterations is Less Than: "%d"';
  SArgon2ParameterBuilderNotInitialized =
    'Argon2 Parameter Builder Not Initialized';

type
  TArgon2ParametersBuilder = class abstract(TInterfacedObject,
    IArgon2ParametersBuilder)

  strict private

  const
    DefaultIterations = Int32(3);
    DefaultMemoryCost = Int32(12);
    DefaultLanes = Int32(1);
    DefaultType: TArgon2Type = TArgon2Type.a2tARGON2_i;
    DefaultVersion: TArgon2Version = TArgon2Version.a2vARGON2_VERSION_13;

  var
    FSalt, FSecret, FAdditional: THashLibByteArray;
    FIterations, FMemory, FLanes: Int32;
    FType: TArgon2Type;
    FVersion: TArgon2Version;

  type
    TArgon2Parameters = class sealed(TInterfacedObject, IArgon2Parameters)

    strict private
      FSalt, FSecret, FAdditional: THashLibByteArray;
      FIterations, FMemory, FLanes: Int32;
      FType: TArgon2Type;
      FVersion: TArgon2Version;

      function GetSalt(): THashLibByteArray; inline;
      function GetSecret(): THashLibByteArray; inline;
      function GetAdditional(): THashLibByteArray; inline;
      function GetIterations(): Int32; inline;
      function GetMemory(): Int32; inline;
      function GetLanes(): Int32; inline;
      function GetType(): TArgon2Type; inline;
      function GetVersion(): TArgon2Version; inline;

    public
      constructor Create(AType: TArgon2Type;
        const ASalt, ASecret, AAdditional: THashLibByteArray;
        AIterations, AMemory, ALanes: Int32; AVersion: TArgon2Version);

      procedure Clear(); inline;

      property Salt: THashLibByteArray read GetSalt;
      property Secret: THashLibByteArray read GetSecret;
      property Additional: THashLibByteArray read GetAdditional;
      property Iterations: Int32 read GetIterations;
      property Memory: Int32 read GetMemory;
      property Lanes: Int32 read GetLanes;
      property &Type: TArgon2Type read GetType;
      property Version: TArgon2Version read GetVersion;
    end;

  strict protected

    constructor Create(AType: TArgon2Type);

  public

    destructor Destroy(); override;

    function WithParallelism(AParallelism: Int32)
      : IArgon2ParametersBuilder; virtual;

    function WithSalt(const ASalt: THashLibByteArray)
      : IArgon2ParametersBuilder; virtual;

    function WithSecret(const ASecret: THashLibByteArray)
      : IArgon2ParametersBuilder; virtual;

    function WithAdditional(const AAdditional: THashLibByteArray)
      : IArgon2ParametersBuilder; virtual;

    function WithIterations(AIterations: Int32)
      : IArgon2ParametersBuilder; virtual;

    function WithMemoryAsKB(AMemory: Int32): IArgon2ParametersBuilder; virtual;

    function WithMemoryPowOfTwo(AMemory: Int32)
      : IArgon2ParametersBuilder; virtual;

    function WithVersion(AVersion: TArgon2Version)
      : IArgon2ParametersBuilder; virtual;

    procedure Clear(); virtual;

    function Build(): IArgon2Parameters; virtual;
  end;

type
  TArgon2iParametersBuilder = class sealed(TArgon2ParametersBuilder)

  strict private
    constructor Create();

  public
    class function Builder(): IArgon2ParametersBuilder; static; inline;

  end;

type
  TArgon2dParametersBuilder = class sealed(TArgon2ParametersBuilder)

  strict private
    constructor Create();

  public
    class function Builder(): IArgon2ParametersBuilder; static; inline;

  end;

type
  TArgon2idParametersBuilder = class sealed(TArgon2ParametersBuilder)

  strict private
    constructor Create();

  public
    class function Builder(): IArgon2ParametersBuilder; static; inline;

  end;

type

  /// <summary>
  /// Argon2 PBKDF - Based on the results of https://password-hashing.net/
  /// and https://www.ietf.org/archive/id/draft-irtf-cfrg-argon2-03.txt
  /// </summary>
  TPBKDF_Argon2NotBuildInAdapter = class sealed(TKDF, IPBKDF_Argon2,
    IPBKDF_Argon2NotBuildIn)

  strict private

  const

    Argon2BlockSize = Int32(1024);
    Argon2QwordsInBlock = Int32(Argon2BlockSize div 8);

    Argon2AddressesInBlock = Int32(128);

    Argon2PrehashDigestLength = Int32(64);
    Argon2PrehashSeedLength = Int32(72);

    Argon2SyncPoints = Int32(4);

    // Minimum and maximum number of lanes (degree of parallelism)
    MinParallelism = Int32(1);
    MaxParallelism = Int32(16777216);

    // Minimum digest size in bytes
    MinOutLen = Int32(4);

    // Minimum and maximum number of passes
    MinIterations = Int32(1);

  type
    TBlock = record

    private

      const
      Size = Int32(Argon2QwordsInBlock);

      procedure CopyBlock(const AOther: TBlock); inline;
      procedure &Xor(const AB1, AB2: TBlock); overload;
      procedure XorWith(const AOther: TBlock);

    public
    var
      // 128 * 8 Byte QWords
      V: THashLibUInt64Array;
      Initialized: Boolean;

      class function CreateBlock(): TBlock; static;

      function Clear(): TBlock;
      procedure &Xor(const AB1, AB2, AB3: TBlock); overload;
      procedure FromBytes(const AInput: THashLibByteArray);

      function ToBytes(): THashLibByteArray;
      function ToString(): String;

    end;

  type
    TPosition = record

    public
    var
      Pass, Lane, Slice, Index: Int32;

      class function CreatePosition(): TPosition; static;

      procedure Update(APass, ALane, ASlice, AIndex: Int32);

    end;

  type
    TFillBlock = record

    private

      procedure FillBlock(var ALeftBlock, ARightBlock, ACurrentBlock: TBlock;
        AWithXor: Boolean);

    public
    var
      AddressBlock, ZeroBlock, InputBlock: TBlock;

      class function CreateFillBlock(): TFillBlock; static;
    end;

  var

    FMemory: THashLibGenericArray<TBlock>;
    FFillers: THashLibGenericArray<TFillBlock>;
    FSegmentLength, FLaneLength: Int32;
    FParameters: IArgon2Parameters;
    FPassword, FResult: THashLibByteArray;

    class procedure AddIntToLittleEndian(const AHash: IHash; AInt32Value: Int32);
      static; inline;

    class procedure AddByteString(const AHash: IHash;
      const AOctets: THashLibByteArray); static; inline;

    class function MakeBlake2BInstanceAndInitialize(AHashSize: Int32): IHash;
      static; inline;

    class function GetStartingIndex(const APosition: TPosition): Int32;
      static; inline;

    procedure InitializeMemory(AMemoryBlocks: Int32);
    procedure DoInit(const AParameters: IArgon2Parameters);
    // Clear memory.
    procedure Reset();

    function IsDataIndependentAddressing(const APosition: TPosition)
      : Boolean; inline;
    procedure NextAddresses(var AFiller: TFillBlock;
      var AZeroBlock, AInputBlock, AAddressBlock: TBlock); inline;
    function IntToUInt64(AValue: Int32): UInt64; inline;
    procedure InitAddressBlocks(var AFiller: TFillBlock;
      const APosition: TPosition; var AZeroBlock, AInputBlock,
      AAddressBlock: TBlock);
    (* 1.2 Computing the index of the reference block
      1.2.1 Taking pseudo-random value from the previous block *)
    function GetPseudoRandom(var AFiller: TFillBlock;
      const APosition: TPosition; var AAddressBlock, AInputBlock,
      AZeroBlock: TBlock; APrevOffset: Int32;
      ADataIndependentAddressing: Boolean): UInt64;
    function GetRefLane(const APosition: TPosition; APseudoRandom: UInt64)
      : Int32; inline;
    function GetRefColumn(const APosition: TPosition; APseudoRandom: UInt64;
      ASameLane: Boolean): Int32;
    function IsWithXor(const APosition: TPosition): Boolean; inline;
    function GetPrevOffset(ACurrentOffset: Int32): Int32; inline;
    function RotatePrevOffset(ACurrentOffset, APrevOffset: Int32)
      : Int32; inline;
    procedure FillSegment(ALane: Int32; var APosition: TPosition);
    procedure FillSegmentForLane(ALane: Int32; const ABasePosition: TPosition);
    procedure DoParallelFillMemoryBlocks;

    (* *

      * H0 = H64(p, τ, m, t, v, y, |P|, P, |S|, S, |L|, K, |X|, X)
      * -> 64 byte (Argon2PrehashDigestLength)
    *)
    function InitialHash(const AParameters: IArgon2Parameters;
      AOutputLength: Int32; const APassword: THashLibByteArray)
      : THashLibByteArray; inline;

    function GetInitialHashLong(const AInitialHash,
      AAppendix: THashLibByteArray): THashLibByteArray; inline;

    // H' - hash - variable length hash function
    function Hash(const AInput: THashLibByteArray; AOutputLength: Int32)
      : THashLibByteArray;
    procedure Digest(AOutputLength: Int32);
    (* *
      * (H0 || 0 || i) 72 byte -> 1024 byte
      * (H0 || 1 || i) 72 byte -> 1024 byte
    *)
    procedure FillFirstBlocks(const AInitialHash: THashLibByteArray);
    procedure Initialize(const APassword: THashLibByteArray;
      AOutputLength: Int32); inline;

    class procedure ValidatePBKDF_Argon2Inputs(const AArgon2Parameters
      : IArgon2Parameters); static;

  public

    /// <summary>
    /// Initialise the <see cref="HlpPBKDF_Argon2NotBuildInAdapter|TPBKDF_Argon2NotBuildInAdapter" />
    /// from the password and parameters.
    /// </summary>
    /// <param name="APassword">
    /// the password to use.
    /// </param>
    /// <param name="AParameters">
    /// Argon2 configuration.
    /// </param>
    constructor Create(const APassword: THashLibByteArray;
      const AParameters: IArgon2Parameters);

    destructor Destroy; override;

    procedure Clear(); override;

    /// <summary>
    /// Returns the pseudo-random bytes for this object.
    /// </summary>
    /// <param name="AByteCount">The number of pseudo-random key bytes to generate.</param>
    /// <returns>A byte array filled with pseudo-random key bytes.</returns>
    /// /// <exception cref="EArgumentOutOfRangeHashLibException">AByteCount must be greater than MinOutLen.</exception>
    function GetBytes(AByteCount: Int32): THashLibByteArray; override;

  end;

implementation

{ TPBKDF_Argon2NotBuildInAdapter.TBlock }

class function TPBKDF_Argon2NotBuildInAdapter.TBlock.CreateBlock: TBlock;
begin
  Result := Default(TBlock);
  System.SetLength(Result.V, Size);
  Result.Initialized := True;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TBlock.CopyBlock(const AOther: TBlock);
begin
{$IFDEF DEBUG}
  System.Assert(Initialized and AOther.Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  System.Move(AOther.V[0], V[0], Size * System.SizeOf(UInt64));
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TBlock.&Xor(const AB1, AB2: TBlock);
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized and AB1.Initialized and AB2.Initialized,
    SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  for LIdx := 0 to System.Pred(Size) do
  begin
    V[LIdx] := AB1.V[LIdx] xor AB2.V[LIdx];
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TBlock.XorWith(const AOther: TBlock);
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized and AOther.Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  for LIdx := 0 to System.Pred(Size) do
  begin
    V[LIdx] := V[LIdx] xor AOther.V[LIdx];
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.TBlock.Clear;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  TArrayUtils.ZeroFill(V);
  Result := Self;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TBlock.&Xor(const AB1, AB2,
  AB3: TBlock);
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized and AB1.Initialized and AB2.Initialized
    and AB3.Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  for LIdx := 0 to System.Pred(Size) do
  begin
    V[LIdx] := AB1.V[LIdx] xor AB2.V[LIdx] xor AB3.V[LIdx];
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TBlock.FromBytes
  (const AInput: THashLibByteArray);
var
  LIdx: Int32;
  LPtrInput: PByte;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  if (System.Length(AInput) <> Argon2BlockSize) then
  begin
    raise EArgumentHashLibException.CreateResFmt(@SInputLengthInvalid,
      [System.Length(AInput), Argon2BlockSize]);
  end;
  LPtrInput := PByte(AInput);
  for LIdx := 0 to System.Pred(Size) do
  begin
    V[LIdx] := TConverters.ReadBytesAsUInt64LE(LPtrInput, LIdx * 8);
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.TBlock.ToBytes: THashLibByteArray;
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  System.SetLength(Result, Argon2BlockSize);
  for LIdx := 0 to System.Pred(Size) do
  begin
    TConverters.ReadUInt64AsBytesLE(V[LIdx], Result, LIdx * 8);
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.TBlock.ToString: String;
var
  LIdx: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(Initialized, SBlockInstanceNotInitialized);
{$ENDIF DEBUG}
  Result := '';
  for LIdx := 0 to System.Pred(Size) do
  begin
    Result := Result + TConverters.ConvertBytesToHexString
      (TConverters.ReadUInt64AsBytesLE(V[LIdx]), False);
  end;
end;

{ TPBKDF_Argon2NotBuildInAdapter.TPosition }

class function TPBKDF_Argon2NotBuildInAdapter.TPosition.CreatePosition()
  : TPosition;
begin
  Result := Default(TPosition);
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TPosition.Update(APass, ALane, ASlice,
  AIndex: Int32);
begin
  Pass := APass;
  Lane := ALane;
  Slice := ASlice;
  Index := AIndex;
end;

{ TPBKDF_Argon2NotBuildInAdapter.TFillBlock }

class function TPBKDF_Argon2NotBuildInAdapter.TFillBlock.CreateFillBlock
  : TFillBlock;
begin
  Result := Default(TFillBlock);
  Result.AddressBlock := TBlock.CreateBlock();
  Result.ZeroBlock := TBlock.CreateBlock();
  Result.InputBlock := TBlock.CreateBlock();
end;

procedure TPBKDF_Argon2NotBuildInAdapter.TFillBlock.FillBlock(var ALeftBlock,
  ARightBlock, ACurrentBlock: TBlock; AWithXor: Boolean);
begin
  Argon2_FillBlock(@ALeftBlock.V[0], @ARightBlock.V[0],
    @ACurrentBlock.V[0], Ord(AWithXor));
end;

{ TArgon2ParametersBuilder.TArgon2Parameters }

constructor TArgon2ParametersBuilder.TArgon2Parameters.Create
  (AType: TArgon2Type; const ASalt, ASecret, AAdditional: THashLibByteArray;
  AIterations, AMemory, ALanes: Int32; AVersion: TArgon2Version);
begin
  inherited Create();
  FSalt := System.Copy(ASalt);
  FSecret := System.Copy(ASecret);
  FAdditional := System.Copy(AAdditional);
  FIterations := AIterations;
  FMemory := AMemory;
  FLanes := ALanes;
  FType := AType;
  FVersion := AVersion;
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetSalt: THashLibByteArray;
begin
  Result := System.Copy(FSalt);
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetSecret
  : THashLibByteArray;
begin
  Result := System.Copy(FSecret);
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetAdditional
  : THashLibByteArray;
begin
  Result := System.Copy(FAdditional);
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetIterations: Int32;
begin
  Result := FIterations;
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetMemory: Int32;
begin
  Result := FMemory;
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetLanes: Int32;
begin
  Result := FLanes;
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetVersion: TArgon2Version;
begin
  Result := FVersion;
end;

function TArgon2ParametersBuilder.TArgon2Parameters.GetType: TArgon2Type;
begin
  Result := FType;
end;

procedure TArgon2ParametersBuilder.TArgon2Parameters.Clear();
begin
  TArrayUtils.ZeroFill(FSalt);
  TArrayUtils.ZeroFill(FSecret);
  TArrayUtils.ZeroFill(FAdditional);
end;

{ TArgon2ParametersBuilder }

constructor TArgon2ParametersBuilder.Create(AType: TArgon2Type);
begin
  inherited Create();
  FLanes := DefaultLanes;
  FMemory := 1 shl DefaultMemoryCost;
  FIterations := DefaultIterations;
  FType := AType;
  FVersion := DefaultVersion;
end;

destructor TArgon2ParametersBuilder.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TArgon2ParametersBuilder.WithAdditional(const AAdditional
  : THashLibByteArray): IArgon2ParametersBuilder;
begin
  FAdditional := System.Copy(AAdditional);
  Result := Self;
end;

function TArgon2ParametersBuilder.WithIterations(AIterations: Int32)
  : IArgon2ParametersBuilder;
begin
  FIterations := AIterations;
  Result := Self;
end;

function TArgon2ParametersBuilder.WithMemoryAsKB(AMemory: Int32)
  : IArgon2ParametersBuilder;
begin
  FMemory := AMemory;
  Result := Self;
end;

function TArgon2ParametersBuilder.WithMemoryPowOfTwo(AMemory: Int32)
  : IArgon2ParametersBuilder;
begin
  FMemory := 1 shl AMemory;
  Result := Self;
end;

function TArgon2ParametersBuilder.WithParallelism(AParallelism: Int32)
  : IArgon2ParametersBuilder;
begin
  FLanes := AParallelism;
  Result := Self;
end;

function TArgon2ParametersBuilder.WithSalt(const ASalt: THashLibByteArray)
  : IArgon2ParametersBuilder;
begin
  FSalt := System.Copy(ASalt);
  Result := Self;
end;

function TArgon2ParametersBuilder.WithSecret(const ASecret: THashLibByteArray)
  : IArgon2ParametersBuilder;
begin
  FSecret := System.Copy(ASecret);
  Result := Self;
end;

function TArgon2ParametersBuilder.WithVersion(AVersion: TArgon2Version)
  : IArgon2ParametersBuilder;
begin
  FVersion := AVersion;
  Result := Self;
end;

function TArgon2ParametersBuilder.Build(): IArgon2Parameters;
begin
  Result := TArgon2Parameters.Create(FType, FSalt, FSecret, FAdditional,
    FIterations, FMemory, FLanes, FVersion);
end;

procedure TArgon2ParametersBuilder.Clear();
begin
  TArrayUtils.ZeroFill(FSalt);
  TArrayUtils.ZeroFill(FSecret);
  TArrayUtils.ZeroFill(FAdditional);
end;

{ TArgon2iParametersBuilder }

constructor TArgon2iParametersBuilder.Create;
begin
  inherited Create(TArgon2Type.a2tARGON2_i);
end;

class function TArgon2iParametersBuilder.Builder: IArgon2ParametersBuilder;
begin
  Result := TArgon2iParametersBuilder.Create();
end;

{ TArgon2dParametersBuilder }

constructor TArgon2dParametersBuilder.Create;
begin
  inherited Create(TArgon2Type.a2tARGON2_d);
end;

class function TArgon2dParametersBuilder.Builder: IArgon2ParametersBuilder;
begin
  Result := TArgon2dParametersBuilder.Create();
end;

{ TArgon2idParametersBuilder }

constructor TArgon2idParametersBuilder.Create;
begin
  inherited Create(TArgon2Type.a2tARGON2_id);
end;

class function TArgon2idParametersBuilder.Builder: IArgon2ParametersBuilder;
begin
  Result := TArgon2idParametersBuilder.Create();
end;

{ TPBKDF_Argon2NotBuildInAdapter }

class procedure TPBKDF_Argon2NotBuildInAdapter.ValidatePBKDF_Argon2Inputs
  (const AArgon2Parameters: IArgon2Parameters);
begin
  if not(System.Assigned(AArgon2Parameters)) then
  begin
    raise EArgumentNilHashLibException.CreateRes
      (@SArgon2ParameterBuilderNotInitialized);
  end;
end;

class procedure TPBKDF_Argon2NotBuildInAdapter.AddIntToLittleEndian
  (const AHash: IHash; AInt32Value: Int32);
begin
  AHash.TransformBytes(TConverters.ReadUInt32AsBytesLE(UInt32(AInt32Value)));
end;

class procedure TPBKDF_Argon2NotBuildInAdapter.AddByteString(const AHash: IHash;
  const AOctets: THashLibByteArray);
begin
  if (AOctets <> nil) then
  begin
    AddIntToLittleEndian(AHash, System.Length(AOctets));
    AHash.TransformBytes(AOctets, 0, System.Length(AOctets));
  end
  else
  begin
    AddIntToLittleEndian(AHash, 0);
  end;
end;

class function TPBKDF_Argon2NotBuildInAdapter.MakeBlake2BInstanceAndInitialize
  (AHashSize: Int32): IHash;
begin
  Result := TBlake2B.Create(TBlake2BConfig.Create(AHashSize) as IBlake2BConfig);
  Result.Initialize;
end;

class function TPBKDF_Argon2NotBuildInAdapter.GetStartingIndex(const APosition
  : TPosition): Int32;
begin
  if ((APosition.Pass = 0) and (APosition.Slice = 0)) then
  begin
    // we have already generated the first two blocks
    Result := 2;
  end
  else
  begin
    Result := 0;
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.InitializeMemory(AMemoryBlocks: Int32);
var
  LIdx: Int32;
begin
  System.SetLength(FMemory, AMemoryBlocks);
  for LIdx := 0 to System.Pred(System.Length(FMemory)) do
  begin
    FMemory[LIdx] := TBlock.CreateBlock();
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.DoInit(const AParameters
  : IArgon2Parameters);
var
  LMemoryBlocks, LIdx: Int32;
begin
  // 2. Align memory size
  // Minimum memoryBlocks = 8L blocks, where L is the number of lanes */
  LMemoryBlocks := AParameters.Memory;

  if (LMemoryBlocks < (2 * Argon2SyncPoints * AParameters.Lanes)) then
  begin
    LMemoryBlocks := 2 * Argon2SyncPoints * AParameters.Lanes;
  end;

  FSegmentLength := LMemoryBlocks div (FParameters.Lanes * Argon2SyncPoints);
  FLaneLength := FSegmentLength * Argon2SyncPoints;

  // Ensure that all segments have equal length
  LMemoryBlocks := FSegmentLength * (AParameters.Lanes * Argon2SyncPoints);

  InitializeMemory(LMemoryBlocks);

  System.SetLength(FFillers, AParameters.Lanes);
  for LIdx := 0 to System.Pred(AParameters.Lanes) do
  begin
    FFillers[LIdx] := TFillBlock.CreateFillBlock();
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.Reset;
var
  LIdx: Int32;
begin
  // Reset memory.
  for LIdx := 0 to System.Pred(System.Length(FMemory)) do
  begin
    FMemory[LIdx].Clear;
    FMemory[LIdx] := Default(TBlock);
  end;
  FMemory := nil;

  for LIdx := 0 to System.Pred(System.Length(FFillers)) do
  begin
    FFillers[LIdx].AddressBlock.Clear;
    FFillers[LIdx].ZeroBlock.Clear;
    FFillers[LIdx].InputBlock.Clear;
  end;
  FFillers := nil;

  TArrayUtils.ZeroFill(FResult);
end;

function TPBKDF_Argon2NotBuildInAdapter.InitialHash(const AParameters
  : IArgon2Parameters; AOutputLength: Int32; const APassword: THashLibByteArray)
  : THashLibByteArray;
var
  LBlake2B: IHash;
begin
  LBlake2B := MakeBlake2BInstanceAndInitialize(Argon2PrehashDigestLength);

  AddIntToLittleEndian(LBlake2B, AParameters.Lanes);
  AddIntToLittleEndian(LBlake2B, AOutputLength);
  AddIntToLittleEndian(LBlake2B, AParameters.Memory);
  AddIntToLittleEndian(LBlake2B, AParameters.Iterations);
  AddIntToLittleEndian(LBlake2B, Int32(AParameters.Version));
  AddIntToLittleEndian(LBlake2B, Int32(AParameters.&Type));

  AddByteString(LBlake2B, APassword);
  AddByteString(LBlake2B, AParameters.Salt);
  AddByteString(LBlake2B, AParameters.Secret);
  AddByteString(LBlake2B, AParameters.Additional);

  Result := LBlake2B.TransformFinal.GetBytes();
end;

function TPBKDF_Argon2NotBuildInAdapter.GetInitialHashLong(const AInitialHash,
  AAppendix: THashLibByteArray): THashLibByteArray;
begin
  System.SetLength(Result, Argon2PrehashSeedLength);
  System.Move(AInitialHash[0], Result[0], Argon2PrehashDigestLength *
    System.SizeOf(Byte));
  System.Move(AAppendix[0], Result[Argon2PrehashDigestLength],
    4 * System.SizeOf(Byte));
end;

function TPBKDF_Argon2NotBuildInAdapter.Hash(const AInput: THashLibByteArray;
  AOutputLength: Int32): THashLibByteArray;
var
  LOutlenBytes, LOutBuffer: THashLibByteArray;
  LBlake2BLength, LRoundCount, LPosition, LIdx, LLastLength: Int32;
  LBlake2B: IHash;
begin
  System.SetLength(Result, AOutputLength);
  LOutlenBytes := TConverters.ReadUInt32AsBytesLE(UInt32(AOutputLength));

  LBlake2BLength := 64;

  if (AOutputLength <= LBlake2BLength) then
  begin

    LBlake2B := MakeBlake2BInstanceAndInitialize(AOutputLength);

    LBlake2B.TransformBytes(LOutlenBytes, 0, System.Length(LOutlenBytes));
    LBlake2B.TransformBytes(AInput, 0, System.Length(AInput));
    Result := LBlake2B.TransformFinal.GetBytes();
  end
  else
  begin

    LBlake2B := MakeBlake2BInstanceAndInitialize(LBlake2BLength);

    System.SetLength(LOutBuffer, LBlake2BLength);

    // V1
    LBlake2B.TransformBytes(LOutlenBytes, 0, System.Length(LOutlenBytes));
    LBlake2B.TransformBytes(AInput, 0, System.Length(AInput));
    LOutBuffer := LBlake2B.TransformFinal.GetBytes();

    System.Move(LOutBuffer[0], Result[0], (LBlake2BLength div 2) *
      System.SizeOf(Byte));

    LRoundCount := ((AOutputLength + 31) div 32) - 2;

    LPosition := LBlake2BLength div 2;

    LIdx := 2;

    while LIdx <= LRoundCount do
    begin
      // V2 to Vr
      LBlake2B.TransformBytes(LOutBuffer, 0, System.Length(LOutBuffer));
      LOutBuffer := LBlake2B.TransformFinal.GetBytes();

      System.Move(LOutBuffer[0], Result[LPosition], (LBlake2BLength div 2) *
        System.SizeOf(Byte));

      System.Inc(LIdx);
      LPosition := LPosition + (LBlake2BLength div 2);
    end;

    LLastLength := AOutputLength - (32 * LRoundCount);

    // Vr+1

    LBlake2B := MakeBlake2BInstanceAndInitialize(LLastLength);

    LBlake2B.TransformBytes(LOutBuffer, 0, System.Length(LOutBuffer));
    LOutBuffer := LBlake2B.TransformFinal.GetBytes();
    System.Move(LOutBuffer[0], Result[LPosition],
      LLastLength * System.SizeOf(Byte));
  end;
{$IFDEF DEBUG}
  System.Assert(System.Length(Result) = AOutputLength);
{$ENDIF DEBUG}
end;

procedure TPBKDF_Argon2NotBuildInAdapter.Digest(AOutputLength: Int32);
var
  LIdx, LLastBlockInLane: Int32;
  LFinalBlockBytes: THashLibByteArray;
  LFinalBlock: TBlock;
begin
  LFinalBlock := FMemory[FLaneLength - 1];

  // XOR the last blocks
  for LIdx := 1 to System.Pred(FParameters.Lanes) do
  begin
    LLastBlockInLane := (LIdx * FLaneLength) + (FLaneLength - 1);
    LFinalBlock.XorWith(FMemory[LLastBlockInLane]);
  end;

  LFinalBlockBytes := LFinalBlock.ToBytes();

  FResult := Hash(LFinalBlockBytes, AOutputLength);
end;

procedure TPBKDF_Argon2NotBuildInAdapter.FillFirstBlocks(const AInitialHash
  : THashLibByteArray);
var
  LZeroBytes, LOneBytes, LInitialHashWithZeros, LInitialHashWithOnes,
    LBlockHashBytes: THashLibByteArray;
  LIdx: Int32;
begin

  LZeroBytes := THashLibByteArray.Create(0, 0, 0, 0);
  LOneBytes := THashLibByteArray.Create(1, 0, 0, 0);

  LInitialHashWithZeros := GetInitialHashLong(AInitialHash, LZeroBytes);
  LInitialHashWithOnes := GetInitialHashLong(AInitialHash, LOneBytes);

  for LIdx := 0 to System.Pred(FParameters.Lanes) do
  begin
    TConverters.ReadUInt32AsBytesLE(UInt32(LIdx), LInitialHashWithZeros,
      Argon2PrehashDigestLength + 4);
    TConverters.ReadUInt32AsBytesLE(UInt32(LIdx), LInitialHashWithOnes,
      Argon2PrehashDigestLength + 4);

    LBlockHashBytes := Hash(LInitialHashWithZeros, Argon2BlockSize);
    FMemory[LIdx * FLaneLength].FromBytes(LBlockHashBytes);

    LBlockHashBytes := Hash(LInitialHashWithOnes, Argon2BlockSize);
    FMemory[(LIdx * FLaneLength) + 1].FromBytes(LBlockHashBytes);
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.IsDataIndependentAddressing
  (const APosition: TPosition): Boolean;
begin
  Result := (FParameters.&Type = TArgon2Type.a2tARGON2_i) or
    ((FParameters.&Type = TArgon2Type.a2tARGON2_id) and (APosition.Pass = 0)
    and (APosition.Slice < (Argon2SyncPoints div 2)));
end;

procedure TPBKDF_Argon2NotBuildInAdapter.NextAddresses(var AFiller
  : TFillBlock; var AZeroBlock, AInputBlock, AAddressBlock: TBlock);
begin
  System.Inc(AInputBlock.V[6]);
  AFiller.FillBlock(AZeroBlock, AInputBlock, AAddressBlock, False);
  AFiller.FillBlock(AZeroBlock, AAddressBlock, AAddressBlock, False);
end;

function TPBKDF_Argon2NotBuildInAdapter.IntToUInt64(AValue: Int32): UInt64;
begin
  Result := UInt64((AValue and UInt32($FFFFFFFF)))
end;

procedure TPBKDF_Argon2NotBuildInAdapter.InitAddressBlocks
  (var AFiller: TFillBlock; const APosition: TPosition;
  var AZeroBlock, AInputBlock, AAddressBlock: TBlock);
begin
  AInputBlock.V[0] := IntToUInt64(APosition.Pass);
  AInputBlock.V[1] := IntToUInt64(APosition.Lane);
  AInputBlock.V[2] := IntToUInt64(APosition.Slice);
  AInputBlock.V[3] := IntToUInt64(System.Length(FMemory));
  AInputBlock.V[4] := IntToUInt64(FParameters.Iterations);
  AInputBlock.V[5] := IntToUInt64(Int32(FParameters.&Type));

  if ((APosition.Pass = 0) and (APosition.Slice = 0)) then
  begin
    NextAddresses(AFiller, AZeroBlock, AInputBlock, AAddressBlock);
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.GetPseudoRandom(var AFiller
  : TFillBlock; const APosition: TPosition; var AAddressBlock, AInputBlock,
  AZeroBlock: TBlock; APrevOffset: Int32;
  ADataIndependentAddressing: Boolean): UInt64;
begin
  if (ADataIndependentAddressing) then
  begin
    if (APosition.Index mod Argon2AddressesInBlock = 0) then
    begin
      NextAddresses(AFiller, AZeroBlock, AInputBlock, AAddressBlock);
    end;
    Result := AAddressBlock.V[APosition.Index mod Argon2AddressesInBlock];
    Exit;
  end
  else
  begin
    Result := FMemory[APrevOffset].V[0];
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.GetRefLane(const APosition: TPosition;
  APseudoRandom: UInt64): Int32;
var
  LRefLane: Int32;
begin
  LRefLane := Int32((APseudoRandom shr 32) mod UInt64(FParameters.Lanes));

  if ((APosition.Pass = 0) and (APosition.Slice = 0)) then
  begin
    // Can not reference other lanes yet
    LRefLane := APosition.Lane;
  end;
  Result := LRefLane;
end;

function TPBKDF_Argon2NotBuildInAdapter.GetRefColumn(const APosition: TPosition;
  APseudoRandom: UInt64; ASameLane: Boolean): Int32;
var
  LReferenceAreaSize, LStartPosition, LTemp: Int32;
  LRelativePosition: UInt64;
begin

  if (APosition.Pass = 0) then
  begin
    LStartPosition := 0;

    if (ASameLane) then
    begin
      // The same lane => add current segment
      LReferenceAreaSize := ((APosition.Slice) * FSegmentLength) +
        APosition.Index - 1;
    end
    else
    begin
      if (APosition.Index = 0) then
      begin
        LTemp := -1;
      end
      else
      begin
        LTemp := 0;
      end;
      LReferenceAreaSize := (APosition.Slice * FSegmentLength) + LTemp;
    end
  end
  else
  begin
    LStartPosition := ((APosition.Slice + 1) * FSegmentLength) mod FLaneLength;

    if (ASameLane) then
    begin
      LReferenceAreaSize := FLaneLength - FSegmentLength + APosition.Index - 1;
    end
    else
    begin
      if (APosition.Index = 0) then
      begin
        LTemp := -1;
      end
      else
      begin
        LTemp := 0;
      end;
      LReferenceAreaSize := FLaneLength - FSegmentLength + LTemp;
    end;
  end;

  LRelativePosition := APseudoRandom and UInt32($FFFFFFFF);
  LRelativePosition := (LRelativePosition * LRelativePosition) shr 32;
  LRelativePosition := UInt64(LReferenceAreaSize) - 1 -
    UInt64((UInt64(LReferenceAreaSize) * LRelativePosition) shr 32);

  Result := Int32(UInt64(LStartPosition) + LRelativePosition) mod FLaneLength;
end;

function TPBKDF_Argon2NotBuildInAdapter.IsWithXor(const APosition
  : TPosition): Boolean;
begin
  Result := not((APosition.Pass = 0) or
    (FParameters.Version = TArgon2Version.a2vARGON2_VERSION_10));
end;

function TPBKDF_Argon2NotBuildInAdapter.GetPrevOffset(ACurrentOffset
  : Int32): Int32;
begin
  if (ACurrentOffset mod FLaneLength = 0) then
  begin
    // Last block in this lane
    Result := ACurrentOffset + FLaneLength - 1;
    Exit;
  end
  else
  begin
    // Previous block
    Result := ACurrentOffset - 1;
    Exit;
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.RotatePrevOffset(ACurrentOffset,
  APrevOffset: Int32): Int32;
begin
  if (ACurrentOffset mod FLaneLength = 1) then
  begin
    APrevOffset := ACurrentOffset - 1;
  end;
  Result := APrevOffset;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.Initialize(const APassword
  : THashLibByteArray; AOutputLength: Int32);
var
  LInitialHash: THashLibByteArray;
begin
  LInitialHash := InitialHash(FParameters, AOutputLength, APassword);
  FillFirstBlocks(LInitialHash);
end;

procedure TPBKDF_Argon2NotBuildInAdapter.FillSegment(ALane: Int32;
  var APosition: TPosition);
var
  LAddressBlock, LInputBlock, LZeroBlock, LPrevBlock, LRefBlock,
    LCurrentBlock: TBlock;
  LDataIndependentAddressing, LWithXor: Boolean;
  LStartingIndex, LCurrentOffset, LPrevOffset, LRefLane, LRefColumn: Int32;
  LPseudoRandom: UInt64;
  LFiller: TFillBlock;
begin
  APosition.Lane := ALane;
  LFiller := FFillers[ALane];
  LDataIndependentAddressing := IsDataIndependentAddressing(APosition);
  LStartingIndex := GetStartingIndex(APosition);
  LCurrentOffset := (APosition.Lane * FLaneLength) +
    (APosition.Slice * FSegmentLength) + LStartingIndex;
  LPrevOffset := GetPrevOffset(LCurrentOffset);

  LAddressBlock := Default(TBlock);
  LInputBlock := Default(TBlock);
  LZeroBlock := Default(TBlock);

  if (LDataIndependentAddressing) then
  begin
    LAddressBlock := LFiller.AddressBlock.Clear();
    LZeroBlock := LFiller.ZeroBlock.Clear();
    LInputBlock := LFiller.InputBlock.Clear();

    InitAddressBlocks(LFiller, APosition, LZeroBlock, LInputBlock,
      LAddressBlock);
  end;

  APosition.Index := LStartingIndex;

  while APosition.Index < FSegmentLength do
  begin
    LPrevOffset := RotatePrevOffset(LCurrentOffset, LPrevOffset);

    LPseudoRandom := GetPseudoRandom(LFiller, APosition, LAddressBlock,
      LInputBlock, LZeroBlock, LPrevOffset, LDataIndependentAddressing);
    LRefLane := GetRefLane(APosition, LPseudoRandom);
    LRefColumn := GetRefColumn(APosition, LPseudoRandom,
      LRefLane = APosition.Lane);

    // 2 Creating a new block
    LPrevBlock := FMemory[LPrevOffset];
    LRefBlock := FMemory[(((FLaneLength) * LRefLane) + LRefColumn)];
    LCurrentBlock := FMemory[LCurrentOffset];

    LWithXor := IsWithXor(APosition);
    LFiller.FillBlock(LPrevBlock, LRefBlock, LCurrentBlock, LWithXor);

    System.Inc(APosition.Index);
    System.Inc(LCurrentOffset);
    System.Inc(LPrevOffset);
  end;
end;

procedure TPBKDF_Argon2NotBuildInAdapter.FillSegmentForLane(ALane: Int32;
  const ABasePosition: TPosition);
var
  LPos: TPosition;
begin
  LPos := ABasePosition;
  FillSegment(ALane, LPos);
end;

procedure TPBKDF_Argon2NotBuildInAdapter.DoParallelFillMemoryBlocks;
var
  LPass, LSlice: Int32;
  LIterations, LLanes: Int32;
  LBasePosition: TPosition;
{$IFNDEF HASHLIB_USE_PPL}
  LLane: Int32;
{$ENDIF}
begin
  LIterations := FParameters.Iterations;
  LLanes      := FParameters.Lanes;

  for LPass := 0 to System.Pred(LIterations) do
  begin
    for LSlice := 0 to System.Pred(Argon2SyncPoints) do
    begin
      LBasePosition := TPosition.CreatePosition();
      LBasePosition.Update(LPass, 0, LSlice, 0);

{$IFDEF HASHLIB_USE_PPL}
      TParallel.&For(
        0,
        LLanes - 1,
        procedure(ALane: Integer)
        begin
          FillSegmentForLane(ALane, LBasePosition);
        end
      );
{$ELSE}
      for LLane := 0 to System.Pred(LLanes) do
      begin
        FillSegmentForLane(LLane, LBasePosition);
      end;
{$ENDIF HASHLIB_USE_PPL}
    end;
  end;
end;

function TPBKDF_Argon2NotBuildInAdapter.GetBytes(AByteCount: Int32)
  : THashLibByteArray;
begin
  if (AByteCount <= MinOutLen) then
  begin
    raise EArgumentHashLibException.CreateResFmt(@SInvalidOutputByteCount,
      [MinOutLen]);
  end;

  Initialize(FPassword, AByteCount);
  DoParallelFillMemoryBlocks;
  Digest(AByteCount);
  System.SetLength(Result, AByteCount);
  System.Move(FResult[0], Result[0], AByteCount * System.SizeOf(Byte));

  Reset();
end;

procedure TPBKDF_Argon2NotBuildInAdapter.Clear();
begin
  TArrayUtils.ZeroFill(FPassword);
end;

constructor TPBKDF_Argon2NotBuildInAdapter.Create(const APassword
  : THashLibByteArray; const AParameters: IArgon2Parameters);
begin
  inherited Create();
  ValidatePBKDF_Argon2Inputs(AParameters);
  FPassword := System.Copy(APassword);
  FParameters := AParameters;

  if (FParameters.Lanes < MinParallelism) then
  begin
    raise EArgumentInvalidHashLibException.CreateResFmt(@SLanesTooSmall,
      [MinParallelism]);
  end
  else if (FParameters.Lanes > MaxParallelism) then
  begin
    raise EArgumentInvalidHashLibException.CreateResFmt(@SLanesTooBig,
      [MaxParallelism]);
  end
  else if (FParameters.Memory < (2 * FParameters.Lanes)) then
  begin
    raise EArgumentInvalidHashLibException.CreateResFmt(@SMemoryTooSmall,
      [(2 * FParameters.Lanes), (2 * FParameters.Lanes)]);
  end
  else if (FParameters.Iterations < MinIterations) then
  begin
    raise EArgumentInvalidHashLibException.CreateResFmt(@SIterationsTooSmall,
      [MinIterations]);
  end;

  DoInit(AParameters);
end;

destructor TPBKDF_Argon2NotBuildInAdapter.Destroy;
begin
  Clear();
  inherited Destroy;
end;

end.

