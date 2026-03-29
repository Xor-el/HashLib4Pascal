unit HlpBlake3;

{$I ..\Include\HashLib.inc}

interface

uses
  Math,
  SysUtils,
  HlpHash,
  HlpHashResult,
  HlpIHashResult,
  HlpIHash,
  HlpIHashInfo,
  HlpHashSize,
  HlpConverters,
  HlpArrayUtils,
  HlpHashLibTypes;

resourcestring
  SInvalidXOFSize =
    'XOFSize in Bits must be Multiples of 8 and be Greater than Zero Bytes';
  SInvalidKeyLength = '"Key" Length Must Not Be Greater Than %d, "%d"';
  SMaximumOutputLengthExceeded = '"Maximum Output Length is 2^64 Bytes';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SOutputLengthInvalid = 'Output Length is above the Digest Length';
  SWritetoXofAfterReadError = '"%s" Write to Xof after Read not Allowed';

type
  TBlake3 = class(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private
  const
    ChunkSize = Int32(1024);
    BlockSizeInBytes = Int32(64);
    KeyLengthInBytes = Int32(32);

    FlagChunkStart = UInt32(1 shl 0);
    FlagChunkEnd = UInt32(1 shl 1);
    FlagParent = UInt32(1 shl 2);
    FlagRoot = UInt32(1 shl 3);
    FlagKeyedHash = UInt32(1 shl 4);
    FlagDeriveKeyContext = UInt32(1 shl 5);
    FlagDeriveKeyMaterial = UInt32(1 shl 6);

    // maximum size in bytes this digest output reader can produce
    MaxDigestLengthInBytes = UInt64(System.High(UInt64));

    IV: array [0 .. 7] of UInt32 = ($6A09E667, $BB67AE85, $3C6EF372, $A54FF53A,
      $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19);

    // A TBlake3Node represents a chunk or parent in the BLAKE3 Merkle tree. In BLAKE3
    // terminology, the elements of the bottom layer (aka "leaves") of the tree are
    // called chunk nodes, and the elements of upper layers (aka "interior nodes")
    // are called parent nodes.
    //
    // Computing a BLAKE3 hash involves splitting the input into chunk nodes, then
    // repeatedly merging these nodes into parent nodes, until only a single "root"
    // node remains. The root node can then be used to generate up to 2^64 - 1 bytes
    // of pseudorandom output.
  type
    TBlake3Node = record
    private
    var
      // the chaining value from the previous state
      CV: array [0 .. 7] of UInt32;
      // the current state
      Block: array [0 .. 15] of UInt32;
      Counter: UInt64;
      BlockLen, Flags: UInt32;

      function Clone(): TBlake3Node;

      // ChainingValue returns the first 8 words of the compressed node. This is used
      // in two places. First, when a chunk node is being constructed, its cv is
      // overwritten with this value after each block of input is processed. Second,
      // when two nodes are merged into a parent, each of their chaining values
      // supplies half of the new node's block.
      procedure ChainingValue(AResult: PCardinal); inline;

      // compress is the core hash function, generating 16 pseudorandom words from a
      // node.
      // NOTE: we unroll all of the rounds, as well as the permutations that occur
      // between rounds.
      procedure Compress(APtrState: PCardinal);

      class function DefaultBlake3Node(): TBlake3Node; static;

    public
      class function ParentNode(ALeft, ARight, AKey: PCardinal;
        AFlags: UInt32): TBlake3Node; static;
    end;

    // TBlake3ChunkState manages the state involved in hashing a single chunk of input.
  type
    TBlake3ChunkState = record
    private
    var
      N: TBlake3Node;
      Block: array [0 .. BlockSizeInBytes - 1] of Byte;
      BlockLen, BytesConsumed: Int32;

      function Clone(): TBlake3ChunkState;

      // ChunkCounter is the index of this chunk, i.e. the number of chunks that have
      // been processed prior to this one.
      function ChunkCounter(): UInt64; inline;

      function Complete(): Boolean; inline;

      // node returns a node containing the chunkState's current state, with the
      // ChunkEnd flag set.
      function Node(): TBlake3Node;

      // update incorporates input into the chunkState.
      procedure Update(APtrData: PByte; ADataLength: Int32);

      class function DefaultBlake3ChunkState(): TBlake3ChunkState; static;

    public
      class function CreateBlake3ChunkState(AIV: PCardinal;
        AChunkCounter: UInt64; AFlags: UInt32): TBlake3ChunkState; static;
    end;

    // A TBlake3OutputReader produces a stream of 2^64 - 1 pseudorandom output
    // bytes.
  type
    TBlake3OutputReader = record
    private
    var
      N: TBlake3Node;
      Block: array [0 .. BlockSizeInBytes - 1] of Byte;
      Offset: UInt64;

      function Clone(): TBlake3OutputReader;

      procedure Read(const ADestination: THashLibByteArray;
        ADestinationOffset, AOutputLength: UInt64);

      class function DefaultBlake3OutputReader(): TBlake3OutputReader; static;

    end;

  function RootNode(): TBlake3Node;

  function HasSubTreeAtHeight(AIdx: Int32): Boolean; inline;

  // AddChunkChainingValue appends a chunk to the right edge of the Merkle tree.
  procedure AddChunkChainingValue(ACV: PCardinal); inline;

  class function Len64(AValue: UInt64): Int32; static;

  class function TrailingZeros64(AValue: UInt64): Int32; static;

  strict protected
  var
    FCS: TBlake3ChunkState;
    FOutputReader: TBlake3OutputReader;
    FKey: array [0 .. 7] of UInt32;
    FFlags: UInt32;

    // log(n) set of Merkle subtree roots, at most one per height.
    // stack [54][8]uint32
    FStack: array [0 .. 53, 0 .. 7] of UInt32; // 2^54 * chunkSize = 2^64
    // bit vector indicating which stack elems are valid; also number of chunks added
    FUsed: UInt64;

    procedure Finish();
    function GetName: String; override;

    procedure InternalDoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64); inline;

    constructor Create(AHashSize: Int32;
      const AKey: THashLibByteArray); overload;

    constructor CreateInternal(AHashSize: Int32;
      AKeyWords: PCardinal; AFlags: UInt32);

  public
    constructor Create(AHashSize: THashSize = THashSize.Size256;
      const AKey: THashLibByteArray = nil); overload;
    procedure Initialize; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;

    // DeriveKey derives a subkey from ctx and srcKey. ctx should be hardcoded,
    // globally unique, and application-specific. A good format for ctx strings is:
    //
    // [application] [commit timestamp] [purpose]
    //
    // e.g.:
    //
    // example.com 2019-12-25 16:18:03 session tokens v1
    //
    // The purpose of these requirements is to ensure that an attacker cannot trick
    // two different applications into using the same context string.
    class procedure DeriveKey(const ASrcKey, ACtx,
      ASubKey: THashLibByteArray); static;

  end;

type
  TBlake3XOF = class sealed(TBlake3, IXOF)
  strict private
  var
    FXOFSizeInBits: UInt64;

    function GetXOFSizeInBits: UInt64; inline;
    procedure SetXOFSizeInBits(AXofSizeInBits: UInt64); inline;
    function SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;

    function GetResult(): THashLibByteArray;

  strict protected
  var
    FFinalized: Boolean;

    function GetName: String; override;
    property XOFSizeInBits: UInt64 read GetXOFSizeInBits write SetXOFSizeInBits;

  public

    constructor Create(AHashSize: Int32;
      const AKey: THashLibByteArray); overload;

    constructor Create(AHashSize: Int32; AKeyWords: PCardinal;
      AFlags: UInt32); overload;

    procedure Initialize(); override;
    function Clone(): IHash; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal(): IHashResult; override;

    procedure DoOutput(const ADestination: THashLibByteArray;
      ADestinationOffset, AOutputLength: UInt64);

  end;

implementation

uses
  HlpBlake3Dispatch;

{ TBlake3.TBlake3Node }

class function TBlake3.TBlake3Node.DefaultBlake3Node: TBlake3Node;
begin
  Result := Default(TBlake3Node);
  Result.Counter := 0;
  Result.BlockLen := 0;
  Result.Flags := 0;
end;

function TBlake3.TBlake3Node.Clone: TBlake3Node;
begin
  Result := DefaultBlake3Node();
  System.Move(CV, Result.CV, System.SizeOf(CV));
  System.Move(Block, Result.Block, System.SizeOf(Block));
  Result.Counter := Counter;
  Result.BlockLen := BlockLen;
  Result.Flags := Flags;
end;

procedure TBlake3.TBlake3Node.Compress(APtrState: PCardinal);
var
  LCounterFlags: array[0..3] of UInt32;
begin
  LCounterFlags[0] := UInt32(Counter);
  LCounterFlags[1] := UInt32(Counter shr 32);
  LCounterFlags[2] := BlockLen;
  LCounterFlags[3] := Flags;
  Blake3_Compress(APtrState, @Block[0], @CV[0], @LCounterFlags[0]);
end;

procedure TBlake3.TBlake3Node.ChainingValue(AResult: PCardinal);
var
  LFull: array [0 .. 15] of UInt32;
begin
  Compress(@LFull[0]);
  System.Move(LFull, AResult[0], 8 * System.SizeOf(UInt32));
end;

class function TBlake3.TBlake3Node.ParentNode(ALeft, ARight,
  AKey: PCardinal; AFlags: UInt32): TBlake3Node;
begin
  Result := DefaultBlake3Node();
  System.Move(AKey^, Result.CV[0], 8 * System.SizeOf(UInt32));
  System.Move(ALeft^, Result.Block[0], 8 * System.SizeOf(UInt32));
  System.Move(ARight^, Result.Block[8], 8 * System.SizeOf(UInt32));
  Result.Counter := 0;
  Result.BlockLen := BlockSizeInBytes;
  Result.Flags := AFlags or FlagParent;
end;

{ TBlake3.TBlake3ChunkState }

class function TBlake3.TBlake3ChunkState.DefaultBlake3ChunkState
  : TBlake3ChunkState;
begin
  Result := Default(TBlake3ChunkState);
  Result.N := TBlake3Node.DefaultBlake3Node;
  Result.BlockLen := 0;
  Result.BytesConsumed := 0;
end;

function TBlake3.TBlake3ChunkState.Complete: Boolean;
begin
  Result := BytesConsumed = ChunkSize;
end;

class function TBlake3.TBlake3ChunkState.CreateBlake3ChunkState
  (AIV: PCardinal; AChunkCounter: UInt64; AFlags: UInt32)
  : TBlake3ChunkState;
begin
  Result := DefaultBlake3ChunkState;
  System.Move(AIV^, Result.N.CV[0], 8 * System.SizeOf(UInt32));
  Result.N.Counter := AChunkCounter;
  Result.N.BlockLen := BlockSizeInBytes;
  // compress the first block with the start flag set
  Result.N.Flags := AFlags or FlagChunkStart;
end;

function TBlake3.TBlake3ChunkState.ChunkCounter: UInt64;
begin
  Result := N.Counter;
end;

function TBlake3.TBlake3ChunkState.Clone: TBlake3ChunkState;
begin
  Result := DefaultBlake3ChunkState();
  Result.N := N.Clone();
  System.Move(Block, Result.Block, System.SizeOf(Block));
  Result.BlockLen := BlockLen;
  Result.BytesConsumed := BytesConsumed;
end;

function TBlake3.TBlake3ChunkState.Node: TBlake3Node;
begin
  Result := N.Clone();
  // pad the remaining space in the block with zeros
  TArrayUtils.FillMemory(@(Block[BlockLen]), (Int64(System.Length(Block)) - BlockLen) * System.SizeOf(Byte), 0);
  TConverters.le32_copy(@(Block[0]), 0, @(Result.Block[0]), 0, BlockSizeInBytes);
  Result.BlockLen := UInt32(BlockLen);
  Result.Flags := Result.Flags or FlagChunkEnd;
end;

procedure TBlake3.TBlake3ChunkState.Update(APtrData: PByte; ADataLength: Int32);
var
  LCount, LIndex: Int32;
  LCardinalPtr, LCVPtr: PCardinal;
  LBytePtr: PByte;
begin
  LIndex := 0;
  LBytePtr := @(Block[0]);
  LCardinalPtr := @(N.Block[0]);
  LCVPtr := @(N.CV[0]);

  while ADataLength > 0 do
  begin
    // If the block buffer is full, compress it and clear it. More
    // input is coming, so this compression is not flagChunkEnd.
    if BlockLen = BlockSizeInBytes then
    begin
      // copy the chunk block (bytes) into the node block and chain it.
      TConverters.le32_copy(LBytePtr, 0, LCardinalPtr, 0, BlockSizeInBytes);
      N.ChainingValue(LCVPtr);
      // clear the start flag for all but the first block
      N.Flags := N.Flags and (N.Flags xor FlagChunkStart);
      BlockLen := 0;
    end;

    // Copy input bytes into the chunk block.
    LCount := Min(BlockSizeInBytes - BlockLen, ADataLength);
    System.Move(APtrData[LIndex], LBytePtr[BlockLen], LCount);

    System.Inc(BlockLen, LCount);
    System.Inc(BytesConsumed, LCount);
    System.Inc(LIndex, LCount);
    System.Dec(ADataLength, LCount);
  end;
end;

{ TBlake3.TBlake3OutputReader }

class function TBlake3.TBlake3OutputReader.DefaultBlake3OutputReader
  : TBlake3OutputReader;
begin
  Result := Default(TBlake3OutputReader);
  Result.N := TBlake3Node.DefaultBlake3Node();
  Result.Offset := 0;
end;

function TBlake3.TBlake3OutputReader.Clone: TBlake3OutputReader;
begin
  Result := DefaultBlake3OutputReader();
  Result.N := N.Clone();
  System.Move(Block, Result.Block, System.SizeOf(Block));
  Result.Offset := Offset;
end;

procedure TBlake3.TBlake3OutputReader.
  Read(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
var
  LRemainder, LBlockOffset, LDiff: UInt64;
  LWords: array [0 .. 15] of UInt32;
  LCount: Int32;
  LPtrCardinal: PCardinal;
  LPtrByte: PByte;
begin
  if Offset = MaxDigestLengthInBytes then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes
      (@SMaximumOutputLengthExceeded);
  end
  else
  begin
    LRemainder := MaxDigestLengthInBytes - Offset;
    if AOutputLength > LRemainder then
    begin
      AOutputLength := LRemainder;
    end;
  end;

  LPtrCardinal := @(LWords[0]);
  LPtrByte := @(Block[0]);

  while AOutputLength > 0 do
  begin
    if (Offset and (BlockSizeInBytes - 1)) = 0 then
    begin
      N.Counter := Offset div UInt64(BlockSizeInBytes);
      N.Compress(LPtrCardinal);
      TConverters.le32_copy(LPtrCardinal, 0, LPtrByte, 0, BlockSizeInBytes);
    end;

    LBlockOffset := Offset and (BlockSizeInBytes - 1);

    LDiff := UInt64(System.Length(Block)) - LBlockOffset;

    // Math.Min
    if AOutputLength < LDiff then
    begin
      LCount := AOutputLength
    end
    else
    begin
      LCount := LDiff;
    end;

    System.Move(Block[LBlockOffset], ADestination[ADestinationOffset], LCount);

    System.Dec(AOutputLength, LCount);
    System.Inc(ADestinationOffset, LCount);
    System.Inc(Offset, LCount);
  end;
end;

{ TBlake3 }

// Len64 returns the minimum number of bits required to represent x; zero yields 0.
class function TBlake3.Len64(AValue: UInt64): Int32;

  function Len8(AValue: Byte): Byte; inline;
  begin
    Result := 0;
    while AValue <> 0 do
    begin
      AValue := AValue shr 1;
      System.Inc(Result);
    end;
  end;

begin
  Result := 0;
  if AValue >= (1 shl 32) then
  begin
    AValue := AValue shr 32;
    Result := 32;
  end;
  if AValue >= (1 shl 16) then
  begin
    AValue := AValue shr 16;
    Result := Result + 16;
  end;
  if AValue >= (1 shl 8) then
  begin
    AValue := AValue shr 8;
    Result := Result + 8;
  end;
  Result := Result + Int32(Len8(AValue));
end;

class function TBlake3.TrailingZeros64(AValue: UInt64): Int32;
begin
  if AValue = 0 then
  begin
    Result := 64;
    Exit;
  end;
{$IFDEF FPC}
  Result := Int32(BsfQWord(AValue));
{$ELSE}
  Result := 0;
  while ((AValue and 1) = 0) do
  begin
    AValue := AValue shr 1;
    System.Inc(Result);
  end;
{$ENDIF FPC}
end;

constructor TBlake3.CreateInternal(AHashSize: Int32;
  AKeyWords: PCardinal; AFlags: UInt32);
begin
  inherited Create(AHashSize, BlockSizeInBytes);
  System.Move(AKeyWords^, FKey[0], 8 * System.SizeOf(UInt32));
  FFlags := AFlags;
end;

constructor TBlake3.Create(AHashSize: Int32; const AKey: THashLibByteArray);
var
  LKeyWords: array [0 .. 7] of UInt32;
  LKeyLength: Int32;
begin
  if AKey = nil then
  begin
    System.Move(IV, LKeyWords[0], System.SizeOf(IV));
    CreateInternal(AHashSize, @LKeyWords[0], 0);
  end
  else
  begin
    LKeyLength := System.Length(AKey);
    if (LKeyLength <> KeyLengthInBytes) then
    begin
      raise EArgumentOutOfRangeHashLibException.CreateResFmt(@SInvalidKeyLength,
        [KeyLengthInBytes, LKeyLength]);
    end;
    TConverters.le32_copy(PByte(AKey), 0, @LKeyWords[0], 0, LKeyLength);
    CreateInternal(AHashSize, @LKeyWords[0], FlagKeyedHash);
  end;
end;

constructor TBlake3.Create(AHashSize: THashSize; const AKey: THashLibByteArray);
begin
  Create(Int32(AHashSize), AKey);
end;

procedure TBlake3.Initialize;
begin
  FCS := TBlake3ChunkState.CreateBlake3ChunkState(@FKey[0], 0, FFlags);
  FOutputReader := TBlake3OutputReader.DefaultBlake3OutputReader();
  FillChar(FStack, System.SizeOf(FStack), 0);
  FUsed := 0;
end;

procedure TBlake3.InternalDoOutput(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
begin
  FOutputReader.Read(ADestination, ADestinationOffset, AOutputLength);
end;

function TBlake3.Clone: IHash;
var
  LHashInstance: TBlake3;
begin
  LHashInstance := TBlake3.CreateInternal(HashSize, @FKey[0], FFlags);
  LHashInstance.FCS := FCS.Clone();
  LHashInstance.FOutputReader := FOutputReader.Clone();
  System.Move(FStack, LHashInstance.FStack, System.SizeOf(FStack));
  LHashInstance.FUsed := FUsed;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

procedure TBlake3.Finish;
begin
  FOutputReader.N := RootNode();
end;

function TBlake3.GetName: String;
begin
  Result := Format('%s_%u', [Self.ClassName, Self.HashSize * 8]);
end;

function TBlake3.HasSubTreeAtHeight(AIdx: Int32): Boolean;
begin
  Result := (FUsed and (1 shl AIdx)) <> 0;
end;

procedure TBlake3.AddChunkChainingValue(ACV: PCardinal);
var
  LIdx: Int32;
begin
  // seek to first open stack slot, merging subtrees as we go
  LIdx := 0;
  while HasSubTreeAtHeight(LIdx) do
  begin
    TBlake3Node.ParentNode(@FStack[LIdx, 0], ACV, @FKey[0], FFlags)
      .ChainingValue(ACV);
    System.Inc(LIdx);
  end;
  System.Move(ACV^, FStack[LIdx, 0], 8 * System.SizeOf(UInt32));
  System.Inc(FUsed);
end;

function TBlake3.RootNode: TBlake3Node;
var
  LIdx, LTrailingZeros64, LLen64: Int32;
  LTemp: array [0 .. 7] of UInt32;
  LPtrTemp: PCardinal;
begin
  Result := FCS.Node();
  LPtrTemp := @LTemp[0];

  LTrailingZeros64 := TrailingZeros64(FUsed);
  LLen64 := Len64(FUsed);
  for LIdx := LTrailingZeros64 to System.Pred(LLen64) do
  begin
    if HasSubTreeAtHeight(LIdx) then
    begin
      Result.ChainingValue(LPtrTemp);
      Result := TBlake3Node.ParentNode(@FStack[LIdx, 0], LPtrTemp,
        @FKey[0], FFlags);
    end;
  end;
  Result.Flags := Result.Flags or FlagRoot;
end;

procedure TBlake3.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
var
  LPtrAData: PByte;
  LCV: array [0 .. 7] of UInt32;
  LCVs: array [0 .. 7, 0 .. 7] of UInt32;
  LCount, LParDeg, I, LBatchBytes, LNumChunks: Int32;
  LPtrCV: PCardinal;
begin
  LPtrAData := PByte(AData) + AIndex;
  LPtrCV := @LCV[0];
  LParDeg := Blake3_ParallelDegree;

  // Step 1: Complete any partial chunk to reach a clean boundary
  if (FCS.BytesConsumed > 0) and (ADataLength > 0) then
  begin
    LCount := Min(ChunkSize - FCS.BytesConsumed, ADataLength);
    FCS.Update(LPtrAData, LCount);
    System.Inc(LPtrAData, LCount);
    System.Dec(ADataLength, LCount);
  end;

  // Flush the completed chunk if there's more data to process
  if FCS.Complete() and (ADataLength > 0) then
  begin
    FCS.Node().ChainingValue(LPtrCV);
    AddChunkChainingValue(LPtrCV);
    FCS := TBlake3ChunkState.CreateBlake3ChunkState(@FKey[0],
      FCS.ChunkCounter() + 1, FFlags);
  end;

  // Step 2: Process full chunk batches in parallel (4x SSE2, 8x AVX2)
  // At this point FCS.BytesConsumed = 0 whenever ADataLength > 0.
  // Always leave at least ChunkSize bytes for the sequential path so that
  // the last chunk ends up in FCS (required by RootNode's invariant).
  // HashMany cascades internally (e.g. AVX2: hash8 -> hash4 -> scalar).
  while ADataLength >= 2 * ChunkSize do
  begin
    LNumChunks := (ADataLength div ChunkSize) - 1;
    if LNumChunks > LParDeg then
      LNumChunks := LParDeg;
    Blake3_HashMany(LPtrAData, @FKey[0], @LCVs[0, 0],
      LNumChunks, FCS.ChunkCounter(), FFlags);
    for I := 0 to LNumChunks - 1 do
      AddChunkChainingValue(@LCVs[I, 0]);
    LBatchBytes := LNumChunks * ChunkSize;
    FCS := TBlake3ChunkState.CreateBlake3ChunkState(@FKey[0],
      FCS.ChunkCounter() + UInt64(LNumChunks), FFlags);
    System.Inc(LPtrAData, LBatchBytes);
    System.Dec(ADataLength, LBatchBytes);
  end;

  // Step 3: Process remaining data sequentially
  while ADataLength > 0 do
  begin
    if FCS.Complete() then
    begin
      FCS.Node().ChainingValue(LPtrCV);
      AddChunkChainingValue(LPtrCV);
      FCS := TBlake3ChunkState.CreateBlake3ChunkState(@FKey[0],
        FCS.ChunkCounter() + 1, FFlags);
    end;
    LCount := Min(ChunkSize - FCS.BytesConsumed, ADataLength);
    FCS.Update(LPtrAData, LCount);
    System.Inc(LPtrAData, LCount);
    System.Dec(ADataLength, LCount);
  end;
end;

function TBlake3.TransformFinal: IHashResult;
var
  LBuffer: THashLibByteArray;
begin
  Finish();
  System.SetLength(LBuffer, HashSize);
  InternalDoOutput(LBuffer, 0, System.Length(LBuffer));
  Result := THashResult.Create(LBuffer);
  Initialize();
end;

class procedure TBlake3.DeriveKey(const ASrcKey, ACtx,
  ASubKey: THashLibByteArray);
const
  derivationIVLen = Int32(32);
var
  LIVWords: array [0 .. 7] of UInt32;
  LDerivationIV: THashLibByteArray;
  LXof: IXOF;
begin
  System.Move(IV, LIVWords[0], System.SizeOf(IV));
  // construct the derivation Hasher and get the DerivationIV
  LDerivationIV := (TBlake3.CreateInternal(derivationIVLen, @LIVWords[0],
    FlagDeriveKeyContext) as IHash).ComputeBytes(ACtx).GetBytes();
  TConverters.le32_copy(PByte(LDerivationIV), 0, @LIVWords[0], 0,
    KeyLengthInBytes);

  // derive the SubKey
  LXof := TBlake3XOF.Create(32, @LIVWords[0], FlagDeriveKeyMaterial);
  LXof.XOFSizeInBits := System.Length(ASubKey) * 8;
  LXof.Initialize;
  LXof.TransformBytes(ASrcKey);
  LXof.DoOutput(ASubKey, 0, System.Length(ASubKey));
  LXof.Initialize;
end;

{ TBlake3XOF }

function TBlake3XOF.GetXOFSizeInBits: UInt64;
begin
  Result := FXOFSizeInBits;
end;

procedure TBlake3XOF.SetXOFSizeInBits(AXofSizeInBits: UInt64);
begin
  SetXOFSizeInBitsInternal(AXofSizeInBits);
end;

function TBlake3XOF.Clone: IHash;
var
  LHashInstance: TBlake3XOF;
  LXof: IXOF;
begin
  // Xof Cloning
  LXof := TBlake3XOF.Create(HashSize, nil);
  LXof.XOFSizeInBits := XOFSizeInBits;

  // Blake3XOF Cloning
  LHashInstance := LXof as TBlake3XOF;
  LHashInstance.FFinalized := FFinalized;

  // Internal Blake3 Cloning
  LHashInstance.FCS := FCS.Clone();
  LHashInstance.FOutputReader := FOutputReader.Clone();
  System.Move(FStack, LHashInstance.FStack, System.SizeOf(FStack));
  LHashInstance.FUsed := FUsed;
  LHashInstance.FFlags := FFlags;
  System.Move(FKey, LHashInstance.FKey, System.SizeOf(FKey));

  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TBlake3XOF.Create(AHashSize: Int32; const AKey: THashLibByteArray);
begin
  inherited Create(AHashSize, AKey);
  FFinalized := False;
end;

constructor TBlake3XOF.Create(AHashSize: Int32;
  AKeyWords: PCardinal; AFlags: UInt32);
begin
  inherited CreateInternal(AHashSize, AKeyWords, AFlags);
  FFinalized := False;
end;

procedure TBlake3XOF.DoOutput(const ADestination: THashLibByteArray;
  ADestinationOffset, AOutputLength: UInt64);
begin
  if (UInt64(System.Length(ADestination)) - ADestinationOffset) < AOutputLength
  then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes(@SOutputBufferTooShort);
  end;

  if ((FOutputReader.Offset + AOutputLength) > (XOFSizeInBits shr 3)) then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateRes(@SOutputLengthInvalid);
  end;

  if not FFinalized then
  begin
    Finish();
    FFinalized := True;
  end;
  InternalDoOutput(ADestination, ADestinationOffset, AOutputLength);
end;

function TBlake3XOF.GetName: String;
begin
  Result := Self.ClassName;
end;

function TBlake3XOF.GetResult: THashLibByteArray;
var
  LXofSizeInBytes: UInt64;
begin
  System.SetLength(Result, XOFSizeInBits shr 3);

  LXofSizeInBytes := XOFSizeInBits shr 3;

  System.SetLength(Result, LXofSizeInBytes);

  DoOutput(Result, 0, LXofSizeInBytes);
end;

procedure TBlake3XOF.Initialize;
begin
  FFinalized := False;
  inherited Initialize();
end;

function TBlake3XOF.SetXOFSizeInBitsInternal(AXofSizeInBits: UInt64): IXOF;
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

procedure TBlake3XOF.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
begin
  if FFinalized then
  begin
    raise EInvalidOperationHashLibException.CreateResFmt
      (@SWritetoXofAfterReadError, [Name]);
  end;
  inherited TransformBytes(AData, AIndex, ADataLength);
end;

function TBlake3XOF.TransformFinal: IHashResult;
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

end.
