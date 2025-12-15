unit HlpBlake2SP;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
{$IFDEF HASHLIB_USE_PPL}
  System.Threading,
{$ENDIF HASHLIB_USE_PPL}
  HlpHash,
  HlpIHashResult,
  HlpBlake2S,
  HlpIBlake2SParams,
  HlpBlake2SParams,
  HlpIHash,
  HlpIHashInfo,
  HlpArrayUtils,
  HlpHashLibTypes;

type
  TBlake2SP = class sealed(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private
  const
    BlockSizeInBytes  = 64;
    OutSizeInBytes    = 32;
    ParallelismDegree = 8;
    StripeSize        = ParallelismDegree * BlockSizeInBytes;

  var
    // had to use the classes directly for performance purposes
    FRootHash: TBlake2S;
    FLeafHashes: THashLibGenericArray<TBlake2S>;
    FBuffer, FKey: THashLibByteArray;
    FBufferLength: UInt64;

    /// <summary>
    /// <br />Blake2S defaults to setting the expected output length <br />
    /// from the <c>HashSize</c> in the <c>TBlake2SConfig</c> class. <br />In
    /// some cases, however, we do not want this, as the output length <br />
    /// of these instances is given by <c>TBlake2STreeConfig.InnerSize</c>
    /// instead. <br />
    /// </summary>
    function Blake2SPCreateLeafParam(const ABlake2SConfig: IBlake2SConfig;
      const ABlake2STreeConfig: IBlake2STreeConfig): TBlake2S;
    function Blake2SPCreateLeaf(AOffset: UInt64): TBlake2S;
    function Blake2SPCreateRoot(): TBlake2S;

    // Each lane processes its own "stripe" of the input
    procedure ProcessLeafLane(AIdx: Int32; APtrData: PByte;
      ADataLength: UInt64);

    // Dispatch computation across all lanes (parallel or sequential)
    procedure ProcessLeafLanesInParallel(APtrData: PByte; ADataLength: UInt64);

    function DeepCloneBlake2SInstances(const ALeafHashes
      : THashLibGenericArray<TBlake2S>): THashLibGenericArray<TBlake2S>;

    procedure Clear;

    constructor CreateInternal(AHashSize: Int32);
  strict protected
    function GetName: String; override;

  public
    constructor Create(AHashSize: Int32; const AKey: THashLibByteArray);
    destructor Destroy; override;
    procedure Initialize; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ADataLength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;
  end;

implementation

{ TBlake2SP }

function TBlake2SP.Blake2SPCreateLeafParam(const ABlake2SConfig: IBlake2SConfig;
  const ABlake2STreeConfig: IBlake2STreeConfig): TBlake2S;
begin
  Result := TBlake2S.Create(ABlake2SConfig, ABlake2STreeConfig);
end;

function TBlake2SP.Blake2SPCreateLeaf(AOffset: UInt64): TBlake2S;
var
  LBlake2SConfig: IBlake2SConfig;
  LBlake2STreeConfig: IBlake2STreeConfig;
begin
  LBlake2SConfig := TBlake2SConfig.Create(HashSize);
  LBlake2SConfig.Key := FKey;

  LBlake2STreeConfig := TBlake2STreeConfig.Create();
  LBlake2STreeConfig.FanOut        := ParallelismDegree;
  LBlake2STreeConfig.MaxDepth      := 2;
  LBlake2STreeConfig.NodeDepth     := 0;
  LBlake2STreeConfig.LeafSize      := 0;
  LBlake2STreeConfig.NodeOffset    := AOffset;
  LBlake2STreeConfig.InnerHashSize := OutSizeInBytes;

  if AOffset = (ParallelismDegree - 1) then
  begin
    LBlake2STreeConfig.IsLastNode := True;
  end;

  Result := Blake2SPCreateLeafParam(LBlake2SConfig, LBlake2STreeConfig);
end;

function TBlake2SP.Blake2SPCreateRoot(): TBlake2S;
var
  LBlake2SConfig: IBlake2SConfig;
  LBlake2STreeConfig: IBlake2STreeConfig;
begin
  LBlake2SConfig := TBlake2SConfig.Create(HashSize);
  LBlake2SConfig.Key := FKey;

  LBlake2STreeConfig := TBlake2STreeConfig.Create();
  LBlake2STreeConfig.FanOut        := ParallelismDegree;
  LBlake2STreeConfig.MaxDepth      := 2;
  LBlake2STreeConfig.NodeDepth     := 1;
  LBlake2STreeConfig.LeafSize      := 0;
  LBlake2STreeConfig.NodeOffset    := 0;
  LBlake2STreeConfig.InnerHashSize := OutSizeInBytes;
  LBlake2STreeConfig.IsLastNode    := True;

  Result := TBlake2S.Create(LBlake2SConfig, LBlake2STreeConfig, False);
end;

procedure TBlake2SP.Clear;
begin
  TArrayUtils.ZeroFill(FKey);
end;

function TBlake2SP.DeepCloneBlake2SInstances(const ALeafHashes
  : THashLibGenericArray<TBlake2S>): THashLibGenericArray<TBlake2S>;
var
  LIdx: Int32;
begin
  System.SetLength(Result, System.Length(ALeafHashes));
  for LIdx := System.Low(ALeafHashes) to System.High(ALeafHashes) do
  begin
    Result[LIdx] := ALeafHashes[LIdx].CloneInternal();
  end;
end;

function TBlake2SP.Clone(): IHash;
var
  LHashInstance: TBlake2SP;
begin
  LHashInstance := TBlake2SP.CreateInternal(HashSize);
  LHashInstance.FKey := System.Copy(FKey);

  if FRootHash <> Nil then
  begin
    LHashInstance.FRootHash := FRootHash.CloneInternal();
  end;

  LHashInstance.FLeafHashes   := DeepCloneBlake2SInstances(FLeafHashes);
  LHashInstance.FBuffer       := System.Copy(FBuffer);
  LHashInstance.FBufferLength := FBufferLength;

  Result := LHashInstance as IHash;
  Result.BufferSize := BufferSize;
end;

constructor TBlake2SP.CreateInternal(AHashSize: Int32);
begin
  Inherited Create(AHashSize, BlockSizeInBytes);
end;

constructor TBlake2SP.Create(AHashSize: Int32; const AKey: THashLibByteArray);
var
  LIdx: Int32;
begin
  Inherited Create(AHashSize, BlockSizeInBytes);

  System.SetLength(FBuffer, ParallelismDegree * BlockSizeInBytes);
  System.SetLength(FLeafHashes, ParallelismDegree);

  FKey      := System.Copy(AKey);
  FRootHash := Blake2SPCreateRoot;

  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    FLeafHashes[LIdx] := Blake2SPCreateLeaf(LIdx);
  end;
end;

destructor TBlake2SP.Destroy;
var
  LIdx: Int32;
begin
  Clear();

  FRootHash.Free;
  FRootHash := Nil;

  for LIdx := System.Low(FLeafHashes) to System.High(FLeafHashes) do
  begin
    FLeafHashes[LIdx].Free;
    FLeafHashes[LIdx] := Nil;
  end;

  FLeafHashes := Nil;

  inherited Destroy;
end;

function TBlake2SP.GetName: String;
begin
  Result := Format('%s_%u', [Self.ClassName, Self.HashSize * 8]);
end;

procedure TBlake2SP.Initialize;
var
  LIdx: Int32;
begin
  FRootHash.Initialize;

  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    FLeafHashes[LIdx].Initialize;
    FLeafHashes[LIdx].HashSize := OutSizeInBytes;
  end;

  TArrayUtils.ZeroFill(FBuffer);
  FBufferLength := 0;
end;

procedure TBlake2SP.ProcessLeafLane(AIdx: Int32; APtrData: PByte;
  ADataLength: UInt64);
var
  LLeafHashes: THashLibGenericArray<TBlake2S>;
  LTemp: THashLibByteArray;
  LCounter: UInt64;
  LPtrData: PByte;
begin
  System.SetLength(LTemp, BlockSizeInBytes);

  LPtrData    := APtrData;
  LCounter    := ADataLength;
  LLeafHashes := FLeafHashes;

  // Start at lane offset
  Inc(LPtrData, AIdx * BlockSizeInBytes);

  // Process all full "stripes" of ParallelismDegree * BlockSizeInBytes
  while (LCounter >= StripeSize) do
  begin
    System.Move(LPtrData^, LTemp[0], BlockSizeInBytes);
    LLeafHashes[AIdx].TransformBytes(LTemp, 0, BlockSizeInBytes);

    Inc(LPtrData, UInt64(StripeSize));
    LCounter := LCounter - UInt64(StripeSize);
  end;
end;

procedure TBlake2SP.ProcessLeafLanesInParallel(APtrData: PByte;
  ADataLength: UInt64);
var
  LFullStripeLength: UInt64;
{$IFNDEF HASHLIB_USE_PPL}
  LIdx: Int32;
{$ENDIF}
begin
  // Only full stripes are processed here
  LFullStripeLength := (ADataLength div StripeSize) * StripeSize;
  if LFullStripeLength = 0 then
    Exit;

{$IFDEF HASHLIB_USE_PPL}
  // parallel processing of each lane
  TParallel.&For(
    0,
    ParallelismDegree - 1,
    procedure(AIdx: Integer)
    begin
      ProcessLeafLane(AIdx, APtrData, LFullStripeLength);
    end
  );
{$ELSE}
  // Fallback: simple sequential processing of each lane
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    ProcessLeafLane(LIdx, APtrData, LFullStripeLength);
  end;
{$ENDIF HASHLIB_USE_PPL}
end;

procedure TBlake2SP.TransformBytes(const AData: THashLibByteArray;
  AIndex, ADataLength: Int32);
var
  LLeft, LFill, LDataLength: UInt64;
  LPtrData: PByte;
  LIdx: Int32;
  LLeafHashes: THashLibGenericArray<TBlake2S>;
  LProcessed: UInt64;
begin
  LLeafHashes := FLeafHashes;
  LDataLength := UInt64(ADataLength);
  LPtrData    := PByte(AData) + AIndex;

  LLeft := FBufferLength;
  LFill := UInt64(System.Length(FBuffer)) - LLeft;

  // Fill existing buffer to a full "parallel chunk" if possible
  if (LLeft > 0) and (LDataLength >= LFill) then
  begin
    System.Move(LPtrData^, FBuffer[LLeft], LFill);

    for LIdx := 0 to System.Pred(ParallelismDegree) do
    begin
      LLeafHashes[LIdx].TransformBytes(FBuffer, LIdx * BlockSizeInBytes,
        BlockSizeInBytes);
    end;

    Inc(LPtrData, LFill);
    LDataLength := LDataLength - LFill;
    LLeft := 0;
  end;

  // Process as many full "parallel stripes" as possible
  ProcessLeafLanesInParallel(LPtrData, LDataLength);

  // Move pointer past processed data (everything except the remainder)
  LProcessed := (LDataLength div StripeSize) * StripeSize;
  Inc(LPtrData, LProcessed);

  // Keep the remainder in the buffer
  LDataLength := LDataLength - LProcessed;

  if (LDataLength > 0) then
  begin
    System.Move(LPtrData^, FBuffer[LLeft], LDataLength);
  end;

  FBufferLength := LLeft + LDataLength;
end;

function TBlake2SP.TransformFinal: IHashResult;
var
  LHash: THashLibMatrixByteArray;
  LIdx: Int32;
  LLeft: UInt64;
  LLeafHashes: THashLibGenericArray<TBlake2S>;
  LRootHash: TBlake2S;
begin
  LLeafHashes := FLeafHashes;
  LRootHash   := FRootHash;

  System.SetLength(LHash, ParallelismDegree);
  for LIdx := System.Low(LHash) to System.High(LHash) do
  begin
    System.SetLength(LHash[LIdx], OutSizeInBytes);
  end;

  // Finalize each leaf with the remaining buffered bytes
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    if (FBufferLength > (UInt64(LIdx) * BlockSizeInBytes)) then
    begin
      LLeft := FBufferLength - UInt64(LIdx * BlockSizeInBytes);
      if (LLeft > BlockSizeInBytes) then
      begin
        LLeft := BlockSizeInBytes;
      end;

      LLeafHashes[LIdx].TransformBytes(
        FBuffer,
        LIdx * BlockSizeInBytes,
        Int32(LLeft)
      );
    end;

    LHash[LIdx] := LLeafHashes[LIdx].TransformFinal().GetBytes();
  end;

  // Feed all leaf hashes into the root
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    LRootHash.TransformBytes(LHash[LIdx], 0, OutSizeInBytes);
  end;

  Result := LRootHash.TransformFinal();
  Initialize();
end;

end.

