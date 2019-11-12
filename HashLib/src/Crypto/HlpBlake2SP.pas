unit HlpBlake2SP;

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
{$IFDEF HAS_DELPHI_PPL}
  System.Classes,
  System.Threading,
{$ENDIF HAS_DELPHI_PPL}
  HlpHash,
  HlpIHashResult,
  HlpBlake2S,
  HlpIBlake2SConfig,
  HlpBlake2SConfig,
  HlpIBlake2STreeConfig,
  HlpBlake2STreeConfig,
  HlpIHash,
  HlpIHashInfo,
  HlpArrayUtils,
  HlpHashLibTypes;

type
  TBlake2SP = class(THash, ICryptoNotBuildIn, ITransformBlock)
  strict private
  const
    BlockSizeInBytes = Int32(64);
    OutSizeInBytes = Int32(32);
    ParallelismDegree = Int32(8);

  var
    FRootHash: IHash;
    FLeafHashes: THashLibGenericArray<IHash>;
    FBuffer, FKey: THashLibByteArray;
    FBufferLength: UInt64;

    /// <summary>
    /// <br />Blake2S defaults to setting the expected output length <br />
    /// from the <c>HashSize</c> in the <c>TBlake2SConfig</c> class. <br />In
    /// some cases, however, we do not want this, as the output length <br />
    /// of these instances is given by <c>TBlake2STreeConfig.InnerSize</c>
    /// instead. <br />
    /// </summary>
    function Blake2SPInitLeafParam(const ABlake2SConfig: IBlake2SConfig;
      const ABlake2STreeConfig: IBlake2STreeConfig): IHash;
    function Blake2SPInitLeaf(AOffset: UInt64): IHash;
    function Blake2SPInitRoot(): IHash;
    procedure ParallelComputation(AIdx: Int32; APtrDataTwo: PByte;
      ACounter: UInt64);

    procedure DoParallelComputation(APtrDataTwo: PByte; ACounter: UInt64);

    procedure Clear();

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

function TBlake2SP.Blake2SPInitLeafParam(const ABlake2SConfig: IBlake2SConfig;
  const ABlake2STreeConfig: IBlake2STreeConfig): IHash;
begin
  Result := TBlake2S.Create(ABlake2SConfig, ABlake2STreeConfig);
  Result.Initialize;
  (Result as THash).HashSize := ABlake2STreeConfig.InnerHashSize;
end;

function TBlake2SP.Blake2SPInitLeaf(AOffset: UInt64): IHash;
var
  LBlake2SConfig: IBlake2SConfig;
  LBlake2STreeConfig: IBlake2STreeConfig;
begin
  LBlake2SConfig := TBlake2SConfig.Create(HashSize);
  LBlake2SConfig.Key := FKey;
  LBlake2STreeConfig := TBlake2STreeConfig.Create();
  LBlake2STreeConfig.FanOut := ParallelismDegree;
  LBlake2STreeConfig.MaxDepth := 2;
  LBlake2STreeConfig.NodeDepth := 0;
  LBlake2STreeConfig.LeafSize := 0;
  LBlake2STreeConfig.NodeOffset := AOffset;
  LBlake2STreeConfig.InnerHashSize := OutSizeInBytes;
  if AOffset = (ParallelismDegree - 1) then
  begin
    LBlake2STreeConfig.IsLastNode := True;
  end;
  Result := Blake2SPInitLeafParam(LBlake2SConfig, LBlake2STreeConfig);
end;

function TBlake2SP.Blake2SPInitRoot(): IHash;
var
  LBlake2SConfig: IBlake2SConfig;
  LBlake2STreeConfig: IBlake2STreeConfig;
begin
  LBlake2SConfig := TBlake2SConfig.Create(HashSize);
  LBlake2SConfig.Key := FKey;
  LBlake2STreeConfig := TBlake2STreeConfig.Create();
  LBlake2STreeConfig.FanOut := ParallelismDegree;
  LBlake2STreeConfig.MaxDepth := 2;
  LBlake2STreeConfig.NodeDepth := 1;
  LBlake2STreeConfig.LeafSize := 0;
  LBlake2STreeConfig.NodeOffset := 0;
  LBlake2STreeConfig.InnerHashSize := OutSizeInBytes;
  LBlake2STreeConfig.IsLastNode := True;
  Result := TBlake2S.Create(LBlake2SConfig, LBlake2STreeConfig, False);
  Result.Initialize;
end;

procedure TBlake2SP.Clear;
begin
  TArrayUtils.ZeroFill(FKey);
end;

function TBlake2SP.Clone(): IHash;
var
  LHashInstance: TBlake2SP;
begin
  LHashInstance := TBlake2SP.Create(HashSize, FKey);
  if FRootHash <> Nil then
  begin
    LHashInstance.FRootHash := FRootHash.Clone();
  end;
  // TODO
  // confirm that this line below does a deep copy
  LHashInstance.FLeafHashes := System.Copy(FLeafHashes);
  LHashInstance.FBuffer := System.Copy(FBuffer);
  LHashInstance.FBufferLength := FBufferLength;
  Result := LHashInstance as IHash;
  Result.BufferSize := BufferSize;
end;

constructor TBlake2SP.Create(AHashSize: Int32; const AKey: THashLibByteArray);
begin
  Inherited Create(AHashSize, BlockSizeInBytes);
  System.SetLength(FBuffer, ParallelismDegree * BlockSizeInBytes);
  System.SetLength(FLeafHashes, ParallelismDegree);
  FKey := System.Copy(AKey);
end;

destructor TBlake2SP.Destroy;
begin
  Clear();
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
  FRootHash := Blake2SPInitRoot;
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    FLeafHashes[LIdx] := Blake2SPInitLeaf(LIdx);
  end;
  TArrayUtils.ZeroFill(FBuffer);
  FBufferLength := 0;
end;

procedure TBlake2SP.ParallelComputation(AIdx: Int32; APtrDataTwo: PByte;
  ACounter: UInt64);
begin
  System.Inc(APtrDataTwo, AIdx * BlockSizeInBytes);

  while (ACounter >= (ParallelismDegree * BlockSizeInBytes)) do
  begin
    FLeafHashes[AIdx].TransformUntyped(APtrDataTwo^,
      BlockSizeInBytes * System.SizeOf(Byte));
    System.Inc(APtrDataTwo, ParallelismDegree * BlockSizeInBytes);
    ACounter := ACounter - UInt64(ParallelismDegree * BlockSizeInBytes);
  end;
end;

{$IFDEF HAS_DELPHI_PPL}

procedure TBlake2SP.DoParallelComputation(APtrDataTwo: PByte; ACounter: UInt64);

  function CreateTask(AIdx: Int32; APtrDataTwo: PByte; ACounter: UInt64): ITask;
  begin
    Result := TTask.Create(
      procedure()
      begin
        ParallelComputation(AIdx, APtrDataTwo, ACounter);
      end);
  end;

var
  LArrayTasks: array of ITask;
  LIdx: Int32;
begin
  System.SetLength(LArrayTasks, ParallelismDegree);
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    LArrayTasks[LIdx] := CreateTask(LIdx, APtrDataTwo, ACounter);
    LArrayTasks[LIdx].Start;
  end;
  TTask.WaitForAll(LArrayTasks);
end;

{$ELSE}

procedure TBlake2SP.DoParallelComputation(APtrDataTwo: PByte; ACounter: UInt64);
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    ParallelComputation(LIdx, APtrDataTwo, ACounter);
  end;
end;
{$ENDIF HAS_DELPHI_PPL}

procedure TBlake2SP.TransformBytes(const AData: THashLibByteArray;
AIndex, ADataLength: Int32);
var
  LLeft, LFill, LDataLength, LCounter: UInt64;
  LPtrData, LPtrDataTwo: PByte;
  LIdx: Int32;
begin
  LDataLength := UInt64(ADataLength);
  LPtrData := PByte(AData) + AIndex;
  LLeft := FBufferLength;
  LFill := UInt64(System.Length(FBuffer)) - LLeft;

  if (LLeft > 0) and (LDataLength >= LFill) then
  begin
    System.Move(LPtrData^, FBuffer[LLeft], LFill);

    for LIdx := 0 to System.Pred(ParallelismDegree) do
    begin
      FLeafHashes[LIdx].TransformBytes(FBuffer, LIdx * BlockSizeInBytes,
        BlockSizeInBytes);
    end;

    System.Inc(LPtrData, LFill);
    LDataLength := LDataLength - LFill;
    LLeft := 0;
  end;

  LPtrDataTwo := LPtrData;
  LCounter := LDataLength;
  DoParallelComputation(LPtrDataTwo, LCounter);

  System.Inc(LPtrData, LDataLength - (LDataLength mod UInt64(ParallelismDegree *
    BlockSizeInBytes)));
  LDataLength := LDataLength mod UInt64(ParallelismDegree * BlockSizeInBytes);

  if (LDataLength > 0) then
  begin
    System.Move(LPtrData^, FBuffer[LLeft], LDataLength);
  end;

  FBufferLength := UInt32(LLeft) + UInt32(LDataLength);
end;

function TBlake2SP.TransformFinal: IHashResult;
var
  LHash: THashLibMatrixByteArray;
  LIdx: Int32;
  LLeft: UInt64;
begin
  System.SetLength(LHash, ParallelismDegree);
  for LIdx := System.Low(LHash) to System.High(LHash) do
  begin
    System.SetLength(LHash[LIdx], OutSizeInBytes);
  end;

  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    if (FBufferLength > (LIdx * BlockSizeInBytes)) then
    begin
      LLeft := FBufferLength - UInt64(LIdx * BlockSizeInBytes);
      if (LLeft > BlockSizeInBytes) then
      begin
        LLeft := BlockSizeInBytes;
      end;
      FLeafHashes[LIdx].TransformBytes(FBuffer, LIdx * BlockSizeInBytes,
        Int32(LLeft));
    end;

    LHash[LIdx] := FLeafHashes[LIdx].TransformFinal().GetBytes();
  end;

  for LIdx := 0 to System.Pred(ParallelismDegree) do
  begin
    FRootHash.TransformBytes(LHash[LIdx]);
  end;
  Result := FRootHash.TransformFinal();
  Initialize();
end;

end.
