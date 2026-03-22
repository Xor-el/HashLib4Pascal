unit HlpMurmur2_64;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpConverters,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpMultipleTransformNonBlock;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type
  // MurmurHash64A (64-bit) algorithm by Austin Appleby.
  TMurmur2_64 = class sealed(TMultipleTransformNonBlock, IHash64, IHashWithKey,
    ITransformBlock)

  strict private
  var
    FKey, FWorkingKey: UInt64;

  const
    CKEY = UInt64($0);
    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
    CMul: UInt64 = UInt64($C6A4A7935BD1E995);
    CShift = Int32(47);

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

  strict protected
    function ComputeAggregatedBytes(const AData: THashLibByteArray)
      : IHashResult; override;

  public
    constructor Create();
    procedure Initialize(); override;
    function Clone(): IHash; override;
    property KeyLength: Int32 read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TMurmur2_64 }

function TMurmur2_64.Clone(): IHash;
var
  LHashInstance: TMurmur2_64;
begin
  LHashInstance := TMurmur2_64.Create();
  LHashInstance.FKey := FKey;
  LHashInstance.FWorkingKey := FWorkingKey;
  FBuffer.Position := 0;
  LHashInstance.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

function TMurmur2_64.ComputeAggregatedBytes(const AData: THashLibByteArray)
  : IHashResult;
var
  LLength, LCurrentIndex, LNBlocks, LIdx: Int32;
  LHashAcc, LReadChunk: UInt64;
  LPtrData: PByte;
  LPtrDataUInt64: PUInt64;
begin
  LLength := System.length(AData);
  LPtrData := PByte(AData);

  if (LLength = 0) then
  begin
    Result := THashResult.Create(UInt64(0));
    Exit;
  end;

  LHashAcc := FWorkingKey xor (UInt64(LLength) * CMul);
  LCurrentIndex := 0;
  LIdx := 0;
  LPtrDataUInt64 := PUInt64(LPtrData);
  LNBlocks := LLength shr 3;

  while LIdx < LNBlocks do
  begin
    LReadChunk := TConverters.ReadPUInt64AsUInt64LE(LPtrDataUInt64 + LIdx);

    LReadChunk := LReadChunk * CMul;
    LReadChunk := LReadChunk xor (LReadChunk shr CShift);
    LReadChunk := LReadChunk * CMul;

    LHashAcc := LHashAcc xor LReadChunk;
    LHashAcc := LHashAcc * CMul;

    System.Inc(LIdx);
    System.Inc(LCurrentIndex, 8);
    System.Dec(LLength, 8);
  end;

  case LLength of
    7:
      begin
        LHashAcc := LHashAcc xor ((UInt64(AData[LCurrentIndex + 6]) shl 48));

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 5]) shl 40);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 4]) shl 32);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 3]) shl 24);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 2]) shl 16);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

    6:
      begin
        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 5]) shl 40);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 4]) shl 32);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 3]) shl 24);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 2]) shl 16);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

    5:
      begin
        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 4]) shl 32);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 3]) shl 24);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 2]) shl 16);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);
        LHashAcc := LHashAcc * CMul;
      end;

    4:
      begin
        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 3]) shl 24);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 2]) shl 16);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);
        LHashAcc := LHashAcc * CMul;
      end;

    3:
      begin
        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 2]) shl 16);

        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);
        LHashAcc := LHashAcc * CMul;
      end;

    2:
      begin
        LHashAcc := LHashAcc xor (UInt64(AData[LCurrentIndex + 1]) shl 8);

        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

    1:
      begin
        LHashAcc := LHashAcc xor UInt64(AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

  end;

  LHashAcc := LHashAcc xor (LHashAcc shr CShift);
  LHashAcc := LHashAcc * CMul;
  LHashAcc := LHashAcc xor (LHashAcc shr CShift);

  Result := THashResult.Create(LHashAcc);
end;

constructor TMurmur2_64.Create;
begin
  inherited Create(8, 8);
  FKey := CKEY;
end;

function TMurmur2_64.GetKey: THashLibByteArray;
begin
  Result := TConverters.ReadUInt64AsBytesLE(FKey);
end;

function TMurmur2_64.GetKeyLength: Int32;
begin
  Result := 8;
end;

procedure TMurmur2_64.Initialize;
begin
  FWorkingKey := FKey;
  inherited Initialize();
end;

procedure TMurmur2_64.SetKey(const AValue: THashLibByteArray);
begin
  if (AValue = nil) then
  begin
    FKey := CKEY;
  end
  else
  begin
    if System.length(AValue) <> KeyLength then
    begin
      raise EArgumentHashLibException.CreateResFmt(@SInvalidKeyLength,
        [KeyLength]);
    end;
    FKey := TConverters.ReadBytesAsUInt64LE(PByte(AValue), 0);
  end;
end;

end.
