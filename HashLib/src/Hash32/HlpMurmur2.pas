unit HlpMurmur2;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpIHash,
  HlpConverters,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpMultipleTransformNonBlock;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type
  // The original MurmurHash2 32-bit algorithm by Austin Appleby.
  TMurmur2 = class sealed(TMultipleTransformNonBlock, IHash32, IHashWithKey,
    ITransformBlock)

  strict private
  var
    FKey, FWorkingKey: UInt32;

  const
    CKEY = UInt32($0);
    CMul = UInt32($5BD1E995);
    CShift = Int32(24);

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

{ TMurmur2 }

constructor TMurmur2.Create;
begin
  inherited Create(4, 4);
  FKey := CKEY;
end;

function TMurmur2.GetKey: THashLibByteArray;
begin
  Result := TConverters.ReadUInt32AsBytesLE(FKey);
end;

procedure TMurmur2.SetKey(const AValue: THashLibByteArray);
begin
  if (AValue = nil) then
  begin
    FKey := CKEY;
  end
  else
  begin
    if System.Length(AValue) <> KeyLength then
    begin
      raise EArgumentHashLibException.CreateResFmt(@SInvalidKeyLength,
        [KeyLength]);
    end;
    FKey := TConverters.ReadBytesAsUInt32LE(PByte(AValue), 0);
  end;
end;

function TMurmur2.GetKeyLength: Int32;
begin
  Result := 4;
end;

procedure TMurmur2.Initialize;
begin
  FWorkingKey := FKey;
  inherited Initialize();
end;

function TMurmur2.Clone(): IHash;
var
  LHashInstance: TMurmur2;
begin
  LHashInstance := TMurmur2.Create();
  LHashInstance.FKey := FKey;
  LHashInstance.FWorkingKey := FWorkingKey;
  FBuffer.Position := 0;
  LHashInstance.FBuffer.CopyFrom(FBuffer, FBuffer.Size);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

function TMurmur2.ComputeAggregatedBytes(const AData: THashLibByteArray)
  : IHashResult;
var
  LLength, LCurrentIndex, LNBlocks, LIdx: Int32;
  LBlock, LHashAcc: UInt32;
  LPtrData: PByte;
  LPtrDataCardinal: PCardinal;
begin
  LLength := System.Length(AData);
  LPtrData := PByte(AData);

  if (LLength = 0) then
  begin
    Result := THashResult.Create(Int32(0));
    Exit;
  end;

  LHashAcc := FWorkingKey xor UInt32(LLength);

  LCurrentIndex := 0;
  LIdx := 0;
  LPtrDataCardinal := PCardinal(LPtrData);
  LNBlocks := LLength shr 2;

  while LIdx < LNBlocks do
  begin
    LBlock := TConverters.ReadPCardinalAsUInt32LE(LPtrDataCardinal + LIdx);

    LBlock := LBlock * CMul;
    LBlock := LBlock xor (LBlock shr CShift);
    LBlock := LBlock * CMul;

    LHashAcc := LHashAcc * CMul;
    LHashAcc := LHashAcc xor LBlock;

    System.Inc(LIdx);
    System.Inc(LCurrentIndex, 4);
    System.Dec(LLength, 4);
  end;

  case LLength of
    3:
      begin
        LHashAcc := LHashAcc xor (AData[LCurrentIndex + 2] shl 16);

        LHashAcc := LHashAcc xor (AData[LCurrentIndex + 1] shl 8);

        LHashAcc := LHashAcc xor (AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

    2:
      begin
        LHashAcc := LHashAcc xor (AData[LCurrentIndex + 1] shl 8);

        LHashAcc := LHashAcc xor (AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;

    1:
      begin
        LHashAcc := LHashAcc xor (AData[LCurrentIndex]);

        LHashAcc := LHashAcc * CMul;
      end;
  end;

  LHashAcc := LHashAcc xor (LHashAcc shr 13);

  LHashAcc := LHashAcc * CMul;
  LHashAcc := LHashAcc xor (LHashAcc shr 15);

  Result := THashResult.Create(Int32(LHashAcc));
end;

end.
