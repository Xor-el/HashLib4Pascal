unit HlpMurmurHash3_x86_32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHash,
  HlpIHash,
  HlpHashResult,
  HlpIHashResult,
  HlpBits;

resourcestring
  SInvalidKeyLength = 'KeyLength Must Be Equal to %d';

type

  TMurmurHash3_x86_32 = class sealed(THash, IHash32, IHashWithKey,
    ITransformBlock)

  strict private
  var
    FKey, FHashValue, FTotalLength: UInt32;
    FIdx: Int32;
    FBuffer: THashLibByteArray;

    procedure ByteUpdate(AByte: Byte); inline;
    procedure Finish();

  const
    CKEY = UInt32($0);

    C1 = UInt32($CC9E2D51);
    C2 = UInt32($1B873593);
    C3 = UInt32($E6546B64);
    C4 = UInt32($85EBCA6B);
    C5 = UInt32($C2B2AE35);

    function GetKeyLength(): Int32;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(const AValue: THashLibByteArray); inline;

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;
    property KeyLength: Int32 read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TMurmurHash3_x86_32 }

function TMurmurHash3_x86_32.Clone(): IHash;
var
  LHashInstance: TMurmurHash3_x86_32;
begin
  LHashInstance := TMurmurHash3_x86_32.Create();
  LHashInstance.FKey := FKey;
  LHashInstance.FHashValue := FHashValue;
  LHashInstance.FTotalLength := FTotalLength;
  LHashInstance.FIdx := FIdx;
  LHashInstance.FBuffer := System.Copy(FBuffer);
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TMurmurHash3_x86_32.Create;
begin
  inherited Create(4, 4);
  FKey := CKEY;
  System.SetLength(FBuffer, 4);
end;

procedure TMurmurHash3_x86_32.Finish;
var
  LFinalBlock: UInt32;
begin

  // tail

  LFinalBlock := 0;

  if (FIdx <> 0) then
  begin

    case (FIdx) of
      3:
        begin
          LFinalBlock := LFinalBlock xor (FBuffer[2] shl 16);
          LFinalBlock := LFinalBlock xor (FBuffer[1] shl 8);
          LFinalBlock := LFinalBlock xor FBuffer[0];
          LFinalBlock := LFinalBlock * C1;
          LFinalBlock := TBits.RotateLeft32(LFinalBlock, 15);
          LFinalBlock := LFinalBlock * C2;
          FHashValue := FHashValue xor LFinalBlock;

        end;
      2:
        begin

          LFinalBlock := LFinalBlock xor (FBuffer[1] shl 8);
          LFinalBlock := LFinalBlock xor FBuffer[0];
          LFinalBlock := LFinalBlock * C1;
          LFinalBlock := TBits.RotateLeft32(LFinalBlock, 15);
          LFinalBlock := LFinalBlock * C2;
          FHashValue := FHashValue xor LFinalBlock;

        end;
      1:
        begin

          LFinalBlock := LFinalBlock xor FBuffer[0];
          LFinalBlock := LFinalBlock * C1;
          LFinalBlock := TBits.RotateLeft32(LFinalBlock, 15);
          LFinalBlock := LFinalBlock * C2;
          FHashValue := FHashValue xor LFinalBlock;

        end;
    end;
  end;

  // finalization

  FHashValue := FHashValue xor FTotalLength;

  FHashValue := FHashValue xor (FHashValue shr 16);
  FHashValue := FHashValue * C4;
  FHashValue := FHashValue xor (FHashValue shr 13);
  FHashValue := FHashValue * C5;
  FHashValue := FHashValue xor (FHashValue shr 16);
end;

procedure TMurmurHash3_x86_32.ByteUpdate(AByte: Byte);
var
  LPtrBuffer: PByte;
  LBlock: UInt32;
begin
  FBuffer[FIdx] := AByte;
  System.Inc(FIdx);
  if FIdx >= 4 then
  begin
    LPtrBuffer := PByte(FBuffer);
    LBlock := TConverters.ReadBytesAsUInt32LE(LPtrBuffer, 0);

    LBlock := LBlock * C1;
    LBlock := TBits.RotateLeft32(LBlock, 15);
    LBlock := LBlock * C2;

    FHashValue := FHashValue xor LBlock;
    FHashValue := TBits.RotateLeft32(FHashValue, 13);
    FHashValue := (FHashValue * 5) + C3;

    FIdx := 0;
  end;
end;

function TMurmurHash3_x86_32.GetKey: THashLibByteArray;
begin
  Result := TConverters.ReadUInt32AsBytesLE(FKey);
end;

procedure TMurmurHash3_x86_32.SetKey(const AValue: THashLibByteArray);
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

function TMurmurHash3_x86_32.GetKeyLength: Int32;
begin
  Result := 4;
end;

procedure TMurmurHash3_x86_32.Initialize;
begin
  FHashValue := FKey;
  FTotalLength := 0;
  FIdx := 0;
end;

procedure TMurmurHash3_x86_32.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LLength, LNBlocks, LIdx, LOffset: Int32;
  LBlock, LHashAcc: UInt32;
  LPtrData, LPtrBuffer: PByte;
  LPtrDataCardinal: PCardinal;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LLength := ALength;
  LIdx := AIndex;
  LPtrData := PByte(AData);
  System.Inc(FTotalLength, LLength);

  // consume last pending bytes

  if ((FIdx <> 0) and (ALength <> 0)) then
  begin
    { *                       buf    data
      idx = 1, len = 3 -> [0, 1[ + [0, 3[ => Block = [], buf []
      idx = 1, len = 4 -> [0, 1[ + [0, 3[ => Block = [], buf = data[3, 4[
      idx = 1, len = 5 -> [0, 1[ + [0, 3[ => Block = [], buf = data[3, 5[
      ...
      idx = 1, len = 7 -> [0, 1[ + [0, 3[ => Block = [3,7[, buf []
      idx = 2, len = 3 -> [0, 2[ + [0, 2[ => Block = [], buf [2, 3[
      idx = 2, len = 4 -> [0, 2[ + [0, 2[ => Block = [], buf [2, 4[
      ...
      idx = 2, len = 6 -> [0, 2[ + [0, 2[ => Block = [2,6[, buf []
      * }
{$IFDEF DEBUG}
    System.Assert(AIndex = 0); // nothing would work anyways if AIndex is !=0
{$ENDIF DEBUG}
    while ((FIdx < 4) and (LLength <> 0)) do
    begin
      FBuffer[FIdx] := (LPtrData + AIndex)^;
      System.Inc(FIdx);
      System.Inc(AIndex);
      System.Dec(LLength);
    end;
    if (FIdx = 4) then
    begin
      LPtrBuffer := PByte(FBuffer);
      LBlock := TConverters.ReadBytesAsUInt32LE(LPtrBuffer, 0);

      LBlock := LBlock * C1;
      LBlock := TBits.RotateLeft32(LBlock, 15);
      LBlock := LBlock * C2;

      FHashValue := FHashValue xor LBlock;
      FHashValue := TBits.RotateLeft32(FHashValue, 13);
      FHashValue := (FHashValue * 5) + C3;

      FIdx := 0;
    end;
  end
  else
  begin
    LIdx := 0;
  end;

  LNBlocks := LLength shr 2;

  // body

  LHashAcc := FHashValue;
  LPtrDataCardinal := PCardinal(LPtrData + AIndex);
  while LIdx < LNBlocks do
  begin
    LBlock := TConverters.ReadPCardinalAsUInt32LE(LPtrDataCardinal + LIdx);

    LBlock := LBlock * C1;
    LBlock := TBits.RotateLeft32(LBlock, 15);
    LBlock := LBlock * C2;

    LHashAcc := LHashAcc xor LBlock;
    LHashAcc := TBits.RotateLeft32(LHashAcc, 13);
    LHashAcc := (LHashAcc * 5) + C3;

    System.Inc(LIdx);
  end;

  FHashValue := LHashAcc;

  // save pending end bytes
  LOffset := AIndex + (LIdx * 4);
  while LOffset < (LLength + AIndex) do
  begin
    ByteUpdate(AData[LOffset]);
    System.Inc(LOffset);
  end;
end;

function TMurmurHash3_x86_32.TransformFinal: IHashResult;
var
  LBufferBytes: THashLibByteArray;
begin
  Finish();

  System.SetLength(LBufferBytes, HashSize);
  TConverters.ReadUInt32AsBytesBE(FHashValue, LBufferBytes, 0);

  Result := THashResult.Create(LBufferBytes);
  Initialize();
end;

end.
