unit HlpSHA1;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBitOperations,
  HlpHashLibTypes,
  HlpSHA0,
  HlpIHash;

type
  TSHA1CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  SHA1_Compress: TSHA1CompressProc;

const
  // K round constants, each replicated across four lanes for the SIMD kernels;
  // the scalar reference reads one per group ([0], [4], [8], [12]).
  K_SHA1: array [0 .. 15] of UInt32 = (
    $5A827999, $5A827999, $5A827999, $5A827999,
    $6ED9EBA1, $6ED9EBA1, $6ED9EBA1, $6ED9EBA1,
    $8F1BBCDC, $8F1BBCDC, $8F1BBCDC, $8F1BBCDC,
    $CA62C1D6, $CA62C1D6, $CA62C1D6, $CA62C1D6
  );

type
  TSHA1 = class sealed(TSHA0)

  strict protected
    procedure Expand(AData: PCardinal); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    constructor Create();
    function Clone(): IHash; override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

  end;

implementation

uses
  HlpBinaryPrimitives,
  HlpSHA1Simd;

// =============================================================================
// Scalar reference implementation
// =============================================================================

procedure SHA1_Compress_Scalar(AState, AData: Pointer; ANumBlocks: UInt32);
var
  LPState: PCardinal;
  LPData: PByte;
  LA, LB, LC, LD, LE, LT: UInt32;
  LW: array [0 .. 79] of UInt32;
  LRound: Int32;
begin
  LPState := PCardinal(AState);
  LPData := PByte(AData);

  while ANumBlocks > 0 do
  begin
    TBinaryPrimitives.CopyUInt32BigEndian(LPData, 0, @LW[0], 0, 64);

    for LRound := 16 to 79 do
    begin
      LT := LW[LRound - 3] xor LW[LRound - 8] xor LW[LRound - 14]
        xor LW[LRound - 16];
      LW[LRound] := TBitOperations.RotateLeft32(LT, 1);
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2];
    LD := LPState[3]; LE := LPState[4];

    for LRound := 0 to 19 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LD xor (LB and (LC xor LD)))
        + LE + K_SHA1[0] + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 20 to 39 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + K_SHA1[4] + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 40 to 59 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) +
        ((LB and LC) or (LD and (LB or LC)))
        + LE + K_SHA1[8] + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    for LRound := 60 to 79 do
    begin
      LT := TBitOperations.RotateLeft32(LA, 5) + (LB xor LC xor LD)
        + LE + K_SHA1[12] + LW[LRound];
      LE := LD; LD := LC; LC := TBitOperations.RotateLeft32(LB, 30);
      LB := LA; LA := LT;
    end;

    LPState[0] := LPState[0] + LA; LPState[1] := LPState[1] + LB;
    LPState[2] := LPState[2] + LC; LPState[3] := LPState[3] + LD;
    LPState[4] := LPState[4] + LE;

    System.FillChar(LW, System.SizeOf(LW), 0);
    System.Inc(LPData, 64);
    System.Dec(ANumBlocks);
  end;
end;

{ TSHA1 }

function TSHA1.Clone(): IHash;
var
  LHashInstance: TSHA1;
begin
  LHashInstance := TSHA1.Create();
  LHashInstance.FState := System.Copy(FState);
  LHashInstance.FBuffer := FBuffer.Clone();
  LHashInstance.FProcessedBytesCount := FProcessedBytesCount;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TSHA1.Create;
begin
  inherited Create();
end;

procedure TSHA1.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
begin
  SHA1_Compress(@FState[0], AData + AIndex, 1);
end;

procedure TSHA1.TransformBytes(const AData: THashLibByteArray;
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
    SHA1_Compress(@FState[0], LPtrData + AIndex, UInt32(LBlockCount));
    AIndex := AIndex + (LBlockCount * FBuffer.Length);
    ALength := ALength - (LBlockCount * FBuffer.Length);
  end;

  if (ALength > 0) then
  begin
    FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount);
  end;
end;

procedure TSHA1.Expand(AData: PCardinal);
var
{$IFNDEF USE_UNROLLED_VARIANT}
  LIdx: Int32;
{$ENDIF USE_UNROLLED_VARIANT}
  LScheduleTemp: UInt32;
begin

{$IFDEF USE_UNROLLED_VARIANT}
  LScheduleTemp := AData[16 - 3] xor AData[16 - 8] xor AData[16 - 14] xor AData[0];
  AData[16] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[17 - 3] xor AData[17 - 8] xor AData[17 - 14] xor AData[17 - 16];
  AData[17] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[18 - 3] xor AData[18 - 8] xor AData[18 - 14] xor AData[18 - 16];
  AData[18] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[19 - 3] xor AData[19 - 8] xor AData[19 - 14] xor AData[19 - 16];
  AData[19] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[20 - 3] xor AData[20 - 8] xor AData[20 - 14] xor AData[20 - 16];
  AData[20] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[21 - 3] xor AData[21 - 8] xor AData[21 - 14] xor AData[21 - 16];
  AData[21] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[22 - 3] xor AData[22 - 8] xor AData[22 - 14] xor AData[22 - 16];
  AData[22] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[23 - 3] xor AData[23 - 8] xor AData[23 - 14] xor AData[23 - 16];
  AData[23] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[24 - 3] xor AData[24 - 8] xor AData[24 - 14] xor AData[24 - 16];
  AData[24] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[25 - 3] xor AData[25 - 8] xor AData[25 - 14] xor AData[25 - 16];
  AData[25] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[26 - 3] xor AData[26 - 8] xor AData[26 - 14] xor AData[26 - 16];
  AData[26] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[27 - 3] xor AData[27 - 8] xor AData[27 - 14] xor AData[27 - 16];
  AData[27] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[28 - 3] xor AData[28 - 8] xor AData[28 - 14] xor AData[28 - 16];
  AData[28] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[29 - 3] xor AData[29 - 8] xor AData[29 - 14] xor AData[29 - 16];
  AData[29] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[30 - 3] xor AData[30 - 8] xor AData[30 - 14] xor AData[30 - 16];
  AData[30] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[31 - 3] xor AData[31 - 8] xor AData[31 - 14] xor AData[31 - 16];
  AData[31] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[32 - 3] xor AData[32 - 8] xor AData[32 - 14] xor AData[32 - 16];
  AData[32] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[33 - 3] xor AData[33 - 8] xor AData[33 - 14] xor AData[33 - 16];
  AData[33] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[34 - 3] xor AData[34 - 8] xor AData[34 - 14] xor AData[34 - 16];
  AData[34] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[35 - 3] xor AData[35 - 8] xor AData[35 - 14] xor AData[35 - 16];
  AData[35] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[36 - 3] xor AData[36 - 8] xor AData[36 - 14] xor AData[36 - 16];
  AData[36] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[37 - 3] xor AData[37 - 8] xor AData[37 - 14] xor AData[37 - 16];
  AData[37] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[38 - 3] xor AData[38 - 8] xor AData[38 - 14] xor AData[38 - 16];
  AData[38] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[39 - 3] xor AData[39 - 8] xor AData[39 - 14] xor AData[39 - 16];
  AData[39] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[40 - 3] xor AData[40 - 8] xor AData[40 - 14] xor AData[40 - 16];
  AData[40] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[41 - 3] xor AData[41 - 8] xor AData[41 - 14] xor AData[41 - 16];
  AData[41] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[42 - 3] xor AData[42 - 8] xor AData[42 - 14] xor AData[42 - 16];
  AData[42] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[43 - 3] xor AData[43 - 8] xor AData[43 - 14] xor AData[43 - 16];
  AData[43] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[44 - 3] xor AData[44 - 8] xor AData[44 - 14] xor AData[44 - 16];
  AData[44] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[45 - 3] xor AData[45 - 8] xor AData[45 - 14] xor AData[45 - 16];
  AData[45] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[46 - 3] xor AData[46 - 8] xor AData[46 - 14] xor AData[46 - 16];
  AData[46] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[47 - 3] xor AData[47 - 8] xor AData[47 - 14] xor AData[47 - 16];
  AData[47] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[48 - 3] xor AData[48 - 8] xor AData[48 - 14] xor AData[48 - 16];
  AData[48] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[49 - 3] xor AData[49 - 8] xor AData[49 - 14] xor AData[49 - 16];
  AData[49] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[50 - 3] xor AData[50 - 8] xor AData[50 - 14] xor AData[50 - 16];
  AData[50] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[51 - 3] xor AData[51 - 8] xor AData[51 - 14] xor AData[51 - 16];
  AData[51] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[52 - 3] xor AData[52 - 8] xor AData[52 - 14] xor AData[52 - 16];
  AData[52] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[53 - 3] xor AData[53 - 8] xor AData[53 - 14] xor AData[53 - 16];
  AData[53] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[54 - 3] xor AData[54 - 8] xor AData[54 - 14] xor AData[54 - 16];
  AData[54] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[55 - 3] xor AData[55 - 8] xor AData[55 - 14] xor AData[55 - 16];
  AData[55] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[56 - 3] xor AData[56 - 8] xor AData[56 - 14] xor AData[56 - 16];
  AData[56] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[57 - 3] xor AData[57 - 8] xor AData[57 - 14] xor AData[57 - 16];
  AData[57] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[58 - 3] xor AData[58 - 8] xor AData[58 - 14] xor AData[58 - 16];
  AData[58] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[59 - 3] xor AData[59 - 8] xor AData[59 - 14] xor AData[59 - 16];
  AData[59] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[60 - 3] xor AData[60 - 8] xor AData[60 - 14] xor AData[60 - 16];
  AData[60] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[61 - 3] xor AData[61 - 8] xor AData[61 - 14] xor AData[61 - 16];
  AData[61] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[62 - 3] xor AData[62 - 8] xor AData[62 - 14] xor AData[62 - 16];
  AData[62] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[63 - 3] xor AData[63 - 8] xor AData[63 - 14] xor AData[63 - 16];
  AData[63] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[64 - 3] xor AData[64 - 8] xor AData[64 - 14] xor AData[64 - 16];
  AData[64] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[65 - 3] xor AData[65 - 8] xor AData[65 - 14] xor AData[65 - 16];
  AData[65] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[66 - 3] xor AData[66 - 8] xor AData[66 - 14] xor AData[66 - 16];
  AData[66] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[67 - 3] xor AData[67 - 8] xor AData[67 - 14] xor AData[67 - 16];
  AData[67] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[68 - 3] xor AData[68 - 8] xor AData[68 - 14] xor AData[68 - 16];
  AData[68] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[69 - 3] xor AData[69 - 8] xor AData[69 - 14] xor AData[69 - 16];
  AData[69] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[70 - 3] xor AData[70 - 8] xor AData[70 - 14] xor AData[70 - 16];
  AData[70] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[71 - 3] xor AData[71 - 8] xor AData[71 - 14] xor AData[71 - 16];
  AData[71] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[72 - 3] xor AData[72 - 8] xor AData[72 - 14] xor AData[72 - 16];
  AData[72] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[73 - 3] xor AData[73 - 8] xor AData[73 - 14] xor AData[73 - 16];
  AData[73] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[74 - 3] xor AData[74 - 8] xor AData[74 - 14] xor AData[74 - 16];
  AData[74] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[75 - 3] xor AData[75 - 8] xor AData[75 - 14] xor AData[75 - 16];
  AData[75] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[76 - 3] xor AData[76 - 8] xor AData[76 - 14] xor AData[76 - 16];
  AData[76] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[77 - 3] xor AData[77 - 8] xor AData[77 - 14] xor AData[77 - 16];
  AData[77] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[78 - 3] xor AData[78 - 8] xor AData[78 - 14] xor AData[78 - 16];
  AData[78] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  LScheduleTemp := AData[79 - 3] xor AData[79 - 8] xor AData[79 - 14] xor AData[79 - 16];
  AData[79] := TBitOperations.RotateLeft32(LScheduleTemp, 1);

{$ELSE}
  for LIdx := 16 to 79 do
  begin
    LScheduleTemp := AData[LIdx - 3] xor AData[LIdx - 8] xor AData[LIdx - 14] xor AData
      [LIdx - 16];
    AData[LIdx] := TBitOperations.RotateLeft32(LScheduleTemp, 1);
  end;
{$ENDIF USE_UNROLLED_VARIANT}
end;

initialization
  SHA1_Compress := TSHA1Simd.Select(@SHA1_Compress_Scalar);

end.
