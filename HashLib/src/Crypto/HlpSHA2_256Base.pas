unit HlpSHA2_256Base;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBinaryPrimitives,
  HlpHashLibTypes,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn;

type
  // Block compression contract shared by the scalar reference implementation and
  // every SIMD backend: hash ANumBlocks consecutive 64-byte blocks into AState.
  TSHA256CompressProc = procedure(AState, AData: Pointer; ANumBlocks: UInt32);

var
  // The active SHA-256 block-compression routine. Assigned once at unit
  // initialization to the best implementation the running CPU supports (see the
  // SIMD facade); defaults to the scalar reference on non-accelerated targets.
  SHA256_Compress: TSHA256CompressProc;

const
  // K256 round constants (64 UInt32 = 256 bytes).
  K256: array [0 .. 63] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2
  );

type
  TSHA2_256Base = class abstract(TBlockHash, ICryptoNotBuildIn, ITransformBlock)
  strict protected
  var
    FState: THashLibUInt32Array;

    constructor Create(AHashSize: Int32);

    procedure Finish(); override;
    procedure TransformBlock(AData: PByte; ADataLength: Int32;
      AIndex: Int32); override;

  public
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;

  end;

implementation

uses
  HlpBitOperations,
  HlpSHA2_256Simd;

// =============================================================================
// Scalar reference implementation
// =============================================================================

procedure SHA256_Compress_Scalar(AState, AData: Pointer; ANumBlocks: UInt32);
var
  LPState: PCardinal;
  LPData: PByte;
  LA, LB, LC, LD, LE, LF, LG, LH, LT1, LT2: UInt32;
  LW: array [0 .. 63] of UInt32;
  LRound: Int32;
begin
  LPState := PCardinal(AState);
  LPData := PByte(AData);

  while ANumBlocks > 0 do
  begin
    TBinaryPrimitives.CopyUInt32BigEndian(LPData, 0, @LW[0], 0, 64);

    for LRound := 16 to 63 do
    begin
      LT1 := LW[LRound - 2];
      LT2 := LW[LRound - 15];
      LW[LRound] := (TBitOperations.RotateRight32(LT1, 17) xor TBitOperations.RotateRight32(LT1, 19)
        xor (LT1 shr 10)) + LW[LRound - 7] +
        (TBitOperations.RotateRight32(LT2, 7) xor TBitOperations.RotateRight32(LT2, 18)
        xor (LT2 shr 3)) + LW[LRound - 16];
    end;

    LA := LPState[0]; LB := LPState[1]; LC := LPState[2]; LD := LPState[3];
    LE := LPState[4]; LF := LPState[5]; LG := LPState[6]; LH := LPState[7];

    for LRound := 0 to 63 do
    begin
      LT1 := LH + (TBitOperations.RotateRight32(LE, 6) xor TBitOperations.RotateRight32(LE, 11)
        xor TBitOperations.RotateRight32(LE, 25)) + ((LE and LF) xor (not LE and LG))
        + K256[LRound] + LW[LRound];
      LT2 := (TBitOperations.RotateRight32(LA, 2) xor TBitOperations.RotateRight32(LA, 13)
        xor TBitOperations.RotateRight32(LA, 22)) +
        ((LA and LB) xor (LA and LC) xor (LB and LC));
      LH := LG; LG := LF; LF := LE; LE := LD + LT1;
      LD := LC; LC := LB; LB := LA; LA := LT1 + LT2;
    end;

    LPState[0] := LPState[0] + LA; LPState[1] := LPState[1] + LB;
    LPState[2] := LPState[2] + LC; LPState[3] := LPState[3] + LD;
    LPState[4] := LPState[4] + LE; LPState[5] := LPState[5] + LF;
    LPState[6] := LPState[6] + LG; LPState[7] := LPState[7] + LH;

    System.FillChar(LW, System.SizeOf(LW), 0);
    System.Inc(LPData, 64);
    System.Dec(ANumBlocks);
  end;
end;

{ TSHA2_256Base }

constructor TSHA2_256Base.Create(AHashSize: Int32);
begin
  inherited Create(AHashSize, 64);
  System.SetLength(FState, 8);
end;

procedure TSHA2_256Base.Finish;
var
  LBits: UInt64;
  LPadIndex: Int32;
  LPad: THashLibByteArray;
begin
  LBits := FProcessedBytesCount * 8;
  if (FBuffer.Position < 56) then
  begin
    LPadIndex := (56 - FBuffer.Position)
  end
  else
  begin
    LPadIndex := (120 - FBuffer.Position);
  end;
  System.SetLength(LPad, LPadIndex + 8);
  LPad[0] := $80;

  TBinaryPrimitives.WriteUInt64BigEndian(LPad, LPadIndex, LBits);

  LPadIndex := LPadIndex + 8;

  TransformBytes(LPad, 0, LPadIndex);
end;

procedure TSHA2_256Base.TransformBlock(AData: PByte; ADataLength: Int32;
  AIndex: Int32);
begin
  SHA256_Compress(@FState[0], AData + AIndex, 1);
end;

procedure TSHA2_256Base.TransformBytes(const AData: THashLibByteArray;
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
    SHA256_Compress(@FState[0], LPtrData + AIndex, UInt32(LBlockCount));
    AIndex := AIndex + (LBlockCount * FBuffer.Length);
    ALength := ALength - (LBlockCount * FBuffer.Length);
  end;

  if (ALength > 0) then
  begin
    FBuffer.Feed(LPtrData, System.Length(AData), AIndex, ALength,
      FProcessedBytesCount);
  end;
end;

initialization
  SHA256_Compress := TSHA2_256Simd.Select(@SHA256_Compress_Scalar);

end.
