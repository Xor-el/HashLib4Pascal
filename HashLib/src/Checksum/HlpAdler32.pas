unit HlpAdler32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBinaryPrimitives,
  HlpHashLibTypes,
  HlpIHashInfo,
  HlpHash,
  HlpIHash,
  HlpHashResult,
  HlpIHashResult;

type
  TAdler32UpdateProc = procedure(AData: PByte; ALength: UInt32; ASums: Pointer);
  TAdler32ProcessBlocksProc = procedure(AData: PByte; ANumBlocks: UInt32;
    ASums, AConstants: Pointer);

var
  Adler32_Update: TAdler32UpdateProc;

// Shared SIMD chunking driver, exposed so each backend's Update wrapper can feed
// it the backend's block-processing kernel.
procedure Adler32_Update_Simd(AData: PByte; ALength: UInt32; ASums: Pointer;
  AProcessBlocks: TAdler32ProcessBlocksProc);

type
  TAdler32 = class sealed(THash, IChecksum, IHash32, ITransformBlock)

  strict private
  var
    FSumA, FSumB: UInt32;

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;

  end;

implementation

uses
  HlpAdler32Simd;

const
  ModAdler = UInt32(65521);
  NMAX = UInt32(5552);
 // MAX_BLOCKS_PER_CHUNK = NMAX div UInt32(32); // 173

  Adler32Constants: array [0 .. 63] of Byte = (
    // Offset 0..31: weights [32,31,...,1]
    // SSE2/SSSE3 use as two 16-byte halves; AVX2 uses full 32 bytes.
    32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10,  9,  8,  7,  6,  5,  4,  3,  2,  1,
    // Offset 32..63: ones_16 (16-bit value 1 in little-endian, repeated)
    // SSSE3 uses first 16 bytes; AVX2 uses all 32 bytes.
    1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
    1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0
  );

// =============================================================================
// Scalar fallback implementation
// =============================================================================

procedure Adler32_Update_Scalar(AData: PByte; ALength: UInt32; ASums: Pointer);
var
  LChunkLen: UInt32;
  LPSumA, LPSumB: PUInt32;
begin
  LPSumA := PUInt32(ASums);
  LPSumB := PUInt32(PByte(ASums) + SizeOf(UInt32));

  while ALength > 0 do
  begin
    LChunkLen := ALength;
    if LChunkLen > NMAX then
      LChunkLen := NMAX;
    Dec(ALength, LChunkLen);

    while LChunkLen > 0 do
    begin
      LPSumA^ := LPSumA^ + AData^;
      LPSumB^ := LPSumB^ + LPSumA^;
      Inc(AData);
      Dec(LChunkLen);
    end;

    LPSumA^ := LPSumA^ mod ModAdler;
    LPSumB^ := LPSumB^ mod ModAdler;
  end;
end;

procedure Adler32_Update_Simd(AData: PByte; ALength: UInt32; ASums: Pointer;
  AProcessBlocks: TAdler32ProcessBlocksProc);
const
  BLOCK_SIZE = UInt32(32);
var
  LChunkLen, LBlocks: UInt32;
  LPSumA, LPSumB: PUInt32;
begin
  LPSumA := PUInt32(ASums);
  LPSumB := PUInt32(PByte(ASums) + SizeOf(UInt32));

  while ALength > 0 do
  begin
    LChunkLen := ALength;
    if LChunkLen > NMAX then
      LChunkLen := NMAX;
    Dec(ALength, LChunkLen);

    LBlocks := LChunkLen div BLOCK_SIZE;
    if LBlocks > 0 then
    begin
      AProcessBlocks(AData, LBlocks, ASums, @Adler32Constants[0]);
      Inc(AData, LBlocks * BLOCK_SIZE);
      Dec(LChunkLen, LBlocks * BLOCK_SIZE);
    end;

    while LChunkLen > 0 do
    begin
      LPSumA^ := LPSumA^ + AData^;
      LPSumB^ := LPSumB^ + LPSumA^;
      Inc(AData);
      Dec(LChunkLen);
    end;

    LPSumA^ := LPSumA^ mod ModAdler;
    LPSumB^ := LPSumB^ mod ModAdler;
  end;
end;

{ TAdler32 }

function TAdler32.Clone(): IHash;
var
  LHashInstance: TAdler32;
begin
  LHashInstance := TAdler32.Create();
  LHashInstance.FSumA := FSumA;
  LHashInstance.FSumB := FSumB;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

constructor TAdler32.Create;
begin
  inherited Create(4, 1);
end;

procedure TAdler32.Initialize;
begin
  FSumA := 1;
  FSumB := 0;
end;

procedure TAdler32.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LSums: array [0 .. 1] of UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  LSums[0] := FSumA;
  LSums[1] := FSumB;
  Adler32_Update(PByte(AData) + AIndex, UInt32(ALength), @LSums[0]);
  FSumA := LSums[0];
  FSumB := LSums[1];
end;

function TAdler32.TransformFinal: IHashResult;
var
  LBufferBytes: THashLibByteArray;
begin
  System.SetLength(LBufferBytes, HashSize);
  TBinaryPrimitives.WriteUInt32BigEndian(LBufferBytes, 0, UInt32((FSumB shl 16) or FSumA));

  Result := THashResult.Create(LBufferBytes);
  Initialize();
end;

initialization
  Adler32_Update := TAdler32Simd.Select(@Adler32_Update_Scalar);

end.
