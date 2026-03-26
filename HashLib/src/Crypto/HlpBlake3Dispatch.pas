unit HlpBlake3Dispatch;

{$I ..\Include\HashLib.inc}

interface

type
  TBlake3CompressProc = procedure(AState, AMsg, ACV, ACounterFlags: Pointer);

  // Hash N complete chunks in parallel.
  // AInput: pointer to N * 1024 bytes of contiguous input
  // AKey: pointer to 8 x UInt32 key/IV
  // AOut: pointer to N * 8 x UInt32 output chaining values
  // ANumChunks: number of chunks to hash
  // ACounter: starting chunk counter
  // AFlags: base flags (chunk start/end handled internally)
  TBlake3HashManyProc = procedure(AInput, AKey, AOut: Pointer;
    ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);

var
  Blake3_Compress: TBlake3CompressProc;
  Blake3_HashMany: TBlake3HashManyProc;
  Blake3_ParallelDegree: Int32;

implementation

uses
  HlpBits,
  HlpSimd;

const
  Blake3IV: array [0 .. 3] of UInt32 = (
    UInt32($6A09E667), UInt32($BB67AE85),
    UInt32($3C6EF372), UInt32($A54FF53A)
  );

  FlagChunkStart = UInt32(1 shl 0);
  FlagChunkEnd = UInt32(1 shl 1);

// =============================================================================
// Scalar fallback implementation (fully unrolled, 7 rounds, inlined G)
// =============================================================================

procedure Blake3_Compress_Scalar(AState, AMsg, ACV, ACounterFlags: Pointer);
var
  LV0, LV1, LV2, LV3, LV4, LV5, LV6, LV7: UInt32;
  LV8, LV9, LV10, LV11, LV12, LV13, LV14, LV15: UInt32;
  LPMsg, LPCV, LPCounterFlags, LPState: PCardinal;
begin
  LPMsg := PCardinal(AMsg);
  LPCV := PCardinal(ACV);
  LPCounterFlags := PCardinal(ACounterFlags);
  LPState := PCardinal(AState);

  // Initialize state from chaining value
  LV0 := LPCV[0];
  LV1 := LPCV[1];
  LV2 := LPCV[2];
  LV3 := LPCV[3];
  LV4 := LPCV[4];
  LV5 := LPCV[5];
  LV6 := LPCV[6];
  LV7 := LPCV[7];
  // Initialize counter half from IV and counter/flags
  LV8 := Blake3IV[0];
  LV9 := Blake3IV[1];
  LV10 := Blake3IV[2];
  LV11 := Blake3IV[3];
  LV12 := LPCounterFlags[0];
  LV13 := LPCounterFlags[1];
  LV14 := LPCounterFlags[2];
  LV15 := LPCounterFlags[3];

  // Round 0
  LV0 := LV0 + LV4 + LPMsg[0];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[1];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[2];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[3];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[4];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[5];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[6];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[7];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[8];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[9];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[10];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[11];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[12];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[13];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[14];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[15];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 1
  LV0 := LV0 + LV4 + LPMsg[2];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[6];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[3];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[10];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[7];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[0];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[4];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[13];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[1];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[11];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[12];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[5];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[9];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[14];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[15];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[8];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 2
  LV0 := LV0 + LV4 + LPMsg[3];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[4];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[10];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[12];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[13];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[2];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[7];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[14];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[6];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[5];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[9];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[0];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[11];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[15];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[8];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[1];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 3
  LV0 := LV0 + LV4 + LPMsg[10];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[7];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[12];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[9];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[14];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[3];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[13];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[15];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[4];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[0];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[11];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[2];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[5];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[8];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[1];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[6];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 4
  LV0 := LV0 + LV4 + LPMsg[12];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[13];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[9];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[11];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[15];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[10];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[14];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[8];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[7];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[2];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[5];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[3];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[0];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[1];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[6];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[4];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 5
  LV0 := LV0 + LV4 + LPMsg[9];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[14];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[11];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[5];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[8];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[12];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[15];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[1];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[13];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[3];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[0];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[10];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[2];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[6];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[4];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[7];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Round 6
  LV0 := LV0 + LV4 + LPMsg[11];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 16);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 12);
  LV0 := LV0 + LV4 + LPMsg[15];
  LV12 := TBits.RotateRight32(LV12 xor LV0, 8);
  LV8 := LV8 + LV12;
  LV4 := TBits.RotateRight32(LV4 xor LV8, 7);
  LV1 := LV1 + LV5 + LPMsg[5];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 16);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 12);
  LV1 := LV1 + LV5 + LPMsg[0];
  LV13 := TBits.RotateRight32(LV13 xor LV1, 8);
  LV9 := LV9 + LV13;
  LV5 := TBits.RotateRight32(LV5 xor LV9, 7);
  LV2 := LV2 + LV6 + LPMsg[1];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 16);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 12);
  LV2 := LV2 + LV6 + LPMsg[9];
  LV14 := TBits.RotateRight32(LV14 xor LV2, 8);
  LV10 := LV10 + LV14;
  LV6 := TBits.RotateRight32(LV6 xor LV10, 7);
  LV3 := LV3 + LV7 + LPMsg[8];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 16);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 12);
  LV3 := LV3 + LV7 + LPMsg[6];
  LV15 := TBits.RotateRight32(LV15 xor LV3, 8);
  LV11 := LV11 + LV15;
  LV7 := TBits.RotateRight32(LV7 xor LV11, 7);
  LV0 := LV0 + LV5 + LPMsg[14];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 16);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 12);
  LV0 := LV0 + LV5 + LPMsg[10];
  LV15 := TBits.RotateRight32(LV15 xor LV0, 8);
  LV10 := LV10 + LV15;
  LV5 := TBits.RotateRight32(LV5 xor LV10, 7);
  LV1 := LV1 + LV6 + LPMsg[2];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 16);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 12);
  LV1 := LV1 + LV6 + LPMsg[12];
  LV12 := TBits.RotateRight32(LV12 xor LV1, 8);
  LV11 := LV11 + LV12;
  LV6 := TBits.RotateRight32(LV6 xor LV11, 7);
  LV2 := LV2 + LV7 + LPMsg[3];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 16);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 12);
  LV2 := LV2 + LV7 + LPMsg[4];
  LV13 := TBits.RotateRight32(LV13 xor LV2, 8);
  LV8 := LV8 + LV13;
  LV7 := TBits.RotateRight32(LV7 xor LV8, 7);
  LV3 := LV3 + LV4 + LPMsg[7];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 16);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 12);
  LV3 := LV3 + LV4 + LPMsg[13];
  LV14 := TBits.RotateRight32(LV14 xor LV3, 8);
  LV9 := LV9 + LV14;
  LV4 := TBits.RotateRight32(LV4 xor LV9, 7);

  // Finalization: XOR top and bottom halves
  LPState[0] := LV0 xor LV8;
  LPState[1] := LV1 xor LV9;
  LPState[2] := LV2 xor LV10;
  LPState[3] := LV3 xor LV11;
  LPState[4] := LV4 xor LV12;
  LPState[5] := LV5 xor LV13;
  LPState[6] := LV6 xor LV14;
  LPState[7] := LV7 xor LV15;
  LPState[8] := LV8 xor LPCV[0];
  LPState[9] := LV9 xor LPCV[1];
  LPState[10] := LV10 xor LPCV[2];
  LPState[11] := LV11 xor LPCV[3];
  LPState[12] := LV12 xor LPCV[4];
  LPState[13] := LV13 xor LPCV[5];
  LPState[14] := LV14 xor LPCV[6];
  LPState[15] := LV15 xor LPCV[7];
end;

// =============================================================================
// Scalar HashMany fallback (sequential, no parallelism)
// =============================================================================

procedure Blake3_HashMany_Scalar(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LChunk, LBlock: Int32;
  LCV: array [0 .. 7] of UInt32;
  LBlockWords: array [0 .. 15] of UInt32;
  LState: array [0 .. 15] of UInt32;
  LCounterFlags: array [0 .. 3] of UInt32;
  LBlockFlags: UInt32;
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);

  for LChunk := 0 to ANumChunks - 1 do
  begin
    // Initialize CV from key/IV
    System.Move(AKey^, LCV[0], 8 * System.SizeOf(UInt32));

    // Process 16 blocks per chunk
    for LBlock := 0 to 15 do
    begin
      // Convert block bytes to words (little-endian, which is native on x86)
      System.Move(LPInput^, LBlockWords[0], 64);

      // Set flags for this block
      LBlockFlags := AFlags;
      if LBlock = 0 then
        LBlockFlags := LBlockFlags or FlagChunkStart;
      if LBlock = 15 then
        LBlockFlags := LBlockFlags or FlagChunkEnd;

      LCounterFlags[0] := UInt32(ACounter);
      LCounterFlags[1] := UInt32(ACounter shr 32);
      LCounterFlags[2] := 64; // BlockLen = 64
      LCounterFlags[3] := LBlockFlags;

      Blake3_Compress(@LState[0], @LBlockWords[0], @LCV[0], @LCounterFlags[0]);

      // Extract chaining value (first 8 words of output)
      if LBlock < 15 then
        System.Move(LState[0], LCV[0], 8 * System.SizeOf(UInt32));

      System.Inc(LPInput, 64);
    end;

    // Write final chaining value for this chunk
    System.Move(LState[0], LPOut^, 8 * System.SizeOf(UInt32));
    System.Inc(LPOut, 8 * System.SizeOf(UInt32));
    System.Inc(ACounter);
  end;
end;

// =============================================================================
// SSE2 and AVX2 implementations (x86-64 only)
// =============================================================================

{$IFDEF HASHLIB_X86_64}

procedure Blake3_Compress_Sse2(AState, AMsg, ACV, ACounterFlags: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3CompressSse2.inc}
end;

procedure Blake3_Compress_Avx2(AState, AMsg, ACV, ACounterFlags: Pointer);
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3CompressAvx2.inc}
end;

procedure Blake3_Hash4_Sse2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
  {$I ..\Include\Simd\Common\SimdProc6Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3Hash4Sse2.inc}
end;

procedure Blake3_Hash8_Avx2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
  {$I ..\Include\Simd\Common\SimdProc6Begin.inc}
  {$I ..\Include\Simd\Blake3\Blake3Hash8Avx2.inc}
end;

// Cascade wrappers matching the official BLAKE3 dispatch pattern:
// AVX2 hash_many: hash8 -> delegate remainder to SSE2 hash_many
// SSE2 hash_many: hash4 -> delegate remainder to scalar hash_many

procedure Blake3_HashMany_Sse2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 4 do
  begin
    Blake3_Hash4_Sse2(LPInput, AKey, LPOut, 4, ACounter, AFlags);
    System.Inc(LPInput, 4 * 1024);
    System.Inc(LPOut, 4 * 32);
    System.Inc(ACounter, 4);
    System.Dec(ANumChunks, 4);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Scalar(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

procedure Blake3_HashMany_Avx2(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 8 do
  begin
    Blake3_Hash8_Avx2(LPInput, AKey, LPOut, 8, ACounter, AFlags);
    System.Inc(LPInput, 8 * 1024);
    System.Inc(LPOut, 8 * 32);
    System.Inc(ACounter, 8);
    System.Dec(ANumChunks, 8);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Sse2(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

{$ENDIF HASHLIB_X86_64}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();
begin
  Blake3_Compress := @Blake3_Compress_Scalar;
  Blake3_HashMany := @Blake3_HashMany_Scalar;
  Blake3_ParallelDegree := 1;
{$IFDEF HASHLIB_X86_64}
  case TSimd.GetActiveLevel() of
    TSimdLevel.AVX2:
    begin
      Blake3_Compress := @Blake3_Compress_Avx2;
      Blake3_HashMany := @Blake3_HashMany_Avx2;
      Blake3_ParallelDegree := 8;
    end;
    TSimdLevel.SSE2, TSimdLevel.SSSE3:
    begin
      Blake3_Compress := @Blake3_Compress_Sse2;
      Blake3_HashMany := @Blake3_HashMany_Sse2;
      Blake3_ParallelDegree := 4;
    end;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
