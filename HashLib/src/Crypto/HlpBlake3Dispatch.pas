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
  v0, v1, v2, v3, v4, v5, v6, v7: UInt32;
  v8, v9, v10, v11, v12, v13, v14, v15: UInt32;
  LPMsg, LPCV, LPCounterFlags, LPState: PCardinal;
begin
  LPMsg := PCardinal(AMsg);
  LPCV := PCardinal(ACV);
  LPCounterFlags := PCardinal(ACounterFlags);
  LPState := PCardinal(AState);

  // Initialize state from chaining value
  v0 := LPCV[0];
  v1 := LPCV[1];
  v2 := LPCV[2];
  v3 := LPCV[3];
  v4 := LPCV[4];
  v5 := LPCV[5];
  v6 := LPCV[6];
  v7 := LPCV[7];
  // Initialize counter half from IV and counter/flags
  v8 := Blake3IV[0];
  v9 := Blake3IV[1];
  v10 := Blake3IV[2];
  v11 := Blake3IV[3];
  v12 := LPCounterFlags[0];
  v13 := LPCounterFlags[1];
  v14 := LPCounterFlags[2];
  v15 := LPCounterFlags[3];

  // Round 0
  v0 := v0 + v4 + LPMsg[0];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[1];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[2];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[3];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[4];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[5];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[6];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[7];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[8];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[9];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[10];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[11];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[12];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[13];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[14];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[15];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 1
  v0 := v0 + v4 + LPMsg[2];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[6];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[3];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[10];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[7];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[0];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[4];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[13];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[1];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[11];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[12];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[5];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[9];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[14];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[15];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[8];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 2
  v0 := v0 + v4 + LPMsg[3];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[4];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[10];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[12];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[13];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[2];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[7];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[14];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[6];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[5];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[9];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[0];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[11];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[15];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[8];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[1];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 3
  v0 := v0 + v4 + LPMsg[10];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[7];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[12];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[9];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[14];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[3];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[13];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[15];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[4];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[0];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[11];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[2];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[5];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[8];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[1];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[6];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 4
  v0 := v0 + v4 + LPMsg[12];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[13];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[9];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[11];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[15];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[10];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[14];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[8];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[7];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[2];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[5];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[3];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[0];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[1];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[6];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[4];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 5
  v0 := v0 + v4 + LPMsg[9];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[14];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[11];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[5];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[8];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[12];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[15];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[1];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[13];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[3];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[0];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[10];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[2];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[6];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[4];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[7];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Round 6
  v0 := v0 + v4 + LPMsg[11];
  v12 := TBits.RotateRight32(v12 xor v0, 16);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 12);
  v0 := v0 + v4 + LPMsg[15];
  v12 := TBits.RotateRight32(v12 xor v0, 8);
  v8 := v8 + v12;
  v4 := TBits.RotateRight32(v4 xor v8, 7);
  v1 := v1 + v5 + LPMsg[5];
  v13 := TBits.RotateRight32(v13 xor v1, 16);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 12);
  v1 := v1 + v5 + LPMsg[0];
  v13 := TBits.RotateRight32(v13 xor v1, 8);
  v9 := v9 + v13;
  v5 := TBits.RotateRight32(v5 xor v9, 7);
  v2 := v2 + v6 + LPMsg[1];
  v14 := TBits.RotateRight32(v14 xor v2, 16);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 12);
  v2 := v2 + v6 + LPMsg[9];
  v14 := TBits.RotateRight32(v14 xor v2, 8);
  v10 := v10 + v14;
  v6 := TBits.RotateRight32(v6 xor v10, 7);
  v3 := v3 + v7 + LPMsg[8];
  v15 := TBits.RotateRight32(v15 xor v3, 16);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 12);
  v3 := v3 + v7 + LPMsg[6];
  v15 := TBits.RotateRight32(v15 xor v3, 8);
  v11 := v11 + v15;
  v7 := TBits.RotateRight32(v7 xor v11, 7);
  v0 := v0 + v5 + LPMsg[14];
  v15 := TBits.RotateRight32(v15 xor v0, 16);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 12);
  v0 := v0 + v5 + LPMsg[10];
  v15 := TBits.RotateRight32(v15 xor v0, 8);
  v10 := v10 + v15;
  v5 := TBits.RotateRight32(v5 xor v10, 7);
  v1 := v1 + v6 + LPMsg[2];
  v12 := TBits.RotateRight32(v12 xor v1, 16);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 12);
  v1 := v1 + v6 + LPMsg[12];
  v12 := TBits.RotateRight32(v12 xor v1, 8);
  v11 := v11 + v12;
  v6 := TBits.RotateRight32(v6 xor v11, 7);
  v2 := v2 + v7 + LPMsg[3];
  v13 := TBits.RotateRight32(v13 xor v2, 16);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 12);
  v2 := v2 + v7 + LPMsg[4];
  v13 := TBits.RotateRight32(v13 xor v2, 8);
  v8 := v8 + v13;
  v7 := TBits.RotateRight32(v7 xor v8, 7);
  v3 := v3 + v4 + LPMsg[7];
  v14 := TBits.RotateRight32(v14 xor v3, 16);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 12);
  v3 := v3 + v4 + LPMsg[13];
  v14 := TBits.RotateRight32(v14 xor v3, 8);
  v9 := v9 + v14;
  v4 := TBits.RotateRight32(v4 xor v9, 7);

  // Finalization: XOR top and bottom halves
  LPState[0] := v0 xor v8;
  LPState[1] := v1 xor v9;
  LPState[2] := v2 xor v10;
  LPState[3] := v3 xor v11;
  LPState[4] := v4 xor v12;
  LPState[5] := v5 xor v13;
  LPState[6] := v6 xor v14;
  LPState[7] := v7 xor v15;
  LPState[8] := v8 xor LPCV[0];
  LPState[9] := v9 xor LPCV[1];
  LPState[10] := v10 xor LPCV[2];
  LPState[11] := v11 xor LPCV[3];
  LPState[12] := v12 xor LPCV[4];
  LPState[13] := v13 xor LPCV[5];
  LPState[14] := v14 xor LPCV[6];
  LPState[15] := v15 xor LPCV[7];
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
