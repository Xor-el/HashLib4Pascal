unit HlpBlake3ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake3;

type
  /// <summary>
  /// Arm SIMD backend for Blake3: owns the AArch64 NEON compression and 4-way
  /// hash-many kernels (bodies in <c>Include\Simd\Blake3\</c>) and the runtime
  /// tier selection via <c>TCpuFeatures.Arm</c>. The hash-many wrapper processes
  /// full 4-way groups in asm and delegates the remainder to the scalar
  /// hash-many. Compiles on every target - without Arm SIMD the selectors return
  /// the scalar routines / degree 1.
  /// </summary>
  TBlake3ArmBackend = class sealed
  public
    class function SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc; static;
    class function SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc; static;
    class function SelectParallelDegree(ADefault: Int32): Int32; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   aarch64: NEON
// =============================================================================

procedure Blake3_Compress_Neon(AState, AMsg, ACV, ACounterFlags: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3CompressNeon_aarch64.inc}
end;

procedure Blake3_Hash4_Neon(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc6Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Blake3\Blake3Hash4Neon_aarch64.inc}
end;

// NEON hash_many: hash4 -> delegate remainder to scalar hash_many
procedure Blake3_HashMany_Neon(AInput, AKey, AOut: Pointer;
  ANumChunks: Int32; ACounter: UInt64; AFlags: UInt32);
var
  LPInput, LPOut: PByte;
begin
  LPInput := PByte(AInput);
  LPOut := PByte(AOut);
  while ANumChunks >= 4 do
  begin
    Blake3_Hash4_Neon(LPInput, AKey, LPOut, 4, ACounter, AFlags);
    System.Inc(LPInput, 4 * 1024);
    System.Inc(LPOut, 4 * 32);
    System.Inc(ACounter, 4);
    System.Dec(ANumChunks, 4);
  end;
  if ANumChunks > 0 then
    Blake3_HashMany_Scalar(LPInput, AKey, LPOut, ANumChunks, ACounter, AFlags);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TBlake3ArmBackend }

class function TBlake3ArmBackend.SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@Blake3_Compress_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TBlake3ArmBackend.SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@Blake3_HashMany_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TBlake3ArmBackend.SelectParallelDegree(ADefault: Int32): Int32;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(4);
  end;
{$ENDIF}
  Result := ADefault;
end;

end.
