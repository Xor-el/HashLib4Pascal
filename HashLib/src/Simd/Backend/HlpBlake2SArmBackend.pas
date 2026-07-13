unit HlpBlake2SArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2S;

type
  /// <summary>
  /// Arm SIMD backend for Blake2S: owns the AArch64 NEON compression kernel
  /// (body in <c>Include\Simd\Blake2S\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TBlake2SArmBackend = class sealed
  public
    class function Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc; static;
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

procedure Blake2S_Compress_Neon(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Blake2S\Blake2SCompressNeon_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TBlake2SArmBackend }

class function TBlake2SArmBackend.Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@Blake2S_Compress_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
