unit HlpBlake2BArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2B;

type
  /// <summary>
  /// Arm SIMD backend for Blake2B: owns the AArch64 NEON compression kernel
  /// (body in <c>Include\Simd\Blake2B\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TBlake2BArmBackend = class sealed
  public
    class function Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc; static;
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

procedure Blake2B_Compress_Neon(AState, AMsg, ACounterFlags, AIV: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Blake2B\Blake2BCompressNeon_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TBlake2BArmBackend }

class function TBlake2BArmBackend.Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@Blake2B_Compress_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
