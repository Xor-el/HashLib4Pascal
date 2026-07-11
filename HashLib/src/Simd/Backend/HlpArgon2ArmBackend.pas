unit HlpArgon2ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_Argon2NotBuildInAdapter;

type
  /// <summary>
  /// Arm SIMD backend for Argon2's fill-block: owns the AArch64 NEON kernel (body
  /// in <c>Include\Simd\Argon2\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TArgon2ArmBackend = class sealed
  public
    class function Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc; static;
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

procedure Argon2_FillBlock_Neon(ALeft, ARight, ACurrent: Pointer; AWithXor: Int32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Argon2\Argon2FillBlockNeon_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TArgon2ArmBackend }

class function TArgon2ArmBackend.Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@Argon2_FillBlock_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
