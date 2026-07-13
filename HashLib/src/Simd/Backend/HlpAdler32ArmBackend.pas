unit HlpAdler32ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpAdler32;

type
  /// <summary>
  /// Arm SIMD backend for Adler-32: owns the AArch64 NEON block-processing kernel
  /// (body in <c>Include\Simd\Adler32\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - without Arm SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TAdler32ArmBackend = class sealed
  public
    class function Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc; static;
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

procedure Adler32_ProcessBlocks_Neon(AData: PByte; ANumBlocks: UInt32;
  ASums, AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Adler32\Adler32BlocksNeon_aarch64.inc}
end;

procedure Adler32_Update_Neon(AData: PByte; ALength: UInt32; ASums: Pointer);
begin
  Adler32_Update_Simd(AData, ALength, ASums, @Adler32_ProcessBlocks_Neon);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TAdler32ArmBackend }

class function TAdler32ArmBackend.Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@Adler32_Update_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
