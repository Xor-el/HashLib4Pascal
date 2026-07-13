unit HlpCRCArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpCRCCore;

type
  /// <summary>
  /// Arm SIMD backend for CRC's fold: owns the PMULL kernels (bodies in
  /// <c>Include\Simd\CRC\</c>) and the runtime tier selection via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm SIMD,
  /// <c>Select</c> just returns the scalar routines.
  /// </summary>
  TCRCArmBackend = class sealed
  public
    class function Select(AReflectedScalar, AForwardScalar: TCRCFoldFunc)
      : TCRCFoldSelection; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures;

// =============================================================================
// SIMD kernels
//   aarch64: PMULL
// =============================================================================

function CRC_Fold_Reflected_Pmull(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedPmull_aarch64.inc}
end;

function CRC_Fold_Forward_Pmull(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardPmull_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TCRCArmBackend }

class function TCRCArmBackend.Select(AReflectedScalar,
  AForwardScalar: TCRCFoldFunc): TCRCFoldSelection;
begin
  Result.Reflected := AReflectedScalar;
  Result.Fwd := AForwardScalar;
  Result.UsesCarrylessMul := False;

{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasPMULL() then
  begin
    Result.Reflected := @CRC_Fold_Reflected_Pmull;
    Result.Fwd := @CRC_Fold_Forward_Pmull;
    Result.UsesCarrylessMul := True;
  end;
{$ENDIF HASHLIB_AARCH64_ASM}
end;

end.
