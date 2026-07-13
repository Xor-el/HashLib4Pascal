unit HlpSHA1ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA1;

type
  /// <summary>
  /// Arm SIMD backend for SHA-1: owns the AArch64 FEAT_SHA1 crypto-extension
  /// kernel (body in <c>Include\Simd\SHA1\</c>) and the runtime feature check via
  /// <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm SIMD,
  /// <c>Select</c> just returns the scalar routine.
  /// </summary>
  TSHA1ArmBackend = class sealed
  public
    class function Select(AScalar: TSHA1CompressProc): TSHA1CompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   aarch64: SHA1 Crypto Extensions, NEON
// =============================================================================

procedure SHA1_Compress_CryptoExt(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressCryptoExt_aarch64.inc}
end;

procedure SHA1_Compress_CryptoExt_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA1_Compress_CryptoExt(AState, AData, ANumBlocks, @K_SHA1);
end;

procedure SHA1_Compress_Gpr(AState, AData: Pointer; ANumBlocks: UInt32);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA1\SHA1CompressGpr_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA1ArmBackend }

class function TSHA1ArmBackend.Select(AScalar: TSHA1CompressProc): TSHA1CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA1() then
    Exit(@SHA1_Compress_CryptoExt_Wrap);
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@SHA1_Compress_Gpr);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
