unit HlpSHA2_256ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA2_256Base;

type
  /// <summary>
  /// Arm SIMD backend for SHA-256: owns the AArch64 FEAT_SHA256 crypto-extension
  /// kernel (body in <c>Include\Simd\SHA256\</c>) and the runtime feature check
  /// via <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm
  /// SIMD, <c>Select</c> just returns the scalar routine.
  /// </summary>
  TSHA2_256ArmBackend = class sealed
  public
    class function Select(AScalar: TSHA256CompressProc): TSHA256CompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures;

// =============================================================================
// SIMD kernels
//   aarch64: SHA256 Crypto Extensions
// =============================================================================

procedure SHA256_Compress_CryptoExt(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressCryptoExt_aarch64.inc}
end;

procedure SHA256_Compress_CryptoExt_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_CryptoExt(AState, AData, ANumBlocks, @K256);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA2_256ArmBackend }

class function TSHA2_256ArmBackend.Select(AScalar: TSHA256CompressProc): TSHA256CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA256() then
    Exit(@SHA256_Compress_CryptoExt_Wrap);
{$ENDIF}
  Result := AScalar;
end;

end.
