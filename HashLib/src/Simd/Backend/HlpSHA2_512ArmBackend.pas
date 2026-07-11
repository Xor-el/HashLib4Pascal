unit HlpSHA2_512ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA2_512Base;

type
  /// <summary>
  /// Arm SIMD backend for SHA-512: owns the AArch64 FEAT_SHA512 crypto-extension
  /// kernel (body in <c>Include\Simd\SHA512\</c>) and the runtime feature check
  /// via <c>TCpuFeatures.Arm</c>. Compiles on every target - built without Arm
  /// SIMD, <c>Select</c> just returns the scalar routine.
  /// </summary>
  TSHA2_512ArmBackend = class sealed
  public
    class function Select(AScalar: TSHA512CompressProc): TSHA512CompressProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures;

// =============================================================================
// SIMD kernels
//   aarch64: SHA512 Crypto Extensions
// =============================================================================

procedure SHA512_Compress_CryptoExt(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA512\SHA512CompressCryptoExt_aarch64.inc}
end;

procedure SHA512_Compress_CryptoExt_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA512_Compress_CryptoExt(AState, AData, ANumBlocks, @K512);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA2_512ArmBackend }

class function TSHA2_512ArmBackend.Select(AScalar: TSHA512CompressProc): TSHA512CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA512() then
    Exit(@SHA512_Compress_CryptoExt_Wrap);
{$ENDIF}
  Result := AScalar;
end;

end.
