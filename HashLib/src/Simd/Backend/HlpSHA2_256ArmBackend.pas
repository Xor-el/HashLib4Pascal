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
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // K256 with a trailing zero terminator for the pure-GPR kernel: its
  // message-schedule loop ends when the loaded K word is zero (cbnz), like
  // the original's sentinel-terminated table - the plain K256 const cannot
  // drive that loop. The crypto-extension kernel keeps using K256.
  K256_Gpr: array [0 .. 64] of UInt32 = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5,
    $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3,
    $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7,
    $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13,
    $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3,
    $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5,
    $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2,
    0  // terminator - the schedule loop ends on a zero K word
  );

// =============================================================================
// SIMD kernels
//   aarch64: SHA256 Crypto Extensions, NEON
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

procedure SHA256_Compress_Gpr(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA256\SHA256CompressGpr_aarch64.inc}
end;

procedure SHA256_Compress_Gpr_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA256_Compress_Gpr(AState, AData, ANumBlocks, @K256_Gpr);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA2_256ArmBackend }

class function TSHA2_256ArmBackend.Select(AScalar: TSHA256CompressProc): TSHA256CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA256() then
    Exit(@SHA256_Compress_CryptoExt_Wrap);
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@SHA256_Compress_Gpr_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
