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
  HlpCpuFeatures,
  HlpSimdLevels;

const
  // K512 with a trailing zero terminator for the plain-GPR kernel: its
  // message-schedule loop ends when the loaded K word is zero (cbnz), like
  // the original's sentinel-terminated table - the plain K512 const cannot
  // drive that loop. The crypto-extension kernel keeps using K512.
  K512_Gpr: array [0 .. 80] of UInt64 = (
    UInt64($428A2F98D728AE22), UInt64($7137449123EF65CD),
    UInt64($B5C0FBCFEC4D3B2F), UInt64($E9B5DBA58189DBBC),
    UInt64($3956C25BF348B538), UInt64($59F111F1B605D019),
    UInt64($923F82A4AF194F9B), UInt64($AB1C5ED5DA6D8118),
    UInt64($D807AA98A3030242), UInt64($12835B0145706FBE),
    UInt64($243185BE4EE4B28C), UInt64($550C7DC3D5FFB4E2),
    UInt64($72BE5D74F27B896F), UInt64($80DEB1FE3B1696B1),
    UInt64($9BDC06A725C71235), UInt64($C19BF174CF692694),
    UInt64($E49B69C19EF14AD2), UInt64($EFBE4786384F25E3),
    UInt64($0FC19DC68B8CD5B5), UInt64($240CA1CC77AC9C65),
    UInt64($2DE92C6F592B0275), UInt64($4A7484AA6EA6E483),
    UInt64($5CB0A9DCBD41FBD4), UInt64($76F988DA831153B5),
    UInt64($983E5152EE66DFAB), UInt64($A831C66D2DB43210),
    UInt64($B00327C898FB213F), UInt64($BF597FC7BEEF0EE4),
    UInt64($C6E00BF33DA88FC2), UInt64($D5A79147930AA725),
    UInt64($06CA6351E003826F), UInt64($142929670A0E6E70),
    UInt64($27B70A8546D22FFC), UInt64($2E1B21385C26C926),
    UInt64($4D2C6DFC5AC42AED), UInt64($53380D139D95B3DF),
    UInt64($650A73548BAF63DE), UInt64($766A0ABB3C77B2A8),
    UInt64($81C2C92E47EDAEE6), UInt64($92722C851482353B),
    UInt64($A2BFE8A14CF10364), UInt64($A81A664BBC423001),
    UInt64($C24B8B70D0F89791), UInt64($C76C51A30654BE30),
    UInt64($D192E819D6EF5218), UInt64($D69906245565A910),
    UInt64($F40E35855771202A), UInt64($106AA07032BBD1B8),
    UInt64($19A4C116B8D2D0C8), UInt64($1E376C085141AB53),
    UInt64($2748774CDF8EEB99), UInt64($34B0BCB5E19B48A8),
    UInt64($391C0CB3C5C95A63), UInt64($4ED8AA4AE3418ACB),
    UInt64($5B9CCA4F7763E373), UInt64($682E6FF3D6B2B8A3),
    UInt64($748F82EE5DEFB2FC), UInt64($78A5636F43172F60),
    UInt64($84C87814A1F0AB72), UInt64($8CC702081A6439EC),
    UInt64($90BEFFFA23631E28), UInt64($A4506CEBDE82BDE9),
    UInt64($BEF9A3F7B2C67915), UInt64($C67178F2E372532B),
    UInt64($CA273ECEEA26619C), UInt64($D186B8C721C0C207),
    UInt64($EADA7DD6CDE0EB1E), UInt64($F57D4F7FEE6ED178),
    UInt64($06F067AA72176FBA), UInt64($0A637DC5A2C898A6),
    UInt64($113F9804BEF90DAE), UInt64($1B710B35131C471B),
    UInt64($28DB77F523047D84), UInt64($32CAAB7B40C72493),
    UInt64($3C9EBE0A15C9BEBC), UInt64($431D67C49C100D4C),
    UInt64($4CC5D4BECB3E42B6), UInt64($597F299CFC657E2A),
    UInt64($5FCB6FAB3AD6FAEC), UInt64($6C44198C4A475817),
    UInt64(0)  // terminator - the schedule loop ends on a zero K word
  );

// =============================================================================
// SIMD kernels
//   aarch64: SHA512 Crypto Extensions, NEON
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

procedure SHA512_Compress_Gpr(AState, AData: Pointer; ANumBlocks: UInt32;
  AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA512\SHA512CompressGpr_aarch64.inc}
end;

procedure SHA512_Compress_Gpr_Wrap(AState, AData: Pointer; ANumBlocks: UInt32);
begin
  SHA512_Compress_Gpr(AState, AData, ANumBlocks, @K512_Gpr);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA2_512ArmBackend }

class function TSHA2_512ArmBackend.Select(AScalar: TSHA512CompressProc): TSHA512CompressProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA512() then
    Exit(@SHA512_Compress_CryptoExt_Wrap);
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@SHA512_Compress_Gpr_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
