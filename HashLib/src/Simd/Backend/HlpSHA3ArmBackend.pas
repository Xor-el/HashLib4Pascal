unit HlpSHA3ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA3;

type
  /// <summary>
  /// Arm SIMD backend for Keccak-F1600: owns the AArch64 FEAT_SHA3 crypto-
  /// extension permute / absorb kernels (bodies in <c>Include\Simd\SHA3\</c>) and
  /// the runtime feature check via <c>TCpuFeatures.Arm</c>. Compiles on every
  /// target - without Arm SIMD the selectors return the scalar routines.
  /// </summary>
  TSHA3ArmBackend = class sealed
  public
    class function SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc; static;
    class function SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   aarch64: SHA3 Crypto Extensions, NEON
//
// Both kernels reuse the plain RC round-constant table directly (the
// FEAT_SHA3 asm broadcasts each 64-bit iota with ld1r; the GPR permute walks
// it behind an end-pointer), so no packed constant block is needed.
// =============================================================================

procedure KeccakF1600_CryptoExt(AState: Pointer; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600CryptoExt_aarch64.inc}
end;

procedure KeccakF1600_CryptoExt_Wrap(AState: Pointer);
begin
  KeccakF1600_CryptoExt(AState, @RC);
end;

procedure KeccakF1600_CryptoExt_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600CryptoExtAbsorb_aarch64.inc}
end;

procedure KeccakF1600_CryptoExt_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_CryptoExt_Absorb(AState, AData, ABlockCount, ABlockSize, @RC);
end;

procedure KeccakF1600_Gpr(AState: Pointer; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600Gpr_aarch64.inc}
end;

procedure KeccakF1600_Gpr_Wrap(AState: Pointer);
begin
  KeccakF1600_Gpr(AState, @RC);
end;

procedure KeccakF1600_Gpr_Absorb(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32; AConstants: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc5Begin_aarch64.inc}
  {$I ..\..\Include\Simd\SHA3\KeccakF1600GprAbsorb_aarch64.inc}
end;

procedure KeccakF1600_Gpr_Absorb_Wrap(AState: Pointer; AData: PByte;
  ABlockCount: Int32; ABlockSize: Int32);
begin
  KeccakF1600_Gpr_Absorb(AState, AData, ABlockCount, ABlockSize, @RC);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TSHA3ArmBackend }

class function TSHA3ArmBackend.SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA3() then
    Exit(@KeccakF1600_CryptoExt_Wrap);
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@KeccakF1600_Gpr_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TSHA3ArmBackend.SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  if TCpuFeatures.Arm.HasSHA3() then
    Exit(@KeccakF1600_CryptoExt_Absorb_Wrap);
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON:
      Exit(@KeccakF1600_Gpr_Absorb_Wrap);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
