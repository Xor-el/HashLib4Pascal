unit HlpScryptArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_ScryptNotBuildInAdapter;

type
  /// <summary>
  /// Arm SIMD backend for scrypt's Salsa20/8 XOR core. The NEON kernel (body in
  /// <c>Include\Simd\Scrypt\</c>) is compiled and verified but intentionally NOT
  /// selected: at p=1 scrypt's Salsa20/8 is a single 64-byte block on a strictly
  /// serial chain, and AArch64's 31 GP registers + single-cycle 'ror' let the
  /// scalar kernel win at every N (this mirrors OpenSSL/libsodium/Tarsnap, which
  /// ship x86 SSE2 scrypt but no NEON). Kept for reference / a future p&gt;1 path.
  /// So <c>Select</c> always returns the scalar routine.
  /// </summary>
  TScryptArmBackend = class sealed
  public
    class function Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

// =============================================================================
// SIMD kernels
//   aarch64: NEON (compiled/verified but not registered - see the class comment)
// =============================================================================

procedure Scrypt_SalsaXor_Neon(AState, AInput: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_aarch64.inc}
  {$I ..\..\Include\Simd\Scrypt\ScryptSalsa8Neon_aarch64.inc}
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TScryptArmBackend }

class function TScryptArmBackend.Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc;
begin
  // NEON not registered for scrypt on AArch64 (scalar is faster at p=1).
  Result := AScalar;
end;

end.
