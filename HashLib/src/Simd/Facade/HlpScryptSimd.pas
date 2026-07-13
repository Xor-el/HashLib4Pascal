unit HlpScryptSimd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_ScryptNotBuildInAdapter;

type
  /// <summary>
  /// Arch-neutral SIMD facade for scrypt's Salsa20/8 XOR core. Picks the per-arch
  /// backend at compile time and returns the best routine the running CPU
  /// supports, or <c>AScalar</c> when no SIMD backend is built/available. The KDF
  /// unit calls only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TScryptSimd = class sealed
  public
    class function Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpScryptX86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpScryptArmBackend;
{$IFEND}

{ TScryptSimd }

class function TScryptSimd.Select(AScalar: TScryptSalsaXorProc): TScryptSalsaXorProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TScryptX86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TScryptArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
