unit HlpArgon2Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpPBKDF_Argon2NotBuildInAdapter;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Argon2's fill-block. Picks the per-arch backend
  /// at compile time and returns the best routine the running CPU supports, or
  /// <c>AScalar</c> when no SIMD backend is built/available. The KDF unit calls
  /// only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TArgon2Simd = class sealed
  public
    class function Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpArgon2X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpArgon2ArmBackend;
{$IFEND}

{ TArgon2Simd }

class function TArgon2Simd.Select(AScalar: TArgon2FillBlockProc): TArgon2FillBlockProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TArgon2X86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TArgon2ArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
