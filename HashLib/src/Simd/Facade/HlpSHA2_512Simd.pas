unit HlpSHA2_512Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA2_512Base;

type
  /// <summary>
  /// Arch-neutral SIMD facade for SHA-512. Picks the per-arch backend at compile
  /// time and returns the best block-compression routine the running CPU
  /// supports, or <c>AScalar</c> when no SIMD backend is built/available. The
  /// hash unit calls only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TSHA2_512Simd = class sealed
  public
    /// <summary>Return the fastest available SHA-512 compression routine for the
    /// running CPU, falling back to <c>AScalar</c>. Call once at init.</summary>
    class function Select(AScalar: TSHA512CompressProc): TSHA512CompressProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpSHA2_512X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpSHA2_512ArmBackend;
{$IFEND}

{ TSHA2_512Simd }

class function TSHA2_512Simd.Select(AScalar: TSHA512CompressProc): TSHA512CompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TSHA2_512X86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TSHA2_512ArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
