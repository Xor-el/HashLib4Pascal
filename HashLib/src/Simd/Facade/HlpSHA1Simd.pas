unit HlpSHA1Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA1;

type
  /// <summary>
  /// Arch-neutral SIMD facade for SHA-1. Picks the per-arch backend at compile
  /// time and returns the best block-compression routine the running CPU
  /// supports, or <c>AScalar</c> when no SIMD backend is built/available. The
  /// hash unit calls only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TSHA1Simd = class sealed
  public
    /// <summary>Return the fastest available SHA-1 compression routine for the
    /// running CPU, falling back to <c>AScalar</c>. Call once at init.</summary>
    class function Select(AScalar: TSHA1CompressProc): TSHA1CompressProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpSHA1X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpSHA1ArmBackend;
{$IFEND}

{ TSHA1Simd }

class function TSHA1Simd.Select(AScalar: TSHA1CompressProc): TSHA1CompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TSHA1X86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TSHA1ArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
