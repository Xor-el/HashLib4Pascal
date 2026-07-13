unit HlpSHA2_256Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA2_256Base;

type
  /// <summary>
  /// Arch-neutral SIMD facade for SHA-256. Picks the per-arch backend at compile
  /// time and returns the best block-compression routine the running CPU
  /// supports, or <c>AScalar</c> when no SIMD backend is built/available. The
  /// hash unit calls only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TSHA2_256Simd = class sealed
  public
    /// <summary>Return the fastest available SHA-256 compression routine for the
    /// running CPU, falling back to <c>AScalar</c>. Call once at init.</summary>
    class function Select(AScalar: TSHA256CompressProc): TSHA256CompressProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpSHA2_256X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpSHA2_256ArmBackend;
{$IFEND}

{ TSHA2_256Simd }

class function TSHA2_256Simd.Select(AScalar: TSHA256CompressProc): TSHA256CompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TSHA2_256X86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TSHA2_256ArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
