unit HlpAdler32Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpAdler32;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Adler-32. Picks the per-arch backend at compile
  /// time and returns the best update routine the running CPU supports, or
  /// <c>AScalar</c> when no SIMD backend is built/available. The hash unit calls
  /// only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TAdler32Simd = class sealed
  public
    class function Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpAdler32X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpAdler32ArmBackend;
{$IFEND}

{ TAdler32Simd }

class function TAdler32Simd.Select(AScalar: TAdler32UpdateProc): TAdler32UpdateProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TAdler32X86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TAdler32ArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
