unit HlpBlake2BSimd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2B;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Blake2B. Picks the per-arch backend at compile
  /// time and returns the best compression routine the running CPU supports, or
  /// <c>AScalar</c> when no SIMD backend is built/available. The hash unit calls
  /// only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TBlake2BSimd = class sealed
  public
    class function Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpBlake2BX86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpBlake2BArmBackend;
{$IFEND}

{ TBlake2BSimd }

class function TBlake2BSimd.Select(AScalar: TBlake2BCompressProc): TBlake2BCompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TBlake2BX86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TBlake2BArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
