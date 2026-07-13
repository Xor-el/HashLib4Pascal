unit HlpBlake2SSimd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake2S;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Blake2S. Picks the per-arch backend at compile
  /// time and returns the best compression routine the running CPU supports, or
  /// <c>AScalar</c> when no SIMD backend is built/available. The hash unit calls
  /// only this facade and stays free of any <c>TCpuFeatures</c> /
  /// <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TBlake2SSimd = class sealed
  public
    class function Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpBlake2SX86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpBlake2SArmBackend;
{$IFEND}

{ TBlake2SSimd }

class function TBlake2SSimd.Select(AScalar: TBlake2SCompressProc): TBlake2SCompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TBlake2SX86Backend.Select(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TBlake2SArmBackend.Select(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
