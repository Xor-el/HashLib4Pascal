unit HlpCRCSimd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpCRCCore;

type
  /// <summary>
  /// Arch-neutral SIMD facade for CRC's carry-less-multiply fold. Picks the
  /// per-arch backend at compile time and returns the reflected / forward fold
  /// entry points the running CPU supports (plus whether they use carry-less
  /// multiply), or the scalar routines when no SIMD backend is built/available.
  /// The CRC core calls only this facade and stays free of any
  /// <c>TCpuFeatures</c> / <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TCRCSimd = class sealed
  public
    class function Select(AReflectedScalar, AForwardScalar: TCRCFoldFunc)
      : TCRCFoldSelection; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpCRCX86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpCRCArmBackend;
{$IFEND}

{ TCRCSimd }

class function TCRCSimd.Select(AReflectedScalar, AForwardScalar: TCRCFoldFunc)
  : TCRCFoldSelection;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TCRCX86Backend.Select(AReflectedScalar, AForwardScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TCRCArmBackend.Select(AReflectedScalar, AForwardScalar);
{$ELSE}
  Result.Reflected := AReflectedScalar;
  Result.Fwd := AForwardScalar;
  Result.UsesCarrylessMul := False;
{$IFEND}
end;

end.
