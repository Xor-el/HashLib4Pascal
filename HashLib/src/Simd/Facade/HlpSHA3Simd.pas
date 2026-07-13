unit HlpSHA3Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpSHA3;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Keccak-F1600 (SHA-3 / SHAKE). Picks the
  /// per-arch backend at compile time and returns the best permute / absorb
  /// routines the running CPU supports, or the scalar reference when no SIMD
  /// backend is built/available. The hash unit calls only this facade and stays
  /// free of any <c>TCpuFeatures</c> / <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TSHA3Simd = class sealed
  public
    class function SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc; static;
    class function SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpSHA3X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpSHA3ArmBackend;
{$IFEND}

{ TSHA3Simd }

class function TSHA3Simd.SelectPermute(AScalar: TKeccakF1600Proc): TKeccakF1600Proc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TSHA3X86Backend.SelectPermute(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TSHA3ArmBackend.SelectPermute(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TSHA3Simd.SelectAbsorb(AScalar: TKeccakF1600AbsorbProc): TKeccakF1600AbsorbProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TSHA3X86Backend.SelectAbsorb(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TSHA3ArmBackend.SelectAbsorb(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
