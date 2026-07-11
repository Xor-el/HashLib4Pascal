unit HlpXXHash3Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpXXHash3;

type
  /// <summary>
  /// Arch-neutral SIMD facade for XXH3. Picks the per-arch backend at compile
  /// time and returns the best accumulate / scramble / init-secret routines the
  /// running CPU supports, or the scalar references when no SIMD backend is
  /// built/available. The hash unit calls only this facade and stays free of any
  /// <c>TCpuFeatures</c> / <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TXXHash3Simd = class sealed
  public
    class function SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc; static;
    class function SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc; static;
    class function SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc; static;
    class function SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpXXHash3X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpXXHash3ArmBackend;
{$IFEND}

{ TXXHash3Simd }

class function TXXHash3Simd.SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TXXHash3X86Backend.SelectAccumulate512(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TXXHash3ArmBackend.SelectAccumulate512(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TXXHash3Simd.SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TXXHash3X86Backend.SelectAccumulate(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TXXHash3ArmBackend.SelectAccumulate(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TXXHash3Simd.SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TXXHash3X86Backend.SelectScrambleAcc(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TXXHash3ArmBackend.SelectScrambleAcc(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TXXHash3Simd.SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TXXHash3X86Backend.SelectInitSecret(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TXXHash3ArmBackend.SelectInitSecret(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

end.
