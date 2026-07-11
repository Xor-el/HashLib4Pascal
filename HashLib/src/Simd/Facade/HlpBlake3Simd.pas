unit HlpBlake3Simd;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpBlake3;

type
  /// <summary>
  /// Arch-neutral SIMD facade for Blake3. Picks the per-arch backend at compile
  /// time and returns the best compression / hash-many routines (and the parallel
  /// degree) the running CPU supports, or the scalar reference when no SIMD
  /// backend is built/available. The hash unit calls only this facade and stays
  /// free of any <c>TCpuFeatures</c> / <c>HASHLIB_*_ASM</c> knowledge.
  /// </summary>
  TBlake3Simd = class sealed
  public
    class function SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc; static;
    class function SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc; static;
    class function SelectParallelDegree(ADefault: Int32): Int32; static;
  end;

implementation

{$IF DEFINED(HASHLIB_X86_SIMD)}
uses
  HlpBlake3X86Backend;
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
uses
  HlpBlake3ArmBackend;
{$IFEND}

{ TBlake3Simd }

class function TBlake3Simd.SelectCompress(AScalar: TBlake3CompressProc): TBlake3CompressProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TBlake3X86Backend.SelectCompress(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TBlake3ArmBackend.SelectCompress(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TBlake3Simd.SelectHashMany(AScalar: TBlake3HashManyProc): TBlake3HashManyProc;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TBlake3X86Backend.SelectHashMany(AScalar);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TBlake3ArmBackend.SelectHashMany(AScalar);
{$ELSE}
  Result := AScalar;
{$IFEND}
end;

class function TBlake3Simd.SelectParallelDegree(ADefault: Int32): Int32;
begin
{$IF DEFINED(HASHLIB_X86_SIMD)}
  Result := TBlake3X86Backend.SelectParallelDegree(ADefault);
{$ELSEIF DEFINED(HASHLIB_AARCH64_ASM)}
  Result := TBlake3ArmBackend.SelectParallelDegree(ADefault);
{$ELSE}
  Result := ADefault;
{$IFEND}
end;

end.
