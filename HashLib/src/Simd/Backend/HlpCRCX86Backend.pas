unit HlpCRCX86Backend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpCRCCore;

type
  /// <summary>
  /// x86 SIMD backend for CRC's fold: owns the SSE2 / PCLMULQDQ / VPCLMULQDQ
  /// kernels (bodies in <c>Include\Simd\CRC\</c>) and the runtime tier selection
  /// via <c>TCpuFeatures.X86</c>. Compiles on every target - built without x86
  /// SIMD, <c>Select</c> just returns the scalar routines.
  /// </summary>
  TCRCX86Backend = class sealed
  public
    class function Select(AReflectedScalar, AForwardScalar: TCRCFoldFunc)
      : TCRCFoldSelection; static;
  end;

implementation

{$IFDEF HASHLIB_X86_SIMD}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   i386:    VPCLMULQDQ, PCLMULQDQ, SSE2
//   x86_64:  VPCLMULQDQ, PCLMULQDQ, SSE2
// =============================================================================

{$IFDEF HASHLIB_I386_ASM}

function CRC_Fold_Reflected_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedSse2_i386.inc}
end;

function CRC_Fold_Forward_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardSse2_i386.inc}
end;

function CRC_Fold_Reflected_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedPclmul_i386.inc}
end;

function CRC_Fold_Forward_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardPclmul_i386.inc}
end;

function CRC_Fold_Reflected_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedVpclmul_i386.inc}
end;

function CRC_Fold_Forward_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_i386.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardVpclmul_i386.inc}
end;

{$ENDIF HASHLIB_I386_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

function CRC_Fold_Reflected_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedSse2_x86_64.inc}
end;

function CRC_Fold_Forward_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardSse2_x86_64.inc}
end;

function CRC_Fold_Reflected_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedPclmul_x86_64.inc}
end;

function CRC_Fold_Reflected_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldReflectedVpclmul_x86_64.inc}
end;

function CRC_Fold_Forward_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardPclmul_x86_64.inc}
end;

function CRC_Fold_Forward_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\..\Include\Simd\Common\HlpSimdProc4Begin_x86_64.inc}
  {$I ..\..\Include\Simd\CRC\CRCFoldForwardVpclmul_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

{$ENDIF HASHLIB_X86_SIMD}

{ TCRCX86Backend }

class function TCRCX86Backend.Select(AReflectedScalar,
  AForwardScalar: TCRCFoldFunc): TCRCFoldSelection;
begin
  Result.Reflected := AReflectedScalar;
  Result.Fwd := AForwardScalar;
  Result.UsesCarrylessMul := False;

{$IFDEF HASHLIB_X86_SIMD}
  if TCpuFeatures.X86.HasVPCLMULQDQ() then
  begin
    Result.Reflected := @CRC_Fold_Reflected_Vpclmul;
    Result.Fwd := @CRC_Fold_Forward_Vpclmul;
    Result.UsesCarrylessMul := True;
    Exit;
  end;

  if TCpuFeatures.X86.HasPCLMULQDQ() then
  begin
    Result.Reflected := @CRC_Fold_Reflected_Pclmul;
    Result.Fwd := @CRC_Fold_Forward_Pclmul;
    Result.UsesCarrylessMul := True;
    Exit;
  end;

  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
    begin
      Result.Reflected := @CRC_Fold_Reflected_Sse2;
      Result.Fwd := @CRC_Fold_Forward_Sse2;
    end;
  end;
{$ENDIF HASHLIB_X86_SIMD}
end;

end.
