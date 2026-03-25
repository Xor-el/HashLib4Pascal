unit HlpCRCDispatch;

{$I ..\Include\HashLib.inc}

interface

type
  // AData: data pointer, ALength: byte count (>= 64), AState: pointer to
  // 2 x UInt64 (input: [0]=CRC, [1]=0), AConstants: pointer to
  // TCRCFoldConstants.  Returns the final CRC value.
  TCRCFoldFunc = function(AData: PByte; ALength: UInt32;
    AState: Pointer; AConstants: Pointer): UInt64;

var
  CRC_Fold_Lsb: TCRCFoldFunc;
  CRC_Fold_Msb: TCRCFoldFunc;

implementation

uses
  HlpSimd;

{$IFDEF HASHLIB_X86_64}

function CRC_Fold_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\CRC\CRCFoldPclmul.inc}
end;

function CRC_Fold_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\CRC\CRCFoldVpclmul.inc}
end;

function CRC_Fold_Pclmul_Msb(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\CRC\CRCFoldPclmulMsb.inc}
end;

function CRC_Fold_Vpclmul_Msb(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin.inc}
  {$I ..\Include\Simd\CRC\CRCFoldVpclmulMsb.inc}
end;

{$ENDIF HASHLIB_X86_64}

procedure InitDispatch();
begin
  CRC_Fold_Lsb := nil;
  CRC_Fold_Msb := nil;
{$IFDEF HASHLIB_X86_64}
  if TSimd.HasVPCLMULQDQ() then
  begin
    CRC_Fold_Lsb := @CRC_Fold_Vpclmul;
    CRC_Fold_Msb := @CRC_Fold_Vpclmul_Msb;
  end
  else if TSimd.HasPCLMULQDQ() then
  begin
    CRC_Fold_Lsb := @CRC_Fold_Pclmul;
    CRC_Fold_Msb := @CRC_Fold_Pclmul_Msb;
  end;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
