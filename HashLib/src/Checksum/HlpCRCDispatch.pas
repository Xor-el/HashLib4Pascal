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

{$ENDIF HASHLIB_X86_64}

procedure InitDispatch();
begin
  CRC_Fold_Lsb := nil;
{$IFDEF HASHLIB_X86_64}
  if TSimd.HasVPCLMULQDQ() then
    CRC_Fold_Lsb := @CRC_Fold_Vpclmul
  else if TSimd.HasPCLMULQDQ() then
    CRC_Fold_Lsb := @CRC_Fold_Pclmul;
{$ENDIF}
end;

initialization
  InitDispatch();

end.
