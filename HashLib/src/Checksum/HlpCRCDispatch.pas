unit HlpCRCDispatch;

{
  CRC fold dispatch (scalar + SIMD + PCLMUL) and fast reflected-CRC32 update.

  TCRC (HlpCRC.pas): generic widths, UInt64 table rows, FHash state — uses
  CRC_Fold_Lsb/Msb + UpdateCRCViaByteTable; not the PKZIP wire inverted form.

  CRC32Fast (HlpCRC32Fast.pas): PKZIP/Castagnoli only; FCurrentCRC with not/xor
  convention; uses CRCDispatch_UpdateReflectedCrc32 + TCRCFoldRuntimeCtx32.

  TCRCFoldRuntimeCtx64 matches Ctx32 shape: FoldConstants + TableRow only.
  MSB fold reads CRC width from FoldConstants.CrcBits (see TGF2.GenerateFoldConstants)
  and derives the state mask the same way as TCRC.FCRCMask.
}

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpGF2;

const
  MinSimdBytes = Int32(16);

type
  // Runtime context: PCLMUL reads first field only (offset 0). Same layout as
  // TCRCFoldRuntimeCtx32 apart from TableRow pointer size (PUInt64 vs PUInt32).
  TCRCFoldRuntimeCtx64 = packed record
    FoldConstants: TCRCFoldConstants;
    TableRow: array [0 .. 15] of PUInt64;
  end;

  PCRCFoldRuntimeCtx64 = ^TCRCFoldRuntimeCtx64;

  TCRCFoldRuntimeCtx32 = packed record
    FoldConstants: TCRCFoldConstants;
    TableRow: array [0 .. 15] of PUInt32;
  end;

  PCRCFoldRuntimeCtx32 = ^TCRCFoldRuntimeCtx32;

  // AData: data pointer, ALength: byte count (>= MinSimdBytes, multiple of 16).
  // AState: pointer to 2 x UInt64 ([0]=CRC / state, [1]=0 for PCLMUL).
  // AConstants: pointer to TCRCFoldRuntimeCtx64 or 32 (FoldConstants at offset 0).
  TCRCFoldFunc = function(AData: PByte; ALength: UInt32;
    AState: Pointer; AConstants: Pointer): UInt64;

procedure CRCDispatch_InitRuntimeCtx64(const Table: THashLibMatrixUInt64Array;
  APoly: UInt64; AWidth: Int32; AReflected: Boolean;
  out Ctx: TCRCFoldRuntimeCtx64);

procedure CRCDispatch_InitRuntimeCtx32(const Table: THashLibMatrixUInt32Array;
  AMsbPoly: UInt32; out Ctx: TCRCFoldRuntimeCtx32);

// 16 x 256 slicing-by-16 table for reflected CRC32 (AReflectedPoly = e.g. $EDB88320).
function CRCDispatch_BuildSlicingTable32Reflect(AReflectedPoly: UInt32)
  : THashLibMatrixUInt32Array;

// PKZIP-style reflected CRC32: updates AWireCrc (e.g. FCurrentCRC) with ALength
// bytes at AData using fold dispatch + row-0 tail (same as former LocalCRCCompute).
procedure CRCDispatch_UpdateReflectedCrc32(var AWireCrc: UInt32;
  AData: PByte; ALength: UInt32; ACtx: PCRCFoldRuntimeCtx32);

procedure CRC_UpdateViaBitSerial(AData: PByte; ADataLength, AIndex: Int32;
  var AHash: UInt64; APolynomial: UInt64; AWidth: Int32;
  AInputReflected: Boolean; AHighBitMask: UInt64);

var
  CRC_Fold_Lsb: TCRCFoldFunc;
  CRC_Fold_Msb: TCRCFoldFunc;
  CRC_Fold_Lsb32: TCRCFoldFunc;
  CRC_Fold_UsesPclmul: Boolean;

implementation

uses
  HlpConverters,
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// Scalar fallback implementation
// =============================================================================

function CrcTableU64(const Row: PUInt64; B: Byte): UInt64; inline;
begin
  Result := PUInt64(NativeUInt(Row) + UInt64(B) * SizeOf(UInt64))^;
end;

function CrcTableU32(const Row: PUInt32; B: Byte): UInt32; inline;
begin
  Result := PUInt32(NativeUInt(Row) + UInt64(B) * SizeOf(UInt32))^;
end;

function CRCMaskFromWidth(AWidth: Int32): UInt64; inline;
begin
  Result := ((UInt64(1) shl (AWidth - 1)) - 1) shl 1 or 1;
end;

function CRC_Fold_Lsb_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx64;
  LTemp: UInt64;
  LPtr: PByte;
  LLen: UInt32;
begin
  Ctx := PCRCFoldRuntimeCtx64(AConstants);
  LPtr := AData;
  LLen := ALength;
  LTemp := PUInt64(AState)^;

  while LLen >= 16 do
  begin
    LTemp := CrcTableU64(Ctx.TableRow[15], LPtr[0] xor Byte(LTemp))
      xor CrcTableU64(Ctx.TableRow[14], LPtr[1] xor Byte(LTemp shr 8))
      xor CrcTableU64(Ctx.TableRow[13], LPtr[2] xor Byte(LTemp shr 16))
      xor CrcTableU64(Ctx.TableRow[12], LPtr[3] xor Byte(LTemp shr 24))
      xor CrcTableU64(Ctx.TableRow[11], LPtr[4] xor Byte(LTemp shr 32))
      xor CrcTableU64(Ctx.TableRow[10], LPtr[5] xor Byte(LTemp shr 40))
      xor CrcTableU64(Ctx.TableRow[9], LPtr[6] xor Byte(LTemp shr 48))
      xor CrcTableU64(Ctx.TableRow[8], LPtr[7] xor Byte(LTemp shr 56))
      xor CrcTableU64(Ctx.TableRow[7], LPtr[8])
      xor CrcTableU64(Ctx.TableRow[6], LPtr[9])
      xor CrcTableU64(Ctx.TableRow[5], LPtr[10])
      xor CrcTableU64(Ctx.TableRow[4], LPtr[11])
      xor CrcTableU64(Ctx.TableRow[3], LPtr[12])
      xor CrcTableU64(Ctx.TableRow[2], LPtr[13])
      xor CrcTableU64(Ctx.TableRow[1], LPtr[14])
      xor CrcTableU64(Ctx.TableRow[0], LPtr[15]);

    System.Inc(LPtr, 16);
    System.Dec(LLen, 16);
  end;

  PUInt64(AState)^ := LTemp;
  Result := LTemp;
end;

function CRC_Fold_Msb_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx64;
  LTemp, LNewTemp, LTempCopy: UInt64;
  LPtr: PByte;
  LLen: UInt32;
  LWidth: Int32;
  LCrcMask: UInt64;
  LCrcBytes, LBIdx: Int32;
  LByte: Byte;
begin
  Ctx := PCRCFoldRuntimeCtx64(AConstants);
  LPtr := AData;
  LLen := ALength;
  LTemp := PUInt64(AState)^;
  LWidth := Int32(Ctx.FoldConstants.CrcBits);
  LCrcMask := CRCMaskFromWidth(LWidth);
  LCrcBytes := (LWidth + 7) shr 3;

  while LLen >= 16 do
  begin
    LNewTemp := UInt64(0);
    LTempCopy := LTemp;

    LBIdx := 0;
    while LBIdx < LCrcBytes do
    begin
      LByte := LPtr[LBIdx] xor Byte(LTempCopy shr (LWidth - 8));
      LTempCopy := (LTempCopy shl 8) and LCrcMask;
      LNewTemp := LNewTemp xor CrcTableU64(Ctx.TableRow[15 - LBIdx], LByte);
      System.Inc(LBIdx);
    end;
    while LBIdx < 16 do
    begin
      LNewTemp := LNewTemp xor CrcTableU64(Ctx.TableRow[15 - LBIdx], LPtr[LBIdx]);
      System.Inc(LBIdx);
    end;

    LTemp := LNewTemp;
    System.Inc(LPtr, 16);
    System.Dec(LLen, 16);
  end;

  PUInt64(AState)^ := LTemp;
  Result := LTemp;
end;

procedure CRC32_FoldLsb32_OneSlice(Ctx: PCRCFoldRuntimeCtx32;
  var LCRC: UInt32; LPtr: PByte);
begin
  LCRC := CrcTableU32(Ctx.TableRow[0], LPtr[15])
    xor CrcTableU32(Ctx.TableRow[1], LPtr[14])
    xor CrcTableU32(Ctx.TableRow[2], LPtr[13])
    xor CrcTableU32(Ctx.TableRow[3], LPtr[12])
    xor CrcTableU32(Ctx.TableRow[4], LPtr[11])
    xor CrcTableU32(Ctx.TableRow[5], LPtr[10])
    xor CrcTableU32(Ctx.TableRow[6], LPtr[9])
    xor CrcTableU32(Ctx.TableRow[7], LPtr[8])
    xor CrcTableU32(Ctx.TableRow[8], LPtr[7])
    xor CrcTableU32(Ctx.TableRow[9], LPtr[6])
    xor CrcTableU32(Ctx.TableRow[10], LPtr[5])
    xor CrcTableU32(Ctx.TableRow[11], LPtr[4])
    xor CrcTableU32(Ctx.TableRow[12], LPtr[3] xor Byte(LCRC shr 24))
    xor CrcTableU32(Ctx.TableRow[13], LPtr[2] xor Byte(LCRC shr 16))
    xor CrcTableU32(Ctx.TableRow[14], LPtr[1] xor Byte(LCRC shr 8))
    xor CrcTableU32(Ctx.TableRow[15], LPtr[0] xor Byte(LCRC));
end;

function CRC_Fold_Lsb32_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx32;
  LCRC: UInt32;
  LPtr: PByte;
  LLen: UInt32;
begin
  Ctx := PCRCFoldRuntimeCtx32(AConstants);
  LPtr := AData;
  LLen := ALength;
  LCRC := TConverters.ReadBytesAsUInt32LE(PByte(AState), 0);

  while LLen >= 16 do
  begin
    CRC32_FoldLsb32_OneSlice(Ctx, LCRC, LPtr);
    System.Inc(LPtr, 16);
    System.Dec(LLen, 16);
  end;

  PByte(AState)[0] := Byte(LCRC);
  PByte(AState)[1] := Byte(LCRC shr 8);
  PByte(AState)[2] := Byte(LCRC shr 16);
  PByte(AState)[3] := Byte(LCRC shr 24);
  Result := LCRC;
end;

procedure CRCDispatch_UpdateReflectedCrc32(var AWireCrc: UInt32;
  AData: PByte; ALength: UInt32; ACtx: PCRCFoldRuntimeCtx32);
var
  LInternal: UInt32;
  LPtr: PByte;
  LLen, LProcessed: UInt32;
  LState: array [0 .. 1] of UInt64;
begin
  LInternal := not AWireCrc;
  LPtr := AData;
  LLen := ALength;
  if LLen >= UInt32(MinSimdBytes) then
  begin
    LProcessed := LLen and (not UInt32(15));
    PByte(@LState[0])[0] := Byte(LInternal);
    PByte(@LState[0])[1] := Byte(LInternal shr 8);
    PByte(@LState[0])[2] := Byte(LInternal shr 16);
    PByte(@LState[0])[3] := Byte(LInternal shr 24);
    LState[1] := 0;
    CRC_Fold_Lsb32(LPtr, LProcessed, @LState[0], ACtx);
    LInternal := TConverters.ReadBytesAsUInt32LE(PByte(@LState[0]), 0);
    System.Inc(LPtr, LProcessed);
    System.Dec(LLen, LProcessed);
  end;
  while LLen > 0 do
  begin
    LInternal := (LInternal shr 8) xor CrcTableU32(ACtx.TableRow[0],
      Byte(LInternal and $FF) xor LPtr^);
    System.Inc(LPtr);
    System.Dec(LLen);
  end;
  AWireCrc := not LInternal;
end;

procedure CRCDispatch_InitRuntimeCtx64(const Table: THashLibMatrixUInt64Array;
  APoly: UInt64; AWidth: Int32; AReflected: Boolean;
  out Ctx: TCRCFoldRuntimeCtx64);
var
  I: Int32;
begin
  TGF2.GenerateFoldConstants(APoly, AWidth, AReflected, Ctx.FoldConstants);
  for I := 0 to 15 do
    Ctx.TableRow[I] := PUInt64(@Table[I][0]);
end;

procedure CRCDispatch_InitRuntimeCtx32(const Table: THashLibMatrixUInt32Array;
  AMsbPoly: UInt32; out Ctx: TCRCFoldRuntimeCtx32);
var
  I: Int32;
begin
  TGF2.GenerateFoldConstants(UInt64(AMsbPoly), 32, True, Ctx.FoldConstants);
  for I := 0 to 15 do
    Ctx.TableRow[I] := PUInt32(@Table[I][0]);
end;

function CRCDispatch_BuildSlicingTable32Reflect(AReflectedPoly: UInt32)
  : THashLibMatrixUInt32Array;
var
  LIdx, LJIdx, LKIdx: Int32;
  LRes: UInt32;
begin
  System.SetLength(Result, 16);
  for LIdx := System.Low(Result) to System.High(Result) do
    System.SetLength(Result[LIdx], 256);
  for LIdx := 0 to System.Pred(256) do
  begin
    LRes := LIdx;
    for LJIdx := 0 to System.Pred(16) do
    begin
      LKIdx := 0;
      while LKIdx < System.Pred(9) do
      begin
        LRes := (LRes shr 1) xor (-Int32(LRes and 1) and AReflectedPoly);
        Result[LJIdx][LIdx] := LRes;
        System.Inc(LKIdx);
      end;
    end;
  end;
end;

procedure CRC_UpdateViaBitSerial(AData: PByte; ADataLength, AIndex: Int32;
  var AHash: UInt64; APolynomial: UInt64; AWidth: Int32;
  AInputReflected: Boolean; AHighBitMask: UInt64);
var
  LLength, LIdx: Int32;
  LTemp, LBit, LJdx, LHash: UInt64;
begin
  LLength := ADataLength;
  LIdx := AIndex;
  while LLength > 0 do
  begin
    LTemp := UInt64(AData[LIdx]);
    if AInputReflected then
      LTemp := TGF2.BitReverse(LTemp, 8);

    LJdx := $80;
    LHash := AHash;
    while LJdx > 0 do
    begin
      LBit := LHash and AHighBitMask;
      LHash := LHash shl 1;
      if ((LTemp and LJdx) > 0) then
        LBit := LBit xor AHighBitMask;
      if (LBit > 0) then
        LHash := LHash xor APolynomial;
      LJdx := LJdx shr 1;
    end;
    AHash := LHash;
    System.Inc(LIdx);
    System.Dec(LLength);
  end;
end;

// =============================================================================
// SIMD implementations: SSE2 (IA-32); SSE2, PCLMULQDQ / VPCLMULQDQ (x86-64)
// =============================================================================
// SSE2 = movdqu/movq/pxor/psrldq for wide loads; table XOR stays in GPRs.
// x86-64: SimdProc4Begin_x86_64.inc + CRCFold*Sse2_x86_64.inc. IA-32: SimdProc4Begin_i386.inc
// + CRCFold*Sse2_i386.inc (MSB Width/CrcMask offsets differ from x64).

{$IFDEF HASHLIB_X86_64_ASM}

function CRC_Fold_Lsb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldLsbSse2_x86_64.inc}
end;

function CRC_Fold_Msb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldMsbSse2_x86_64.inc}
end;

function CRC_Fold_Lsb32_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldLsb32Sse2_x86_64.inc}
end;

{$ELSE}

{$IFDEF HASHLIB_I386_ASM}

function CRC_Fold_Lsb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\CRC\CRCFoldLsbSse2_i386.inc}
end;

function CRC_Fold_Msb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\CRC\CRCFoldMsbSse2_i386.inc}
end;

function CRC_Fold_Lsb32_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_i386.inc}
  {$I ..\Include\Simd\CRC\CRCFoldLsb32Sse2_i386.inc}
end;

{$ELSE}

function CRC_Fold_Lsb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
begin
  Result := CRC_Fold_Lsb_Scalar(AData, ALength, AState, AConstants);
end;

function CRC_Fold_Msb_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
begin
  Result := CRC_Fold_Msb_Scalar(AData, ALength, AState, AConstants);
end;

function CRC_Fold_Lsb32_Sse2(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
begin
  Result := CRC_Fold_Lsb32_Scalar(AData, ALength, AState, AConstants);
end;

{$ENDIF HASHLIB_I386_ASM}
{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_X86_64_ASM}

function CRC_Fold_Pclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldPclmul_x86_64.inc}
end;

function CRC_Fold_Vpclmul(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldVpclmul_x86_64.inc}
end;

function CRC_Fold_Pclmul_Msb(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldPclmulMsb_x86_64.inc}
end;

function CRC_Fold_Vpclmul_Msb(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
  {$I ..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
  {$I ..\Include\Simd\CRC\CRCFoldVpclmulMsb_x86_64.inc}
end;

{$ENDIF HASHLIB_X86_64_ASM}

// =============================================================================
// Dispatch initialization
// =============================================================================

procedure InitDispatch();

  procedure BindSse2CrcFold;
  begin
    CRC_Fold_Lsb := @CRC_Fold_Lsb_Sse2;
    CRC_Fold_Msb := @CRC_Fold_Msb_Sse2;
    CRC_Fold_Lsb32 := @CRC_Fold_Lsb32_Sse2;
  end;

begin
  CRC_Fold_Lsb := @CRC_Fold_Lsb_Scalar;
  CRC_Fold_Msb := @CRC_Fold_Msb_Scalar;
  CRC_Fold_Lsb32 := @CRC_Fold_Lsb32_Scalar;
  CRC_Fold_UsesPclmul := False;

{$IFDEF HASHLIB_X86_64_ASM}
  if TCpuFeatures.X86.HasVPCLMULQDQ() then
  begin
    CRC_Fold_Lsb := @CRC_Fold_Vpclmul;
    CRC_Fold_Msb := @CRC_Fold_Vpclmul_Msb;
    CRC_Fold_Lsb32 := @CRC_Fold_Vpclmul;
    CRC_Fold_UsesPclmul := True;
    Exit;
  end;
  if TCpuFeatures.X86.HasPCLMULQDQ() then
  begin
    CRC_Fold_Lsb := @CRC_Fold_Pclmul;
    CRC_Fold_Msb := @CRC_Fold_Pclmul_Msb;
    CRC_Fold_Lsb32 := @CRC_Fold_Pclmul;
    CRC_Fold_UsesPclmul := True;
    Exit;
  end;
{$ENDIF HASHLIB_X86_64_ASM}

{$IFDEF HASHLIB_X86_SIMD}
  case TCpuFeatures.X86.SelectSlot([TX86SimdLevel.SSE2]) of
    TX86SimdLevel.SSE2:
      BindSse2CrcFold;
  end;
{$ENDIF HASHLIB_X86_SIMD}
end;

initialization
  InitDispatch();

end.
