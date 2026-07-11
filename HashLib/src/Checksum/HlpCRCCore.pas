unit HlpCRCCore;

{
  CRC fold dispatch (scalar + SIMD + PCLMUL) and fast reflected-CRC32 update.

  TCRC (HlpCRC.pas): generic widths, UInt64 table rows, FHash state — uses
  CRC_Fold_Reflected/Forward + UpdateCRCViaByteTable; not the PKZIP wire inverted form.

  CRC32Fast (HlpCRC32Fast.pas): PKZIP/Castagnoli only; FCurrentCRC with not/xor
  convention; uses CRCDispatch_UpdateReflectedCrc32 + TCRCFoldRuntimeCtx.

  TCRCFoldRuntimeCtx: FoldConstants + TableRow only. One record serves both the
  UInt64 generic table and the UInt32 CRC32 table (TableRow stores untyped
  pointers, cast at point of use). MSB fold reads CRC width from
  FoldConstants.CrcBits (see TGF2.GenerateFoldConstants) and derives the state
  mask the same way as TCRC.FCRCMask.
}

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpCRCFoldConstants;

const
  MinSimdBytes = Int32(16);

type
  // Unified fold runtime context. The PCLMUL/VPCLMUL (and future PMULL) paths
  // read FoldConstants only (offset 0). The scalar/SSE2 slicing tiers read
  // TableRow at offset 96 (= SizeOf(TCRCFoldConstants)); rows point at UInt64
  // (generic CRC) or UInt32 (CRC32 fast path) tables and are cast at point of
  // use. TableRow is declared as Pointer so one record serves both table cell
  // widths with identical byte layout on i386 (4-byte rows) and x86_64
  // (8-byte rows) — matching the fixed +96+I*SizeOf(Pointer) asm offsets.
  TCRCFoldRuntimeCtx = packed record
    FoldConstants: TCRCFoldConstants;
    TableRow: array [0 .. 15] of Pointer;
  end;

  PCRCFoldRuntimeCtx = ^TCRCFoldRuntimeCtx;

  // AData: data pointer, ALength: byte count (>= MinSimdBytes, multiple of 16).
  // AState: pointer to 2 x UInt64 ([0]=CRC / state, [1]=0 for PCLMUL).
  // AConstants: pointer to TCRCFoldRuntimeCtx (FoldConstants at offset 0).
  TCRCFoldFunc = function(AData: PByte; ALength: UInt32;
    AState: Pointer; AConstants: Pointer): UInt64;

  // Tier-selection result: the three fold entry points plus whether they use
  // carry-less multiply (PCLMUL/VPCLMUL/PMULL) rather than table slicing.
  TCRCFoldSelection = record
    Reflected: TCRCFoldFunc;
    Fwd: TCRCFoldFunc;
    Reflected32: TCRCFoldFunc;
    UsesCarrylessMul: Boolean;
  end;

procedure CRCDispatch_InitRuntimeCtx(const Table: THashLibMatrixUInt64Array;
  APoly: UInt64; AWidth: Int32; AReflected: Boolean;
  out Ctx: TCRCFoldRuntimeCtx); overload;

procedure CRCDispatch_InitRuntimeCtx(const Table: THashLibMatrixUInt32Array;
  AMsbPoly: UInt32; out Ctx: TCRCFoldRuntimeCtx); overload;

// 16 x 256 slicing-by-16 table for reflected CRC32 (AReflectedPoly = e.g. $EDB88320).
function CRCDispatch_BuildSlicingTable32Reflect(AReflectedPoly: UInt32)
  : THashLibMatrixUInt32Array;

// PKZIP-style reflected CRC32: updates AWireCrc (e.g. FCurrentCRC) with ALength
// bytes at AData using fold dispatch + row-0 tail (same as former LocalCRCCompute).
procedure CRCDispatch_UpdateReflectedCrc32(var AWireCrc: UInt32;
  AData: PByte; ALength: UInt32; ACtx: PCRCFoldRuntimeCtx);

procedure CRC_UpdateViaBitSerial(AData: PByte; ADataLength, AIndex: Int32;
  var AHash: UInt64; APolynomial: UInt64; AWidth: Int32;
  AInputReflected: Boolean; AHighBitMask: UInt64);

var
  CRC_Fold_Reflected: TCRCFoldFunc;
  CRC_Fold_Forward: TCRCFoldFunc;
  CRC_Fold_Reflected32: TCRCFoldFunc;
  CRC_Fold_UsesCarrylessMul: Boolean;

implementation

uses
  HlpCRCSimd;

function CrcTableU64(const Row: Pointer; B: Byte): UInt64; inline;
begin
  Result := PUInt64(NativeUInt(Row) + UInt64(B) * SizeOf(UInt64))^;
end;

function CrcTableU32(const Row: Pointer; B: Byte): UInt32; inline;
begin
  Result := PUInt32(NativeUInt(Row) + UInt64(B) * SizeOf(UInt32))^;
end;

function CRCMaskFromWidth(AWidth: Int32): UInt64; inline;
begin
  Result := ((UInt64(1) shl (AWidth - 1)) - 1) shl 1 or 1;
end;

procedure CRC_FoldReflected_OneSlice(Ctx: PCRCFoldRuntimeCtx;
  var ATemp: UInt64; LPtr: PByte);
begin
  ATemp := CrcTableU64(Ctx.TableRow[15], LPtr[0] xor Byte(ATemp))
    xor CrcTableU64(Ctx.TableRow[14], LPtr[1] xor Byte(ATemp shr 8))
    xor CrcTableU64(Ctx.TableRow[13], LPtr[2] xor Byte(ATemp shr 16))
    xor CrcTableU64(Ctx.TableRow[12], LPtr[3] xor Byte(ATemp shr 24))
    xor CrcTableU64(Ctx.TableRow[11], LPtr[4] xor Byte(ATemp shr 32))
    xor CrcTableU64(Ctx.TableRow[10], LPtr[5] xor Byte(ATemp shr 40))
    xor CrcTableU64(Ctx.TableRow[9], LPtr[6] xor Byte(ATemp shr 48))
    xor CrcTableU64(Ctx.TableRow[8], LPtr[7] xor Byte(ATemp shr 56))
    xor CrcTableU64(Ctx.TableRow[7], LPtr[8])
    xor CrcTableU64(Ctx.TableRow[6], LPtr[9])
    xor CrcTableU64(Ctx.TableRow[5], LPtr[10])
    xor CrcTableU64(Ctx.TableRow[4], LPtr[11])
    xor CrcTableU64(Ctx.TableRow[3], LPtr[12])
    xor CrcTableU64(Ctx.TableRow[2], LPtr[13])
    xor CrcTableU64(Ctx.TableRow[1], LPtr[14])
    xor CrcTableU64(Ctx.TableRow[0], LPtr[15]);
end;

function CRC_Fold_Reflected_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx;
  LTemp: UInt64;
  LPtr: PByte;
  LLen: UInt32;
begin
  Ctx := PCRCFoldRuntimeCtx(AConstants);
  LPtr := AData;
  LLen := ALength;
  LTemp := PUInt64(AState)^;

  while LLen >= 16 do
  begin
    CRC_FoldReflected_OneSlice(Ctx, LTemp, LPtr);
    System.Inc(LPtr, 16);
    System.Dec(LLen, 16);
  end;

  PUInt64(AState)^ := LTemp;
  Result := LTemp;
end;

function CRC_Fold_Forward_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx;
  LTemp, LNewTemp, LTempCopy: UInt64;
  LPtr: PByte;
  LLen: UInt32;
  LWidth: Int32;
  LCrcMask: UInt64;
  LCrcBytes, LBIdx: Int32;
  LByte: Byte;
begin
  Ctx := PCRCFoldRuntimeCtx(AConstants);
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

procedure CRC32_FoldReflected32_OneSlice(Ctx: PCRCFoldRuntimeCtx;
  var LCRC: UInt32; LPtr: PByte);
var
  LTempCrc: UInt32;
begin
  LTempCrc := LCRC;
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
    xor CrcTableU32(Ctx.TableRow[12], LPtr[3] xor Byte(LTempCrc shr 24))
    xor CrcTableU32(Ctx.TableRow[13], LPtr[2] xor Byte(LTempCrc shr 16))
    xor CrcTableU32(Ctx.TableRow[14], LPtr[1] xor Byte(LTempCrc shr 8))
    xor CrcTableU32(Ctx.TableRow[15], LPtr[0] xor Byte(LTempCrc));
end;

function CRC_Fold_Reflected32_Scalar(AData: PByte; ALength: UInt32;
  AState: Pointer; AConstants: Pointer): UInt64;
var
  Ctx: PCRCFoldRuntimeCtx;
  LCRC: UInt32;
  LPtr: PByte;
  LLen: UInt32;
begin
  Ctx := PCRCFoldRuntimeCtx(AConstants);
  LPtr := AData;
  LLen := ALength;
  LCRC := UInt32(PUInt64(AState)^);

  while LLen >= 16 do
  begin
    CRC32_FoldReflected32_OneSlice(Ctx, LCRC, LPtr);
    System.Inc(LPtr, 16);
    System.Dec(LLen, 16);
  end;

  PUInt64(AState)^ := LCRC;
  Result := LCRC;
end;

procedure CRCDispatch_UpdateReflectedCrc32(var AWireCrc: UInt32;
  AData: PByte; ALength: UInt32; ACtx: PCRCFoldRuntimeCtx);
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
    LState[0] := UInt64(LInternal);
    LState[1] := 0;
    LInternal := UInt32(CRC_Fold_Reflected32(LPtr, LProcessed, @LState[0], ACtx));
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

procedure CRCDispatch_InitRuntimeCtx(const Table: THashLibMatrixUInt64Array;
  APoly: UInt64; AWidth: Int32; AReflected: Boolean;
  out Ctx: TCRCFoldRuntimeCtx);
var
  I: Int32;
begin
  TGF2.GenerateFoldConstants(APoly, AWidth, AReflected, Ctx.FoldConstants);
  for I := 0 to 15 do
    Ctx.TableRow[I] := @Table[I][0];
end;

procedure CRCDispatch_InitRuntimeCtx(const Table: THashLibMatrixUInt32Array;
  AMsbPoly: UInt32; out Ctx: TCRCFoldRuntimeCtx);
var
  I: Int32;
begin
  TGF2.GenerateFoldConstants(UInt64(AMsbPoly), 32, True, Ctx.FoldConstants);
  for I := 0 to 15 do
    Ctx.TableRow[I] := @Table[I][0];
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
// Fold routine selection (once, at init)
// =============================================================================

procedure InitCRCFold();
var
  LSel: TCRCFoldSelection;
begin
  LSel := TCRCSimd.Select(@CRC_Fold_Reflected_Scalar,
    @CRC_Fold_Forward_Scalar, @CRC_Fold_Reflected32_Scalar);
  CRC_Fold_Reflected := LSel.Reflected;
  CRC_Fold_Forward := LSel.Fwd;
  CRC_Fold_Reflected32 := LSel.Reflected32;
  CRC_Fold_UsesCarrylessMul := LSel.UsesCarrylessMul;
end;

initialization
  InitCRCFold();

end.
