unit HlpGF2;

{$I ..\Include\HashLib.inc}

interface

type
  TUInt128 = record
    Lo, Hi: UInt64;
  end;

  // PCLMULQDQ / VPCLMULQDQ CRC folding and Barrett reduction constants.
  // Layout must match the assembly expectations in CRCFoldPclmul.inc
  // and CRCFoldVpclmul.inc.
  TCRCFoldConstants = packed record
    Fold_4x128: array [0 .. 1] of UInt64;   // offset  0: fold-by-4 constants (stride 512)
    Fold_1x128: array [0 .. 1] of UInt64;   // offset 16: fold-by-1 constants (stride 128)
    Barrett: array [0 .. 1] of UInt64;       // offset 32: Barrett reduction constants
    Fold_8x128: array [0 .. 1] of UInt64;   // offset 48: fold-by-8 constants (stride 1024)
  end;

  TGF2 = class sealed
  strict private
    class function BitLength64(A: UInt64): Int32; static;
    class function BitLength128(const A: TUInt128): Int32; static;

    // 64 x 64 -> 128 carry-less multiply (MSB-first polynomial arithmetic).
    class function CLMul(A, B: UInt64): TUInt128; static;

    // 128-bit polynomial mod G, where G = x^ABits + APoly.
    // Returns remainder (degree < ABits, fits in UInt64).
    class function Reduce(const A: TUInt128; APoly: UInt64;
      ABits: Int32): UInt64; static;

    // floor(A / G) where G = x^ABits + APoly. Returns quotient.
    class function DivPoly(const A: TUInt128; APoly: UInt64;
      ABits: Int32): UInt64; static;

    // XOR G << AShift into LVal (128-bit), G = x^ABits + APoly.
    class procedure XorShiftedG(var AVal: TUInt128; APoly: UInt64;
      ABits, AShift: Int32); static;

  public
    // Compute x^N mod G using repeated squaring.
    // APoly: generator polynomial WITHOUT the leading x^ABits term.
    // ABits: CRC width (degree of G).
    class function PowerMod(N: Int32; APoly: UInt64;
      ABits: Int32): UInt64; static;

    // Reverse the lowest ANumBits bits of AValue.
    class function BitReverse(AValue: UInt64; ANumBits: Int32): UInt64; static;

    // Generate PCLMULQDQ fold and Barrett reduction constants for a CRC.
    // APoly: generator polynomial (MSB-first, without leading bit).
    // ABits: CRC width (8..64).
    // AReflected: True for LSB-first (reflected input) CRCs.
    class procedure GenerateFoldConstants(APoly: UInt64; ABits: Int32;
      AReflected: Boolean; out AConstants: TCRCFoldConstants); static;
  end;

implementation

{ TGF2 }

class function TGF2.BitLength64(A: UInt64): Int32;
begin
  Result := 0;
  while A <> 0 do
  begin
    System.Inc(Result);
    A := A shr 1;
  end;
end;

class function TGF2.BitLength128(const A: TUInt128): Int32;
begin
  if A.Hi <> 0 then
    Result := 64 + BitLength64(A.Hi)
  else
    Result := BitLength64(A.Lo);
end;

class function TGF2.CLMul(A, B: UInt64): TUInt128;
var
  I: Int32;
begin
  Result.Lo := 0;
  Result.Hi := 0;
  for I := 0 to 63 do
  begin
    if (B and (UInt64(1) shl I)) <> 0 then
    begin
      if I = 0 then
      begin
        Result.Lo := Result.Lo xor A;
      end
      else
      begin
        Result.Lo := Result.Lo xor (A shl I);
        Result.Hi := Result.Hi xor (A shr (64 - I));
      end;
    end;
  end;
end;

class procedure TGF2.XorShiftedG(var AVal: TUInt128; APoly: UInt64;
  ABits, AShift: Int32);
var
  LGLo, LGHi: UInt64;
  LLeadPos: Int32;
begin
  LGLo := 0;
  LGHi := 0;
  LLeadPos := ABits + AShift;

  if AShift < 64 then
  begin
    LGLo := APoly shl AShift;
    if AShift > 0 then
      LGHi := APoly shr (64 - AShift);
  end
  else
  begin
    LGHi := APoly shl (AShift - 64);
  end;

  if LLeadPos < 64 then
    LGLo := LGLo xor (UInt64(1) shl LLeadPos)
  else
    LGHi := LGHi xor (UInt64(1) shl (LLeadPos - 64));

  AVal.Lo := AVal.Lo xor LGLo;
  AVal.Hi := AVal.Hi xor LGHi;
end;

class function TGF2.Reduce(const A: TUInt128; APoly: UInt64;
  ABits: Int32): UInt64;
var
  LVal: TUInt128;
  LDeg, LShift: Int32;
begin
  LVal := A;
  while True do
  begin
    LDeg := BitLength128(LVal) - 1;
    if LDeg < ABits then
      Break;
    LShift := LDeg - ABits;
    XorShiftedG(LVal, APoly, ABits, LShift);
  end;
  Result := LVal.Lo;
end;

class function TGF2.DivPoly(const A: TUInt128; APoly: UInt64;
  ABits: Int32): UInt64;
var
  LVal: TUInt128;
  LDeg, LShift: Int32;
  LQuotient: UInt64;
begin
  LVal := A;
  LQuotient := 0;
  while True do
  begin
    LDeg := BitLength128(LVal) - 1;
    if LDeg < ABits then
      Break;
    LShift := LDeg - ABits;
    LQuotient := LQuotient xor (UInt64(1) shl LShift);
    XorShiftedG(LVal, APoly, ABits, LShift);
  end;
  Result := LQuotient;
end;

class function TGF2.PowerMod(N: Int32; APoly: UInt64;
  ABits: Int32): UInt64;
var
  LBase, LResult: UInt64;
  LProduct: TUInt128;
begin
  if N = 0 then
    Exit(1);
  LResult := 1;
  LBase := 2;
  while N > 0 do
  begin
    if (N and 1) <> 0 then
    begin
      LProduct := CLMul(LResult, LBase);
      LResult := Reduce(LProduct, APoly, ABits);
    end;
    N := N shr 1;
    if N > 0 then
    begin
      LProduct := CLMul(LBase, LBase);
      LBase := Reduce(LProduct, APoly, ABits);
    end;
  end;
  Result := LResult;
end;

class function TGF2.BitReverse(AValue: UInt64; ANumBits: Int32): UInt64;
var
  I: Int32;
begin
  Result := 0;
  for I := 0 to ANumBits - 1 do
  begin
    if (AValue and (UInt64(1) shl I)) <> 0 then
      Result := Result or (UInt64(1) shl (ANumBits - 1 - I));
  end;
end;

class procedure TGF2.GenerateFoldConstants(APoly: UInt64; ABits: Int32;
  AReflected: Boolean; out AConstants: TCRCFoldConstants);
var
  LK, LPowOfX: Int32;
  LConst0, LConst1, LBarrett0, LBarrett1, LGMinusXn: UInt64;
  LDiv128: TUInt128;
begin
  // Following the Linux kernel gen-crc-consts.py algorithm.
  // G(x) = x^ABits + APoly  (MSB-first representation).
  // For LSB-first (reflected): each constant is computed in MSB domain,
  // then bit-reflected to 64 bits before storage.

  if AReflected then
    LK := ABits - 65
  else
    LK := 0;

  // --- Fold-by-4 constants (stride = 512 bits) ---
  LConst0 := PowerMod(512 + 64 + LK, APoly, ABits);
  LConst1 := PowerMod(512 + LK, APoly, ABits);
  if AReflected then
  begin
    AConstants.Fold_4x128[0] := BitReverse(LConst0 shl (64 - ABits), 64);
    AConstants.Fold_4x128[1] := BitReverse(LConst1 shl (64 - ABits), 64);
  end
  else
  begin
    AConstants.Fold_4x128[0] := LConst1;
    AConstants.Fold_4x128[1] := LConst0;
  end;

  // --- Fold-by-1 constants (stride = 128 bits) ---
  LConst0 := PowerMod(128 + 64 + LK, APoly, ABits);
  LConst1 := PowerMod(128 + LK, APoly, ABits);
  if AReflected then
  begin
    AConstants.Fold_1x128[0] := BitReverse(LConst0 shl (64 - ABits), 64);
    AConstants.Fold_1x128[1] := BitReverse(LConst1 shl (64 - ABits), 64);
  end
  else
  begin
    AConstants.Fold_1x128[0] := LConst1;
    AConstants.Fold_1x128[1] := LConst0;
  end;

  // --- Fold-by-8 constants (stride = 1024 bits, for VPCLMULQDQ) ---
  LConst0 := PowerMod(1024 + 64 + LK, APoly, ABits);
  LConst1 := PowerMod(1024 + LK, APoly, ABits);
  if AReflected then
  begin
    AConstants.Fold_8x128[0] := BitReverse(LConst0 shl (64 - ABits), 64);
    AConstants.Fold_8x128[1] := BitReverse(LConst1 shl (64 - ABits), 64);
  end
  else
  begin
    AConstants.Fold_8x128[0] := LConst1;
    AConstants.Fold_8x128[1] := LConst0;
  end;

  // --- Barrett reduction constants ---
  // barrett[0] = floor(x^(63+n) / G)
  LDiv128.Lo := 0;
  LDiv128.Hi := 0;
  if (63 + ABits) < 64 then
    LDiv128.Lo := UInt64(1) shl (63 + ABits)
  else if (63 + ABits) = 64 then
    LDiv128.Hi := 1
  else
    LDiv128.Hi := UInt64(1) shl ((63 + ABits) - 64);
  LBarrett0 := DivPoly(LDiv128, APoly, ABits);

  // barrett[1] = (G - x^n) * x^(64-n-1) for n < 64
  //            = ((G - x^n) - x^0) / x   for n = 64
  LGMinusXn := APoly;
  if ABits < 64 then
  begin
    LPowOfX := 64 - ABits - 1;
    LBarrett1 := LGMinusXn shl LPowOfX;
  end
  else
  begin
    LBarrett1 := LGMinusXn shr 1;
  end;

  if AReflected then
  begin
    AConstants.Barrett[0] := BitReverse(LBarrett0, 64);
    AConstants.Barrett[1] := BitReverse(LBarrett1, 64);
  end
  else
  begin
    AConstants.Barrett[0] := LBarrett1;
    AConstants.Barrett[1] := LBarrett0;
  end;
end;

end.
