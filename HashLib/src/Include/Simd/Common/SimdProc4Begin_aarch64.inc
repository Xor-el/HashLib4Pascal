// Shared SIMD procedure prologue for 4-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2, w2 = param3, x3 = param4 (AAPCS64).
// Matches x86 SimdProc4/5 signature order: (AState, AData, ANumBlocks, AConstants[, …]).
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
