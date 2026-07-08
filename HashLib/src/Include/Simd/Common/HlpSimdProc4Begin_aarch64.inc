// Shared SIMD procedure prologue for 4-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2, w2 = param3, x3 = param4 (AAPCS64).
// Matches the x86 SimdProc4/5 signature order: (AState, AData, ANumBlocks,
//   AConstants[, …]); AAPCS64 already delivers the params in x0,x1,w2,x3, so no
//   register remapping (unlike the x86 SysV/MS variants) is needed.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Pointer);
//     {$I HlpSimdProc4Begin_aarch64.inc}
//     // ... SIMD instructions using x0, x1, w2, x3 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
