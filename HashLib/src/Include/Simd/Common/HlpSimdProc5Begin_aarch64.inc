// Shared SIMD procedure prologue for 5-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2, w2 = param3, x3 = param4,
//   x4 = param5 (AAPCS64).
// Matches the x86 SimdProc5 signature order: (AState, AData, ANumBlocks,
//   AConstants, AMask). AAPCS64 passes the first 8 integer/pointer arguments in
//   x0-x7, so param5 arrives in x4 -- no register remapping and no stack load
//   (unlike the x86 MS variant's [rsp+40]) is needed; 32-bit parameters (e.g.
//   ANumBlocks) are read through the wN view of the same register.
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3: UInt32; P4, P5: Pointer);
//     {$I HlpSimdProc5Begin_aarch64.inc}
//     // ... SIMD instructions using x0, x1, w2, x3, x4 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
