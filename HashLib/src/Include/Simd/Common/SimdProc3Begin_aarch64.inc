// Shared SIMD procedure prologue for 3-parameter assembly functions (AArch64).
// After inclusion: x0 = param1, x1 = param2, w2 = param3 (AAPCS64).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);
//     {$I SimdProc3Begin_aarch64.inc}
//     // ... SIMD instructions using x0, x1, w2 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
