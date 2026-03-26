// Shared SIMD procedure prologue for 6-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4,
//   r10 = param5, r11 = param6 (MS x64 ABI layout).
// On FPC non-Windows (System V ABI), remaps rdi,rsi,rdx,rcx,r8,r9 ->
//   rcx,rdx,r8,r9,r10,r11. Move order avoids register clobbering.
// On MS x64, param5/6 are loaded from [rsp+40]/[rsp+48] (after shadow space).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32; P5: UInt64; P6: UInt32);
//     {$I SimdProc6Begin.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9, r10, r11 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
 asm
  {$IFNDEF MSWINDOWS}
  mov r11, r9
  mov r10, r8
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ELSE}
  mov r10, [rsp + 40]
  mov r11, [rsp + 48]
  {$ENDIF}
{$ELSE}
 asm
  .noframe
  mov r10, [rsp + 40]
  mov r11, [rsp + 48]
{$ENDIF}
