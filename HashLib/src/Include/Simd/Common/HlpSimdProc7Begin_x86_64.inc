// Shared SIMD procedure prologue for 7-parameter assembly functions.
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4,
//   r10 = param5, r11 = param6, rax = param7 (MS x64 ABI layout).
// When HASHLIB_SYSV_X64_ABI is defined, remaps rdi,rsi,rdx,rcx,r8,r9 ->
//   rcx,rdx,r8,r9,r10,r11 and loads param7 from [rsp+8].
// On MS x64, param5/6/7 are loaded from [rsp+40]/[rsp+48]/[rsp+56]
//   (above shadow space + return addr).
// Usage:
//   procedure MyProc(P1, P2, P3, P4: Pointer; P5: UInt64; P6: UInt32; P7: Pointer);
//     {$I HlpSimdProc7Begin_x86_64.inc}
//     // ... SIMD instructions using rcx, rdx, r8, r9, r10, r11, rax ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF HASHLIB_SYSV_X64_ABI}
  mov rax, [rsp + 8]
  mov r11, r9
  mov r10, r8
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
{$ELSE}
  mov r10, [rsp + 40]
  mov r11, [rsp + 48]
  mov rax, [rsp + 56]
{$ENDIF}
