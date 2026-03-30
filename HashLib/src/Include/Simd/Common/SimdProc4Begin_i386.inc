// Shared SIMD procedure prologue for 4-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4
//   (first three in EAX, EDX, ECX at entry; param4 from stack after callee saves).
// FPC: Windows and Unix i386 use the same stack tail layout; see asm for ESP offsets.
// Delphi: MS Windows uses [ebp+8] for param4; see asm for other Delphi targets.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32);
//     {$I SimdProc4Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi, eax ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  mov ebx, eax
  mov eax, dword ptr [esp + 8]
  push esi
  mov esi, edx
  push edi
  mov edi, ecx
{$ELSE}
asm
  {$IFDEF MSWINDOWS}
  push ebx
  mov ebx, eax
  mov eax, dword ptr [ebp + 8]
  push esi
  mov esi, edx
  push edi
  mov edi, ecx
  {$ELSE}
  push ebx
  push esi
  push edi
  mov ebx, dword ptr [ebp + 8]
  mov esi, dword ptr [ebp + 12]
  mov edi, dword ptr [ebp + 16]
  mov eax, dword ptr [ebp + 20]
  {$ENDIF}
{$ENDIF}
