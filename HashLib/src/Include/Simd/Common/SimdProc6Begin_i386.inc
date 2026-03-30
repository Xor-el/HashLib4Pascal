// Shared SIMD procedure prologue for 6-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4,
//   ecx = param5 low, edx = param5 high (UInt64 split); param6 is not loaded in this prologue.
// FPC: param4 at [esp+28]; param5 at [esp+20]/[esp+24]; param6 at [esp+16] after push EBX/ESI/EDI (see asm).
// Delphi: MS Windows: [ebp+20]=param4, [ebp+12]/[ebp+16]=param5, [ebp+8]=param6; see asm for other Delphi targets.
// Callee-saved EBX, ESI, EDI — epilogue must pop EDI, ESI, EBX; SIMD bodies may adjust ESP for locals.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32; P5: UInt64; P6: UInt32);
//     {$I SimdProc6Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi, eax, ecx, edx (load param6 from stack if needed) ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, dword ptr [esp + 28] // param4
  mov ecx, dword ptr [esp + 20] // param5_lo
  mov edx, dword ptr [esp + 24] // param5_hi
{$ELSE}
asm
  {$IFDEF MSWINDOWS}
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, dword ptr [ebp + 20] // param4 (first stack param = high address)
  mov ecx, dword ptr [ebp + 12] // param5_lo
  mov edx, dword ptr [ebp + 16] // param5_hi
  {$ELSE}
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, dword ptr [ebp + 20]
  mov ecx, dword ptr [ebp + 12]
  mov edx, dword ptr [ebp + 16]
  {$ENDIF}
{$ENDIF}
