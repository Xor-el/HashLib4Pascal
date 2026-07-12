// Shared SIMD procedure prologue for 7-parameter assembly functions.
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4,
//   ecx = param5 low, edx = param5 high (UInt64 split); param6/param7 are not
//   loaded in this prologue (IA-32 has no free register left) - load them from
//   the documented stack slots when needed.
// FPC: param4 at [esp+32]; param5 at [esp+24]/[esp+28]; param6 at [esp+20];
//   param7 at [esp+16] after push EBX/ESI/EDI (see asm).
// Delphi Win32: first 3 params in EAX/EDX/ECX; param4 at [ebp+24],
//   param5 at [ebp+16]/[ebp+20], param6 at [ebp+12], param7 at [ebp+8].
// Callee-saved EBX, ESI, EDI - epilogue must pop EDI, ESI, EBX; SIMD bodies may adjust ESP for locals.
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32; P5: UInt64; P6: UInt32; P7: Pointer);
//     {$I HlpSimdProc7Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi, eax, ecx, edx (load param6/7 from stack if needed) ...
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
  mov eax, dword ptr [esp + 32] // param4
  mov ecx, dword ptr [esp + 24] // param5_lo
  mov edx, dword ptr [esp + 28] // param5_hi
{$ELSE}
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, dword ptr [ebp + 24] // param4 (first stack param = high address)
  mov ecx, dword ptr [ebp + 16] // param5_lo
  mov edx, dword ptr [ebp + 20] // param5_hi
{$ENDIF}
