// XGETBV query: executes XGETBV with ECX=0, stores EAX:EDX into the
// UInt64 at AResult.
// IA-32: AResult in EAX at asm entry (Windows and Unix).
// x86-64: MS ABI rcx=AResult; FPC non-Windows remaps rdi -> r8.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF HASHLIB_I386_ASM}
  push ebx
  mov ebx, eax
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov [ebx], eax
  mov [ebx + 4], edx
  pop ebx
{$ELSE}
  {$IFDEF FPC}
  {$IFDEF MSWINDOWS}
  mov r8, rcx
  {$ELSE}
  mov r8, rdi
  {$ENDIF}
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
  {$ELSE}
  .noframe
  mov r8, rcx
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
  {$ENDIF}
{$ENDIF}
