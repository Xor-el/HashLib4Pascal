// XGETBV query: executes XGETBV with ECX=0, stores EAX:EDX into the
// UInt64 at AResult.
// Expects MS x64 ABI: rcx = AResult.
// On FPC non-Windows (System V ABI), remaps rdi -> rcx.
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFDEF MSWINDOWS}
  mov r8, rcx
  {$ELSE}
  mov r8, rdi
  {$ENDIF}
  xor ecx, ecx
  xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
{$ELSE}
asm
  .noframe
  mov r8, rcx
  xor ecx, ecx
  xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
{$ENDIF}
