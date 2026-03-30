// XGETBV query: executes XGETBV with ECX=0, stores EAX:EDX into the
// UInt64 at AResult (same contract as XGetBvQuery.inc on x86-64).
//
// FPC i386: AResult in EAX at asm entry (Windows and Unix).
// Delphi: same.
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  mov ebx, eax
  xor ecx, ecx
  xgetbv
  mov [ebx], eax
  mov [ebx + 4], edx
  pop ebx
{$ELSE}
asm
  push ebx
  mov ebx, eax
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv (ECX in, EDX:EAX out)
  mov [ebx], eax
  mov [ebx + 4], edx
  pop ebx
{$ENDIF}
