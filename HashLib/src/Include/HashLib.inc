{ * ************************************************************************ * }
{ *                              HashLib Library                             * }
{ *                       Author - Ugochukwu Mmaduekwe                       * }
{ *              Github Repository <https://github.com/Xor-el>               * }
{ *                                                                          * }
{ *  Distributed under the MIT software license, see the accompanying file   * }
{ *                                 LICENSE                                  * }
{ *         or visit http://www.opensource.org/licenses/mit-license.         * }
{ *                                                                          * }
{ * ************************************************************************ * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

{========================= Compiler Specific Settings =========================}

{$IFDEF FPC}
  {$I HashLibFPC.inc}
{$ELSE}
  // Delphi 2010 and Above
  {$IF CompilerVersion < 21.0}
    {$MESSAGE ERROR 'This Library requires Delphi 2010 or higher.'}
  {$IFEND}
  
  {$DEFINE DELPHI}

  {$DEFINITIONINFO ON} // Enable code browsing (Ctrl+Click)
  {$STRINGCHECKS OFF}
  {$WARN DUPLICATE_CTOR_DTOR OFF}

  {$DEFINE HASHLIB_LITTLE_ENDIAN}

  {$IFDEF CPUARM}
    {$DEFINE HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  {$ENDIF}

  {$DEFINE USE_UNROLLED_VARIANT}

  {$IF CompilerVersion >= 25.0}
    {$DEFINE SHIFT_OVERFLOW_BUG_FIXED}
  {$IFEND}

  {$IF CompilerVersion >= 28.0}
    {$DEFINE HASHLIB_USE_PPL} // Use Parallel Programming Library
  {$IFEND}

  {============================== CPU Architecture ==============================}

  {$IF DEFINED(CPU386)}
    {$DEFINE HASHLIB_I386}
    {$IFDEF MSWINDOWS}
      {$DEFINE HASHLIB_I386_ASM}
    {$ENDIF}
  {$IFEND}

  {$IF DEFINED(CPUX64)}
    {$DEFINE HASHLIB_X86_64}
    {$IFDEF MSWINDOWS}
      {$DEFINE HASHLIB_X86_64_ASM}
    {$ENDIF}
  {$IFEND}

  {$IFDEF CPUARM32}
    {$DEFINE HASHLIB_ARM32}
  {$ENDIF}

  {$IFDEF CPUARM64}
    {$DEFINE HASHLIB_AARCH64}
  {$ENDIF}

  {================================= Target OS ==================================}

  {$IFDEF MSWINDOWS}
    {$DEFINE HASHLIB_MSWINDOWS}
  {$ENDIF}

  {$IFDEF IOS}
    {$DEFINE HASHLIB_IOS}
  {$ENDIF}

  {$IFDEF MACOS}
    {$IFNDEF IOS}
      {$DEFINE HASHLIB_MACOS}
    {$ENDIF}
  {$ENDIF}

  {$IFDEF ANDROID}
    {$DEFINE HASHLIB_ANDROID}
  {$ENDIF}

  {$IFDEF LINUX}
    {$DEFINE HASHLIB_LINUX}
  {$ENDIF}

{$ENDIF}

{========================== Common Compiler Settings ==========================}

{$HINTS OFF}
{$WARNINGS OFF}
{$RANGECHECKS OFF}
{$OVERFLOWCHECKS OFF}
{$SCOPEDENUMS ON}
{$POINTERMATH ON}

{========================== Common Defines Settings ===========================}

{$IF DEFINED(HASHLIB_I386) OR DEFINED(HASHLIB_X86_64)}
  {$DEFINE HASHLIB_X86}
{$IFEND}

{$IF DEFINED(HASHLIB_ARM32) OR DEFINED(HASHLIB_AARCH64)}
  {$DEFINE HASHLIB_ARM}
{$IFEND}

{============================ Common SIMD Settings ============================}

// Uncomment to force scalar dispatch (available on all platforms):
// {$DEFINE HASHLIB_FORCE_SCALAR}

{$IF DEFINED(HASHLIB_I386_ASM) OR DEFINED(HASHLIB_X86_64_ASM)}
  {$DEFINE HASHLIB_X86_SIMD}
{$IFEND}

{$IF DEFINED(HASHLIB_ARM32_ASM) OR DEFINED(HASHLIB_AARCH64_ASM)}
  {$DEFINE HASHLIB_ARM_SIMD}
{$IFEND}

{$IFDEF HASHLIB_X86_SIMD}
// Uncomment ONE to force a specific X86 SIMD dispatch level:
// {$DEFINE HASHLIB_FORCE_SSE2}
// {$DEFINE HASHLIB_FORCE_SSSE3}

{$IF (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_SSE2))
  OR (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_SSSE3))
  OR (DEFINED(HASHLIB_FORCE_SSE2) AND DEFINED(HASHLIB_FORCE_SSSE3))}
  {$MESSAGE ERROR 'Only one HASHLIB_FORCE_* define may be enabled at a time.'}
{$IFEND}

{$ENDIF}

{$IFDEF HASHLIB_ARM_SIMD}
// Uncomment ONE to force a specific Arm SIMD dispatch level:
// {$DEFINE HASHLIB_FORCE_NEON}
// {$DEFINE HASHLIB_FORCE_SVE}

{$IF (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_NEON))
  OR (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_SVE))
  OR (DEFINED(HASHLIB_FORCE_NEON) AND DEFINED(HASHLIB_FORCE_SVE))}
  {$MESSAGE ERROR 'Only one HASHLIB_FORCE_* define may be enabled at a time.'}
{$IFEND}

{$ENDIF}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
