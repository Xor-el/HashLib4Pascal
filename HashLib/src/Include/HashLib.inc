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

{$ENDIF}

{========================== Common Compiler Settings ==========================}

{$HINTS OFF}
{$WARNINGS OFF}
{$RANGECHECKS OFF}
{$OVERFLOWCHECKS OFF}
{$SCOPEDENUMS ON}
{$POINTERMATH ON}

{============================== SIMD Settings =================================}

// Uncomment to force scalar dispatch (available on all platforms):
// {$DEFINE HASHLIB_FORCE_SCALAR}

{$IF DEFINED(HASHLIB_I386_ASM) OR DEFINED(HASHLIB_X86_64_ASM)}
  {$DEFINE HASHLIB_X86_SIMD}
{$IFEND}

{$IFDEF HASHLIB_X86_SIMD}
// Uncomment ONE to force a specific x86/x86-64 SIMD dispatch level:
// {$DEFINE HASHLIB_FORCE_SSE2}
// {$DEFINE HASHLIB_FORCE_SSSE3}

{$IF (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_SSE2))
  OR (DEFINED(HASHLIB_FORCE_SCALAR) AND DEFINED(HASHLIB_FORCE_SSSE3))
  OR (DEFINED(HASHLIB_FORCE_SSE2) AND DEFINED(HASHLIB_FORCE_SSSE3))}
  {$MESSAGE ERROR 'Only one HASHLIB_FORCE_* define may be enabled at a time.'}
{$IFEND}

{$ENDIF}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
