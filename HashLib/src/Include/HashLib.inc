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
    {$DEFINE HAS_DELPHI_NET_ENCODING}
  {$IFEND}

{$ENDIF}

{========================== Common Compiler Settings ==========================}

{$HINTS OFF}
{$WARNINGS OFF}
{$RANGECHECKS OFF}
{$OVERFLOWCHECKS OFF}
{$SCOPEDENUMS ON}
{$POINTERMATH ON}

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)
