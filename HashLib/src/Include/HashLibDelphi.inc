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

{$IFDEF DELPHI}
  {$DEFINITIONINFO ON}       // IDE navigation; no binary impact
  {$STRINGCHECKS OFF}
  {$WARN DUPLICATE_CTOR_DTOR OFF}

  {$DEFINE HASHLIB_LITTLE_ENDIAN}

{$IFDEF CPUARM}
   {$DEFINE HASHLIB_REQUIRES_PROPER_ALIGNMENT}
{$ENDIF}

  {$DEFINE USE_UNROLLED_VARIANT}

 // 2010 only
{$IF CompilerVersion = 21.0}
   {$DEFINE DELPHI2010}
{$IFEND}

  // XE and Above
{$IF CompilerVersion >= 22.0}
   {$DEFINE DELPHIXE_UP}
{$IFEND}

 // XE4 and Above
{$IF CompilerVersion >= 25.0}
   {$DEFINE SHIFT_OVERFLOW_BUG_FIXED}
{$IFEND}

  // XE7 and Above
{$IF CompilerVersion >= 28.0}
   {$DEFINE HASHLIB_USE_PPL} // Use Parallel Programming Library
   {$DEFINE HAS_DELPHI_NET_ENCODING}
{$IFEND}

  {$IF CompilerVersion < 21.0}
    {$MESSAGE ERROR 'This Library requires Delphi 2010 or higher.'}
  {$IFEND}
{$ENDIF}

