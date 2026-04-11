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

// FPC 3.2.2 and Above
{$IF FPC_FULLVERSION < 30202}
   {$MESSAGE ERROR 'This Library requires FreePascal 3.2.2 or higher.'}
{$IFEND}

{$IFDEF ENDIAN_BIG}
   {$MESSAGE FATAL 'This Library does not support "Big Endian" processors yet.'}
{$ENDIF}

{$IFDEF FPC_LITTLE_ENDIAN}
   {$DEFINE HASHLIB_LITTLE_ENDIAN}
{$ENDIF}

{$IFDEF FPC_REQUIRES_PROPER_ALIGNMENT}
   {$DEFINE HASHLIB_REQUIRES_PROPER_ALIGNMENT}
{$ENDIF}

{========================= FPC Version Features ===============================}

{$IF FPC_FULLVERSION >= 30301}
   {.$DEFINE HASHLIB_USE_PPL} // Use Parallel Programming Library
{$IFEND}

{$DEFINE USE_UNROLLED_VARIANT}

{============================== CPU Architecture ==============================}

{$IF DEFINED(CPU386)}
  {$DEFINE HASHLIB_I386}
  {$DEFINE HASHLIB_I386_ASM}
{$IFEND}

{$IF DEFINED(CPUX64)}
  {$DEFINE HASHLIB_X86_64}
  {$DEFINE HASHLIB_X86_64_ASM}
{$IFEND}

{$IFDEF CPUARM}
   {$DEFINE HASHLIB_ARM}
   {$DEFINE HASHLIB_ARM_ASM}
{$ENDIF}

{$IFDEF CPUAARCH64}
   {$DEFINE HASHLIB_AARCH64}
   {$DEFINE HASHLIB_AARCH64_ASM}
{$ENDIF}

{================================= Target OS ==================================}

{$IFDEF MSWINDOWS}
   {$DEFINE HASHLIB_MSWINDOWS}
{$ENDIF}

{$IFDEF ANDROID}
   {$DEFINE HASHLIB_ANDROID}
{$ENDIF}

{$IFDEF IOS}
   {$DEFINE HASHLIB_IOS}
{$ENDIF}

{$IF DEFINED(DARWIN) AND NOT DEFINED(HASHLIB_IOS)}
   {$DEFINE HASHLIB_MACOS}
{$IFEND}

{$IF DEFINED(FREEBSD) OR DEFINED(NETBSD) OR DEFINED(OPENBSD) OR DEFINED(DRAGONFLY)}
   {$DEFINE HASHLIB_BSD}
{$IFEND}

{$IFDEF LINUX}
   {$DEFINE HASHLIB_LINUX}
{$ENDIF}

{$IFDEF SOLARIS}
   {$DEFINE HASHLIB_SOLARIS}
{$ENDIF}

{========================= Compiler Mode & Optimizations ======================}

{$MODE DELPHI}
{$IF DEFINED(CPU386) OR DEFINED(CPUX64)}
  {$ASMMODE INTEL}
{$IFEND}
{$MACRO ON}
{$NOTES OFF}

(*
{$OPTIMIZATION LEVEL3}
{$OPTIMIZATION NOUSELOADMODIFYSTORE}
{$OPTIMIZATION ORDERFIELDS}
{$OPTIMIZATION DEADVALUES}
{$IFDEF CPUI386}  {$OPTIMIZATION USEEBP} {$ENDIF}
{$IFDEF CPUX86_64} {$OPTIMIZATION USERBP} {$ENDIF}
*)

