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

{$IFDEF FPC}
  // FPC 3.0.0 and Above
  {$IF FPC_FULLVERSION < 30000}
     {$MESSAGE ERROR 'This Library requires FreePascal 3.0.0 or higher.'}
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

  {$IF FPC_FULLVERSION >= 30301}
     {.$DEFINE HASHLIB_USE_PPL} // Use Parallel Programming Library
  {$IFEND}

  {$DEFINE USE_UNROLLED_VARIANT}

  {$MODE DELPHI}
  {$MACRO ON}
  {$NOTES OFF}
  {$OPTIMIZATION LEVEL3}
  {$OPTIMIZATION NOUSELOADMODIFYSTORE}
  {$OPTIMIZATION ORDERFIELDS}
  {$OPTIMIZATION DEADVALUES}
  {$IFDEF CPUI386}  {$OPTIMIZATION USEEBP} {$ENDIF}
  {$IFDEF CPUX86_64} {$OPTIMIZATION USERBP} {$ENDIF}
{$ENDIF}

