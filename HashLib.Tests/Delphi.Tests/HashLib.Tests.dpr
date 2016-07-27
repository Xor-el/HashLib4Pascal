program HashLib.Tests;
{

  Delphi DUnit Test Project
  -------------------------
  This project contains the DUnit test framework and the GUI/Console test runners.
  Add "CONSOLE_TESTRUNNER" to the conditional defines entry in the project options
  to use the console test runner.  Otherwise the GUI test runner will be used by
  default.

}

{$WARNINGS OFF}
{$IFDEF CONSOLE_TESTRUNNER}
{$APPTYPE CONSOLE}
{$ENDIF}

uses
  Forms,
  TestFramework,
  GUITestRunner,
  TextTestRunner,
  uConverters in '..\..\HashLib\src\Base\uConverters.pas',
  uHash in '..\..\HashLib\src\Base\uHash.pas',
  uKDF in '..\..\HashLib\src\Base\uKDF.pas',
  uHashBuffer in '..\..\HashLib\src\Base\uHashBuffer.pas',
  uHashCryptoNotBuildIn in '..\..\HashLib\src\Base\uHashCryptoNotBuildIn.pas',
  uHashFactory in '..\..\HashLib\src\Base\uHashFactory.pas',
  uHashResult in '..\..\HashLib\src\Base\uHashResult.pas',
  uHashRounds in '..\..\HashLib\src\Base\uHashRounds.pas',
  uHashSize in '..\..\HashLib\src\Base\uHashSize.pas',
  uHMACNotBuildInAdapter in '..\..\HashLib\src\Base\uHMACNotBuildInAdapter.pas',
  uMultipleTransformNonBlock
    in '..\..\HashLib\src\Base\uMultipleTransformNonBlock.pas',
  uAdler32 in '..\..\HashLib\src\Checksum\uAdler32.pas',
  uCRC in '..\..\HashLib\src\Checksum\uCRC.pas',
  uCRC16 in '..\..\HashLib\src\Checksum\uCRC16.pas',
  uCRC32 in '..\..\HashLib\src\Checksum\uCRC32.pas',
  uCRC64 in '..\..\HashLib\src\Checksum\uCRC64.pas',
  uGost in '..\..\HashLib\src\Crypto\uGost.pas',
  uGrindahl256 in '..\..\HashLib\src\Crypto\uGrindahl256.pas',
  uGrindahl512 in '..\..\HashLib\src\Crypto\uGrindahl512.pas',
  uHAS160 in '..\..\HashLib\src\Crypto\uHAS160.pas',
  uHaval in '..\..\HashLib\src\Crypto\uHaval.pas',
  uMD2 in '..\..\HashLib\src\Crypto\uMD2.pas',
  uMD4 in '..\..\HashLib\src\Crypto\uMD4.pas',
  uMD5 in '..\..\HashLib\src\Crypto\uMD5.pas',
  uMDBase in '..\..\HashLib\src\Crypto\uMDBase.pas',
  uPanama in '..\..\HashLib\src\Crypto\uPanama.pas',
  uRadioGatun32 in '..\..\HashLib\src\Crypto\uRadioGatun32.pas',
  uRadioGatun64 in '..\..\HashLib\src\Crypto\uRadioGatun64.pas',
  uRIPEMD in '..\..\HashLib\src\Crypto\uRIPEMD.pas',
  uRIPEMD128 in '..\..\HashLib\src\Crypto\uRIPEMD128.pas',
  uRIPEMD160 in '..\..\HashLib\src\Crypto\uRIPEMD160.pas',
  uRIPEMD256 in '..\..\HashLib\src\Crypto\uRIPEMD256.pas',
  uRIPEMD320 in '..\..\HashLib\src\Crypto\uRIPEMD320.pas',
  uSHA0 in '..\..\HashLib\src\Crypto\uSHA0.pas',
  uSHA1 in '..\..\HashLib\src\Crypto\uSHA1.pas',
  uSHA2_224 in '..\..\HashLib\src\Crypto\uSHA2_224.pas',
  uSHA2_256 in '..\..\HashLib\src\Crypto\uSHA2_256.pas',
  uSHA2_256Base in '..\..\HashLib\src\Crypto\uSHA2_256Base.pas',
  uSHA2_384 in '..\..\HashLib\src\Crypto\uSHA2_384.pas',
  uSHA2_512 in '..\..\HashLib\src\Crypto\uSHA2_512.pas',
  uSHA2_512_224 in '..\..\HashLib\src\Crypto\uSHA2_512_224.pas',
  uSHA2_512_256 in '..\..\HashLib\src\Crypto\uSHA2_512_256.pas',
  uSHA2_512Base in '..\..\HashLib\src\Crypto\uSHA2_512Base.pas',
  uSHA3 in '..\..\HashLib\src\Crypto\uSHA3.pas',
  uSnefru in '..\..\HashLib\src\Crypto\uSnefru.pas',
  uTiger in '..\..\HashLib\src\Crypto\uTiger.pas',
  uTiger2 in '..\..\HashLib\src\Crypto\uTiger2.pas',
  uWhirlPool in '..\..\HashLib\src\Crypto\uWhirlPool.pas',
  uAP in '..\..\HashLib\src\Hash32\uAP.pas',
  uBernstein in '..\..\HashLib\src\Hash32\uBernstein.pas',
  uBernstein1 in '..\..\HashLib\src\Hash32\uBernstein1.pas',
  uBKDR in '..\..\HashLib\src\Hash32\uBKDR.pas',
  uDEK in '..\..\HashLib\src\Hash32\uDEK.pas',
  uDJB in '..\..\HashLib\src\Hash32\uDJB.pas',
  uELF in '..\..\HashLib\src\Hash32\uELF.pas',
  uFNV in '..\..\HashLib\src\Hash32\uFNV.pas',
  uFNV1a in '..\..\HashLib\src\Hash32\uFNV1a.pas',
  uJenkins3 in '..\..\HashLib\src\Hash32\uJenkins3.pas',
  uJS in '..\..\HashLib\src\Hash32\uJS.pas',
  uMurmur2 in '..\..\HashLib\src\Hash32\uMurmur2.pas',
  uMurmurHash3_x86_32 in '..\..\HashLib\src\Hash32\uMurmurHash3_x86_32.pas',
  uOneAtTime in '..\..\HashLib\src\Hash32\uOneAtTime.pas',
  uPJW in '..\..\HashLib\src\Hash32\uPJW.pas',
  uRotating in '..\..\HashLib\src\Hash32\uRotating.pas',
  uRS in '..\..\HashLib\src\Hash32\uRS.pas',
  uSDBM in '..\..\HashLib\src\Hash32\uSDBM.pas',
  uShiftAndXor in '..\..\HashLib\src\Hash32\uShiftAndXor.pas',
  uSuperFast in '..\..\HashLib\src\Hash32\uSuperFast.pas',
  uXXHash32 in '..\..\HashLib\src\Hash32\uXXHash32.pas',
  uFNV1a64 in '..\..\HashLib\src\Hash64\uFNV1a64.pas',
  uFNV64 in '..\..\HashLib\src\Hash64\uFNV64.pas',
  uMurmur2_64 in '..\..\HashLib\src\Hash64\uMurmur2_64.pas',
  uSipHash2_4 in '..\..\HashLib\src\Hash64\uSipHash2_4.pas',
  uXXHash64 in '..\..\HashLib\src\Hash64\uXXHash64.pas',
  uMurmurHash3_x86_128 in '..\..\HashLib\src\Hash128\uMurmurHash3_x86_128.pas',
  uMurmurHash3_x64_128 in '..\..\HashLib\src\Hash128\uMurmurHash3_x64_128.pas',
  uIHash in '..\..\HashLib\src\Interfaces\uIHash.pas',
  uIKDF in '..\..\HashLib\src\Interfaces\uIKDF.pas',
  uICRC in '..\..\HashLib\src\Interfaces\uICRC.pas',
  uIHashBuffer in '..\..\HashLib\src\Interfaces\uIHashBuffer.pas',
  uIHashInfo in '..\..\HashLib\src\Interfaces\uIHashInfo.pas',
  uIHashResult in '..\..\HashLib\src\Interfaces\uIHashResult.pas',
  uPBKDF2_HMACNotBuildInAdapter
    in '..\..\HashLib\src\KDF\uPBKDF2_HMACNotBuildInAdapter.pas',
  uNullable in '..\..\HashLib\src\Nullable\uNullable.pas',
  uArrayExtensions in '..\..\HashLib\src\Utils\uArrayExtensions.pas',
  uBitConverter in '..\..\HashLib\src\Utils\uBitConverter.pas',
  uBits in '..\..\HashLib\src\Utils\uBits.pas',
  uHashLibTypes in '..\..\HashLib\src\Utils\uHashLibTypes.pas',
  HashLibTests in '..\src\HashLibTests.pas',
  BitConverterTests in '..\src\BitConverterTests.pas',
  PBKDF2_HMACTests in '..\src\PBKDF2_HMACTests.pas';

begin

  Application.Initialize;
  if IsConsole then
    TextTestRunner.RunRegisteredTests
  else
    GUITestRunner.RunRegisteredTests;

end.
