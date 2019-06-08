program PerformanceBenchmarkConsole;

{$APPTYPE CONSOLE}

uses
  Classes,
  SysUtils,
  uPerformanceBenchmark in '..\..\src\Core\uPerformanceBenchmark.pas',
  HlpCRC in '..\..\..\HashLib\src\Checksum\HlpCRC.pas',
  HlpICRC in '..\..\..\HashLib\src\Interfaces\HlpICRC.pas',
  HlpBitConverter in '..\..\..\HashLib\src\Utils\HlpBitConverter.pas',
  HlpGrindahl512 in '..\..\..\HashLib\src\Crypto\HlpGrindahl512.pas',
  HlpGrindahl256 in '..\..\..\HashLib\src\Crypto\HlpGrindahl256.pas',
  HlpHashFactory in '..\..\..\HashLib\src\Base\HlpHashFactory.pas',
  HlpCRC32Fast in '..\..\..\HashLib\src\Checksum\HlpCRC32Fast.pas',
  HlpCRC64 in '..\..\..\HashLib\src\Checksum\HlpCRC64.pas',
  HlpCRC32 in '..\..\..\HashLib\src\Checksum\HlpCRC32.pas',
  HlpBlake2B in '..\..\..\HashLib\src\Crypto\HlpBlake2B.pas',
  HlpFNV64 in '..\..\..\HashLib\src\Hash64\HlpFNV64.pas',
  HlpBits in '..\..\..\HashLib\src\Utils\HlpBits.pas',
  HlpConverters in '..\..\..\HashLib\src\Utils\HlpConverters.pas',
  HlpSHA3 in '..\..\..\HashLib\src\Crypto\HlpSHA3.pas',
  HlpIHashInfo in '..\..\..\HashLib\src\Interfaces\HlpIHashInfo.pas',
  HlpHashBuffer in '..\..\..\HashLib\src\Base\HlpHashBuffer.pas',
  HlpSnefru in '..\..\..\HashLib\src\Crypto\HlpSnefru.pas',
  HlpHash in '..\..\..\HashLib\src\Base\HlpHash.pas',
  HlpXXHash32 in '..\..\..\HashLib\src\Hash32\HlpXXHash32.pas',
  HlpXXHash64 in '..\..\..\HashLib\src\Hash64\HlpXXHash64.pas',
  HlpHashCryptoNotBuildIn in '..\..\..\HashLib\src\Base\HlpHashCryptoNotBuildIn.pas',
  HlpHMACNotBuildInAdapter in '..\..\..\HashLib\src\Base\HlpHMACNotBuildInAdapter.pas',
  HlpPBKDF2_HMACNotBuildInAdapter in '..\..\..\HashLib\src\KDF\HlpPBKDF2_HMACNotBuildInAdapter.pas',
  HlpPBKDF_Argon2NotBuildInAdapter in '..\..\..\HashLib\src\KDF\HlpPBKDF_Argon2NotBuildInAdapter.pas',
  HlpArgon2TypeAndVersion in '..\..\..\HashLib\src\KDF\HlpArgon2TypeAndVersion.pas',
  HlpPBKDF_ScryptNotBuildInAdapter in '..\..\..\HashLib\src\KDF\HlpPBKDF_ScryptNotBuildInAdapter.pas',
  HlpPanama in '..\..\..\HashLib\src\Crypto\HlpPanama.pas',
  HlpAdler32 in '..\..\..\HashLib\src\Checksum\HlpAdler32.pas',
  HlpAP in '..\..\..\HashLib\src\Hash32\HlpAP.pas',
  HlpBernstein in '..\..\..\HashLib\src\Hash32\HlpBernstein.pas',
  HlpBernstein1 in '..\..\..\HashLib\src\Hash32\HlpBernstein1.pas',
  HlpBKDR in '..\..\..\HashLib\src\Hash32\HlpBKDR.pas',
  HlpBlake2BConfig in '..\..\..\HashLib\src\Crypto\Blake2BConfigurations\HlpBlake2BConfig.pas',
  HlpBlake2BIvBuilder in '..\..\..\HashLib\src\Crypto\Blake2BConfigurations\HlpBlake2BIvBuilder.pas',
  HlpBlake2BTreeConfig in '..\..\..\HashLib\src\Crypto\Blake2BConfigurations\HlpBlake2BTreeConfig.pas',
  HlpBlake2S in '..\..\..\HashLib\src\Crypto\HlpBlake2S.pas',
  HlpBlake2SConfig in '..\..\..\HashLib\src\Crypto\Blake2SConfigurations\HlpBlake2SConfig.pas',
  HlpBlake2SIvBuilder in '..\..\..\HashLib\src\Crypto\Blake2SConfigurations\HlpBlake2SIvBuilder.pas',
  HlpBlake2STreeConfig in '..\..\..\HashLib\src\Crypto\Blake2SConfigurations\HlpBlake2STreeConfig.pas',
  HlpCRC16 in '..\..\..\HashLib\src\Checksum\HlpCRC16.pas',
  HlpDEK in '..\..\..\HashLib\src\Hash32\HlpDEK.pas',
  HlpDJB in '..\..\..\HashLib\src\Hash32\HlpDJB.pas',
  HlpELF in '..\..\..\HashLib\src\Hash32\HlpELF.pas',
  HlpFNV in '..\..\..\HashLib\src\Hash32\HlpFNV.pas',
  HlpFNV1a in '..\..\..\HashLib\src\Hash32\HlpFNV1a.pas',
  HlpFNV1a64 in '..\..\..\HashLib\src\Hash64\HlpFNV1a64.pas',
  HlpGost in '..\..\..\HashLib\src\Crypto\HlpGost.pas',
  HlpGOST3411_2012 in '..\..\..\HashLib\src\Crypto\HlpGOST3411_2012.pas',
  HlpHAS160 in '..\..\..\HashLib\src\Crypto\HlpHAS160.pas',
  HlpHashLibTypes in '..\..\..\HashLib\src\Utils\HlpHashLibTypes.pas',
  HlpHashResult in '..\..\..\HashLib\src\Base\HlpHashResult.pas',
  HlpHashRounds in '..\..\..\HashLib\src\Base\HlpHashRounds.pas',
  HlpHashSize in '..\..\..\HashLib\src\Base\HlpHashSize.pas',
  HlpHaval in '..\..\..\HashLib\src\Crypto\HlpHaval.pas',
  HlpIBlake2BConfig in '..\..\..\HashLib\src\Interfaces\IBlake2BConfigurations\HlpIBlake2BConfig.pas',
  HlpIBlake2BTreeConfig in '..\..\..\HashLib\src\Interfaces\IBlake2BConfigurations\HlpIBlake2BTreeConfig.pas',
  HlpIBlake2SConfig in '..\..\..\HashLib\src\Interfaces\IBlake2SConfigurations\HlpIBlake2SConfig.pas',
  HlpIBlake2STreeConfig in '..\..\..\HashLib\src\Interfaces\IBlake2SConfigurations\HlpIBlake2STreeConfig.pas',
  HlpIHash in '..\..\..\HashLib\src\Interfaces\HlpIHash.pas',
  HlpIHashResult in '..\..\..\HashLib\src\Interfaces\HlpIHashResult.pas',
  HlpIKDF in '..\..\..\HashLib\src\Interfaces\HlpIKDF.pas',
  HlpJenkins3 in '..\..\..\HashLib\src\Hash32\HlpJenkins3.pas',
  HlpJS in '..\..\..\HashLib\src\Hash32\HlpJS.pas',
  HlpKDF in '..\..\..\HashLib\src\Base\HlpKDF.pas',
  HlpMD2 in '..\..\..\HashLib\src\Crypto\HlpMD2.pas',
  HlpMD4 in '..\..\..\HashLib\src\Crypto\HlpMD4.pas',
  HlpMD5 in '..\..\..\HashLib\src\Crypto\HlpMD5.pas',
  HlpMDBase in '..\..\..\HashLib\src\Crypto\HlpMDBase.pas',
  HlpMultipleTransformNonBlock in '..\..\..\HashLib\src\Base\HlpMultipleTransformNonBlock.pas',
  HlpMurmur2 in '..\..\..\HashLib\src\Hash32\HlpMurmur2.pas',
  HlpMurmur2_64 in '..\..\..\HashLib\src\Hash64\HlpMurmur2_64.pas',
  HlpMurmurHash3_x64_128 in '..\..\..\HashLib\src\Hash128\HlpMurmurHash3_x64_128.pas',
  HlpMurmurHash3_x86_32 in '..\..\..\HashLib\src\Hash32\HlpMurmurHash3_x86_32.pas',
  HlpMurmurHash3_x86_128 in '..\..\..\HashLib\src\Hash128\HlpMurmurHash3_x86_128.pas',
  HlpNullable in '..\..\..\HashLib\src\Nullable\HlpNullable.pas',
  HlpNullDigest in '..\..\..\HashLib\src\NullDigest\HlpNullDigest.pas',
  HlpOneAtTime in '..\..\..\HashLib\src\Hash32\HlpOneAtTime.pas',
  HlpPJW in '..\..\..\HashLib\src\Hash32\HlpPJW.pas',
  HlpRadioGatun32 in '..\..\..\HashLib\src\Crypto\HlpRadioGatun32.pas',
  HlpRadioGatun64 in '..\..\..\HashLib\src\Crypto\HlpRadioGatun64.pas',
  HlpRIPEMD in '..\..\..\HashLib\src\Crypto\HlpRIPEMD.pas',
  HlpRIPEMD128 in '..\..\..\HashLib\src\Crypto\HlpRIPEMD128.pas',
  HlpRIPEMD160 in '..\..\..\HashLib\src\Crypto\HlpRIPEMD160.pas',
  HlpRIPEMD256 in '..\..\..\HashLib\src\Crypto\HlpRIPEMD256.pas',
  HlpRIPEMD320 in '..\..\..\HashLib\src\Crypto\HlpRIPEMD320.pas',
  HlpRotating in '..\..\..\HashLib\src\Hash32\HlpRotating.pas',
  HlpRS in '..\..\..\HashLib\src\Hash32\HlpRS.pas',
  HlpSDBM in '..\..\..\HashLib\src\Hash32\HlpSDBM.pas',
  HlpSHA0 in '..\..\..\HashLib\src\Crypto\HlpSHA0.pas',
  HlpSHA1 in '..\..\..\HashLib\src\Crypto\HlpSHA1.pas',
  HlpSHA2_224 in '..\..\..\HashLib\src\Crypto\HlpSHA2_224.pas',
  HlpSHA2_256 in '..\..\..\HashLib\src\Crypto\HlpSHA2_256.pas',
  HlpSHA2_256Base in '..\..\..\HashLib\src\Crypto\HlpSHA2_256Base.pas',
  HlpSHA2_384 in '..\..\..\HashLib\src\Crypto\HlpSHA2_384.pas',
  HlpSHA2_512 in '..\..\..\HashLib\src\Crypto\HlpSHA2_512.pas',
  HlpSHA2_512_224 in '..\..\..\HashLib\src\Crypto\HlpSHA2_512_224.pas',
  HlpSHA2_512_256 in '..\..\..\HashLib\src\Crypto\HlpSHA2_512_256.pas',
  HlpSHA2_512Base in '..\..\..\HashLib\src\Crypto\HlpSHA2_512Base.pas',
  HlpShiftAndXor in '..\..\..\HashLib\src\Hash32\HlpShiftAndXor.pas',
  HlpSipHash in '..\..\..\HashLib\src\Hash64\HlpSipHash.pas',
  HlpSuperFast in '..\..\..\HashLib\src\Hash32\HlpSuperFast.pas',
  HlpTiger in '..\..\..\HashLib\src\Crypto\HlpTiger.pas',
  HlpTiger2 in '..\..\..\HashLib\src\Crypto\HlpTiger2.pas',
  HlpWhirlPool in '..\..\..\HashLib\src\Crypto\HlpWhirlPool.pas',
  HlpArrayUtils in '..\..\..\HashLib\src\Utils\HlpArrayUtils.pas';

var
  StringList: TStringList;
  Log: String;

begin
  try
    Writeln('Please be patient, this might take some time' + SLineBreak);
    StringList := TStringList.Create;
    try
      TPerformanceBenchmark.DoBenchmark(StringList);

      for Log in StringList do
      begin
        Writeln(Log);
      end;

    finally
      StringList.Free;
    end;
    Writeln(SLineBreak + 'Performance Benchmark Finished');
    ReadLn;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;

end.
