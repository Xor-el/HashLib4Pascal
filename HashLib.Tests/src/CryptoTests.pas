unit CryptoTests;

interface

{$IFDEF FPC}
{$WARNINGS OFF}
{$NOTES OFF}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HashLibTestBase,
  HlpHashFactory,
  HlpIHash,
  HlpIHashInfo,
  HlpConverters,
  HlpBlake2BConfig,
  HlpIBlake2BConfig,
  HlpBlake2STreeConfig,
  HlpIBlake2STreeConfig,
  Blake2BTestVectors,
  HlpBlake2SConfig,
  HlpIBlake2SConfig,
  HlpBlake2BTreeConfig,
  HlpIBlake2BTreeConfig,
  Blake2STestVectors;

// Crypto

type

  TTestGost = class(THashLibAlgorithmTestCase)

  private

    FGost: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D';
    FExpectedHashOfDefaultData
      : String =
      '21DCCFBF20D313170333BA15596338FB5964267328EB42CA10E269B7045FF856';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'DE9D68F7793C829E7369AC09493A7749B2637A7B1D572A70549936E09F2D1D82';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '6E4E2895E194BEB0A083B1DED6C4084F5E7F37BAAB988D288D9707235F2F8294';
    FExpectedHashOfOnetoNine
      : String =
      '264B4E433DEE474AEC465FA9C725FE963BC4B4ABC4FDAC63B7F73B671663AFC9';
    FExpectedHashOfabcde
      : String =
      'B18CFD04F92DC1D83325036BC723D36DB25EDE41AE879D2545FC7F377B700899';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestGOST3411_2012_256 = class(THashLibAlgorithmTestCase)

  private

    FGOST3411_2012_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB';
    FExpectedHashOfQuickBrownFox =
      '3E7DEA7F2384B6C5A3D0E24AAA29C05E89DDD762145030EC22C71A6DB8B2C1F4';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestQuickBrownFox;
    procedure TestIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestGOST3411_2012_512 = class(THashLibAlgorithmTestCase)

  private

    FGOST3411_2012_512: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A';
    FExpectedHashOfQuickBrownFox =
      'D2B793A0BB6CB5904828B5B6DCFB443BB8F33EFC06AD09368878AE4CDC8245B97E60802469BED1E7C21A64FF0B179A6A1E0BB74D92965450A0ADAB69162C00FE';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestQuickBrownFox;
    procedure TestIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestGrindahl256 = class(THashLibAlgorithmTestCase)

  private

    FGrindahl256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '45A7600159AF54AE110FCB6EA0F38AD57875EAC814F74D2CBC247D28C89923E6';
    FExpectedHashOfDefaultData
      : String =
      'AC72E90B0F3F5864A0AF3C43E2A73E393DEBF22AB81B6786ADE22B4517DAAAB6';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '02D964EE346B0C333CEC0F5D7E68C5CFAAC1E3CB0C06FE36418E17AA3AFCA2BE';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '65BA6F8EFA5B566D556EC8E3A2EC67DB7EE9BDEE663F17A8B8E7FAD067481023';
    FExpectedHashOfOnetoNine
      : String =
      'D2460846C5FE9E4750985CC9244D2458BEFD884435121FE56528022A3C7605B7';
    FExpectedHashOfabcde
      : String =
      '5CDA73422F36E41087795BB6C21D577BAAF114E4A6CCF33D919E700EE2489FE2';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestGrindahl512 = class(THashLibAlgorithmTestCase)

  private

    FGrindahl512: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'EE0BA85F90B6D232430BA43DD0EDD008462591816962A355602ED214FAAE54A9A4607D6F577CE950421FF58AEA53F51A7A9F5CCA894C3776104D43568FEA1207';
    FExpectedHashOfDefaultData
      : String =
      '540F3C6A5070DA391BBA7121DB8F8745752D3515164498FC82CB5B4D837632CF3F256D85C4A0B7F34A86936FAB07BDA2DF2BFDD59AFDBD901E1347C2001DB1AD';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '59A3F868AE1844BA9B683760D62C73E6E254BE6F46DF923F45118F32E9E1AB80A9056AA8A4792F0D6B8C709919C0ACC64EF64FC013C919758841AE6026F47E61';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '7F067A454A4F6300982CAE37900171C627992A75A5567E0D3A51BC6672F79C5AC0CEF5978E933B713F38494DDF26114994C47689AC93EEC9B8EF7892C3B24087';
    FExpectedHashOfOnetoNine
      : String =
      '6845F20B8A9DB083F307844506D342ED0FEE0D16BAF64B22E6C07552CB8C907E936FEDCD885B72C1B05813F722B5706C112AD59D3421CFD88CAA1CFB40EF1BEF';
    FExpectedHashOfabcde
      : String =
      'F282C47F31831EAB58B8EE9D1EEE3B9B5A6A86354EEFE84CA3176BED5AB447E6D5AC82316F2D6FAAD350848E2D418336A57772D96311DA8BC51C93087204C6A5';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHAS160 = class(THashLibAlgorithmTestCase)

  private

    FHAS160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '307964EF34151D37C8047ADEC7AB50F4FF89762D';
    FExpectedHashOfDefaultData
      : String = '2773EDAC4501514254D7B1DF091D6B7652250A52';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '7D2F0051F2BD817A4C27F126882353BCD300B7CA';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '53970A7AC510A85D0E22FF506FED5B57188A8B3F';
    FExpectedHashOfOnetoNine
      : String = 'A0DA48CCD36C9D24AA630D4B3673525E9109A83C';
    FExpectedHashOfabcde: String = 'EEEA94C2F0450B639BC2ACCAF4AEB172A5885313';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_3_128 = class(THashLibAlgorithmTestCase)

  private

    FHaval_3_128: IHash;

  const
    FExpectedHashOfEmptyData: String = 'C68F39913F901F3DDF44C707357A7D70';
    FExpectedHashOfDefaultData: String = '04AF7562BA75D5767ADE2A71E4BE33DE';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'E5639CDBE9AE8B58DEC50065909624D4';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '9D49ED7B5D42C64F590A164C5D1AAE9F';
    FExpectedHashOfOnetoNine: String = 'F2F92D4E5CA6B92A5B5FC5AC822C39D2';
    FExpectedHashOfabcde: String = '51D4032478AA59182916E6C111FA79A6';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_4_128 = class(THashLibAlgorithmTestCase)

  private

    FHaval_4_128: IHash;

  const
    FExpectedHashOfEmptyData: String = 'EE6BBF4D6A46A679B3A856C88538BB98';
    FExpectedHashOfDefaultData: String = 'C815192C498CF266D0EB32E90D60892E';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '37A443E8FB7DE00C28BCE8D3F47BECE8';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '9A0B60DEB9F9FBB2A9DAD87A8C653E72';
    FExpectedHashOfOnetoNine: String = '52DFE2F3DA02591061B02DBDC1510F1C';
    FExpectedHashOfabcde: String = '61634059D9B8336FEB32CA27533ED284';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_5_128 = class(THashLibAlgorithmTestCase)

  private

    FHaval_5_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '184B8482A0C050DCA54B59C7F05BF5DD';
    FExpectedHashOfDefaultData: String = 'B335D2DC38EFB9D937B803F7581AF88D';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'AB287584D5D67B006986F039321FBA2F';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '1D5D93E71FF0B324C54ADD1FBDE1F4E4';
    FExpectedHashOfOnetoNine: String = '8AA1C1CA3A7E4F983654C4F689DE6F8D';
    FExpectedHashOfabcde: String = '11C0532F713332D45D6769376DD6EB3B';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_3_160 = class(THashLibAlgorithmTestCase)

  private

    FHaval_3_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'D353C3AE22A25401D257643836D7231A9A95F953';
    FExpectedHashOfDefaultData
      : String = '4A5E28CA30029D2D04287E6C807E74D297A7FC74';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'B42F2273A6220C65B5ADAE1A9A1188B9D4398D2A';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'E686A2E785EA222FA28911D9243567EB72362D3C';
    FExpectedHashOfOnetoNine
      : String = '39A83AF3293CDAC04DE1DF3D0BE7A1F9D8AAB923';
    FExpectedHashOfabcde: String = '8D7C2218BDD8CB0608BA2479751B44BB15F1FC1F';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_4_160 = class(THashLibAlgorithmTestCase)

  private

    FHaval_4_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '1D33AAE1BE4146DBAACA0B6E70D7A11F10801525';
    FExpectedHashOfDefaultData
      : String = '9E86A9E2D964CCF9019593C88F40AA5C725E0912';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'E7969DB764172896F2467CF74F62BBE231E2772D';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '6FEAC0105DA74AEDC8FA76A1CF0848C8CA94BA28';
    FExpectedHashOfOnetoNine
      : String = 'B03439BE6F2A3EBED93AC86846D029D76F62FD99';
    FExpectedHashOfabcde: String = 'F74B326FE2CE8F5BA151B85B16E67B28FE71F131';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_5_160 = class(THashLibAlgorithmTestCase)

  private

    FHaval_5_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '255158CFC1EED1A7BE7C55DDD64D9790415B933B';
    FExpectedHashOfDefaultData
      : String = 'A9AB9AB152BB4413B717228C3A65E75644542A35';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'EF034569FB10312F89F3FC09DDD9AA5C783A7E21';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'A0FFFE2DE177281E64C5D0A9DC81BFFDF14F6031';
    FExpectedHashOfOnetoNine
      : String = '11F592B3A1A1A9C0F9C638C33B69E442D06C1D99';
    FExpectedHashOfabcde: String = '53734616DD6761E2A1D2BD520035287972625385';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_3_192 = class(THashLibAlgorithmTestCase)

  private

    FHaval_3_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E';
    FExpectedHashOfDefaultData
      : String = '4235822851EB1B63D6B1DB56CF18EBD28E0BC2327416D5D1';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'AE216E5FA60AE76305DA19EE908FA0531FFE52BCC6A2AB5F';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '3E72C9200EAA6ED8D2EF60B8773BAF147A94E98A1FF4E70B';
    FExpectedHashOfOnetoNine
      : String = '6B92F078E73AF2E0F9F049FAA5016D32173A3D62D2F08554';
    FExpectedHashOfabcde
      : String = '4A106D88931B60DF1BA352782141C473E79019022D65D7A5';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_4_192 = class(THashLibAlgorithmTestCase)

  private

    FHaval_4_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA';
    FExpectedHashOfDefaultData
      : String = '54D4FD0DE4228D55F826B627A128A765378B1DC1F8E6CD75';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'F5C16DFD598655201E6C636B363484FFAED4CCA27F3366A1';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '8AB3C2ED5E17CC15EE9D0740185BFFC53C054BC71B9A44AA';
    FExpectedHashOfOnetoNine
      : String = 'A5C285EAD0FF2F47C15C27B991C4A3A5007BA57137B18D07';
    FExpectedHashOfabcde
      : String = '88A58D9011CA363A3F3CD113FFEAA44870C07CC14E94FB1B';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_5_192 = class(THashLibAlgorithmTestCase)

  private

    FHaval_5_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85';
    FExpectedHashOfDefaultData
      : String = 'ED197F026B20DB6362CBC62BDD28E0B34F1E287966D84E3B';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'C28A804383403F608CB4A6473BCAF744CF25E62AF28C5934';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'AB2C407C403A82EEADF2A0B3F4B66B34A12322159E7A95B6';
    FExpectedHashOfOnetoNine
      : String = 'EC32312AA79775539675C9BA83D079FFC7EA498FA6173A46';
    FExpectedHashOfabcde
      : String = 'CDDF16E273A09E9E2F1D7D4761C2D35E1DD6EE327F1F5AFD';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_3_224 = class(THashLibAlgorithmTestCase)

  private

    FHaval_3_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D';
    FExpectedHashOfDefaultData
      : String = '12B7BFA1D36D0163E876A1474EB33CF5BC24C1BBBB181F28ACEE8D36';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '64F21A46C5B17F4AAD8C28F970428BAA00C4096132369A7E5C0B2F67';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '2C403CCE41533900919919CA9B8A637AEC0A1E1F7FA154F978592B6B';
    FExpectedHashOfOnetoNine
      : String = '28E8CC65356B43ACBED4DD70F11D0827F17C4442D323AAA0A0DE285F';
    FExpectedHashOfabcde
      : String = '177DA8770D5BF50E1B5D82DD60DF2635102D490D86F876E70F7A4080';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_4_224 = class(THashLibAlgorithmTestCase)

  private

    FHaval_4_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E';
    FExpectedHashOfDefaultData
      : String = 'DA7AB9D08D42C1819C04C7064891DB700DD05C960C3192CB615758B0';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '462C126C107ADA83089EB66168831EB6804BA6062EC8D049B9B47D2B';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '334328027BA2D8F218F8BF374853252D3150FA774D0CBD6F674AEFE0';
    FExpectedHashOfOnetoNine
      : String = '9A08D0CF1D52BB1AC22F6421CFB902E700C4C496B3E990F4606F577D';
    FExpectedHashOfabcde
      : String = '3EEF5DC9C3B3DE0F142DB08B89C21A1FDB1C64D7B169425DBA161190';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_5_224 = class(THashLibAlgorithmTestCase)

  private

    FHaval_5_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E';
    FExpectedHashOfDefaultData
      : String = 'D5FEA825ED7B8CBF23938425BAFDBEE9AD127A685EFCA4559BD54892';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '1DD7A2CF3F32F5C447F50D5A3F6B9C421B243E310C3C292581F95447';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '12B6415C63F4BBA34F0ADD23EEB74AC7EE8A07420D652BF619B9E9D1';
    FExpectedHashOfOnetoNine
      : String = '2EAADFB8007D9A4D8D7F21182C2913D569F801B44D0920D4CE8A01F0';
    FExpectedHashOfabcde
      : String = 'D8CBE8D06DC58095EC0E69F1C1A4D4A90893AAE80401779CEB6646A9';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_3_256 = class(THashLibAlgorithmTestCase)

  private

    FHaval_3_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17';
    FExpectedHashOfDefaultData
      : String =
      '9AA25FF9D7559F108E01014C27EBEEA34E8D82BD1A6105D28A53791B74C4C024';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'A587C118D2A575F91A7D3986F0893A32F8DBE13218D4B3CDB93DD0B7566E5003';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '7E24B475617096B102F0F64572E297144B35683476D1768CB35C0E0A43A6BF8F';
    FExpectedHashOfOnetoNine
      : String =
      '63E8D0AEEC87738F1E820294CBDF7961CD2246B3620B4BAC81BE0B9827D612C7';
    FExpectedHashOfabcde
      : String =
      '3913AB70F6219EEFE10B202DE5991EFDBC4A808203BD60BBFBFC043383AE8F90';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_4_256 = class(THashLibAlgorithmTestCase)

  private

    FHaval_4_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B';
    FExpectedHashOfDefaultData
      : String =
      'B5E97F406CBD4C36CC549072713E733EE31A5F9F23DD6C5982D3A239A9B38434';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'ED5D88C730ED3EB103DDE96AD42DA60825A9B8B0D8BD2ED580EBF92B851B12E7';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      'FD0122B375A581D3F06DB6EB992F9A3F46657091E427BB8BD247D835CC086437';
    FExpectedHashOfOnetoNine
      : String =
      'DDC95DF473DD169456484BEB4B04EDCA83A5572D9D7ECCD00092365AE4EF8D79';
    FExpectedHashOfabcde
      : String =
      '8F9B46785E52C6C48A0178EDC66D3C23C220D15E52C3C8A13E1CD45D21369193';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestHaval_5_256 = class(THashLibAlgorithmTestCase)

  private

    FHaval_5_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330';
    FExpectedHashOfDefaultData
      : String =
      'E5061D6F4F8645262C5C923F8E607CD77D69CE772E3DE559132B460309BFB516';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '267B5C9F0A093726E47541C8F1DEADD400AD9AEE0145A59FBD5A18BA2877101E';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      'C702F985817A2596D7E0BB073D71DFEF72D77BD45599DD4F7E5D83A8EAF7268B';
    FExpectedHashOfOnetoNine
      : String =
      '77FD61460DB5F89DEFC9A9296FAB68A1730EA6C9C0037A9793DAC8492C0A953C';
    FExpectedHashOfabcde
      : String =
      'C464C9A669D5B43E4C34808114DCE4ECC732D1B71407E7F05468D0B15BFF7E30';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestMD2 = class(THashLibAlgorithmTestCase)

  private

    FMD2: IHash;

  const
    FExpectedHashOfEmptyData: String = '8350E5A3E24C153DF2275C9F80692773';
    FExpectedHashOfDefaultData: String = 'DFBE28FF5A3C23CAA85BE5848F16524E';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '03D7546FEADF29A91CEB40290A27E081';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'C5F4625462CD5CF7723C19E8566F6790';
    FExpectedHashOfOnetoNine: String = '12BD4EFDD922B5C8C7B773F26EF4E35F';
    FExpectedHashOfabcde: String = 'DFF9959487649F5C7AF5D0680A9A5D22';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestMD4 = class(THashLibAlgorithmTestCase)

  private

    FMD4: IHash;

  const
    FExpectedHashOfEmptyData: String = '31D6CFE0D16AE931B73C59D7E0C089C0';
    FExpectedHashOfDefaultData: String = 'A77EAB8C3432FD9DD1B87C3C5C2E9C3C';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '7E30F4DA95992DBA450E345641DE5CEC';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'BF21F9EC05E480EEDB12AF20181713E3';
    FExpectedHashOfOnetoNine: String = '2AE523785D0CAF4D2FB557C12016185C';
    FExpectedHashOfabcde: String = '9803F4A34E8EB14F96ADBA49064A0C41';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestMD5 = class(THashLibAlgorithmTestCase)

  private

    FMD5: IHash;

  const
    FExpectedHashOfEmptyData: String = 'D41D8CD98F00B204E9800998ECF8427E';
    FExpectedHashOfDefaultData: String = '462EC1E50C8F2D5C387682E98F9BC842';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '696D0706C43816B551D874B9B3E4B7E6';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '09F705F43799213192622CCA6DF68941';
    FExpectedHashOfOnetoNine: String = '25F9E794323B453885F5181F1B624D0B';
    FExpectedHashOfabcde: String = 'AB56B4D92B40713ACC5AF89985D4B786';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestPanama = class(THashLibAlgorithmTestCase)

  private

    FPanama: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'AA0CC954D757D7AC7779CA3342334CA471ABD47D5952AC91ED837ECD5B16922B';
    FExpectedHashOfDefaultData
      : String =
      '69A05A5A5DDB32F5589257458BBDD059FB30C4486C052D81029DDB2864E90813';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '93226A060B4A82D1D9FBEE6B78424F8E3E871BE7DA77A9D17D5C78D5F415E631';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '3C15C9B7CDC77470BC02CA96711B66FAA976AC2044F6F177ABCA93B1442EA376';
    FExpectedHashOfOnetoNine
      : String =
      '3C83D2C9109DE4D1FA64833683A7C280591A7CFD8516769EA879E56A4AD39B99';
    FExpectedHashOfabcde
      : String =
      'B064E5476A3F511105B75305FC2EC31578A6B200FB5084CF937C179F1C52A891';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRadioGatun32 = class(THashLibAlgorithmTestCase)

  private

    FRadioGatun32: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'F30028B54AFAB6B3E55355D277711109A19BEDA7091067E9A492FB5ED9F20117';
    FExpectedHashOfDefaultData
      : String =
      '17B20CF19B3FC84FD2FFE084F07D4CD4DBBC50E41048D8259EB963B0A7B9C784';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'CD48D590665EA2C066A0C26E2620D567C75090DE38045B88C53BFAE685D67886';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '72EB7D36180C1B1BBF88E062FEC7419DBB4849892623D332821C1B0D71D6D513';
    FExpectedHashOfOnetoNine
      : String =
      'D77629174F56D8451F73CBE80EC7A20EF2DD65C46A1480CD004CBAA96F3FA1FD';
    FExpectedHashOfabcde
      : String =
      'A593059B12513A1BD88A2D433F07B239BC14743AF0FF7294837B5DF756BF9C7A';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRadioGatun64 = class(THashLibAlgorithmTestCase)

  private

    FRadioGatun64: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '64A9A7FA139905B57BDAB35D33AA216370D5EAE13E77BFCDD85513408311A584';
    FExpectedHashOfDefaultData
      : String =
      '43B3208CE2E6B23D985087A84BD583F713A9002280BF2785B1EE569B12C15054';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'B9CBBB9FE06144CF5E369BDBBCB2C76EBBE8904061C356BA9A06FE2D96E4037F';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      'FA280F80C1323C32AACC7F1CAB3808FE2BB8880F901AE6F03BD14D6D1884B267';
    FExpectedHashOfOnetoNine
      : String =
      '76A565017A42B258F5C8C9D2D9FD4C7347947A659ED142FF61C1BEA592F103C5';
    FExpectedHashOfabcde
      : String =
      '36B4DD23A97424844662E882AD1DA1DBAD8CB435A57F380455393C9FF9DE9D37';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRIPEMD = class(THashLibAlgorithmTestCase)

  private

    FRIPEMD: IHash;

  const
    FExpectedHashOfEmptyData: String = '9F73AA9B372A9DACFB86A6108852E2D9';
    FExpectedHashOfDefaultData: String = 'B3F629A9786744AA105A2C150869C236';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'B06D09CE5452ADEEADF468E00DAC5C8B';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '219ACFCF07BDB775FBA73DACE1E97E08';
    FExpectedHashOfOnetoNine: String = 'C905B44C6429AD0A1934550037D4816F';
    FExpectedHashOfabcde: String = '68D2362617E85CF1BF7381DF14045DBB';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRIPEMD128 = class(THashLibAlgorithmTestCase)

  private

    FRIPEMD128: IHash;

  const
    FExpectedHashOfEmptyData: String = 'CDF26213A150DC3ECB610F18F6B38B46';
    FExpectedHashOfDefaultData: String = '75891B00B2874EDCAF7002CA98264193';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'E93930A64EF6807C4D80EF30DF86AFA7';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'BA844D13A1215E20634A49D5599197EF';
    FExpectedHashOfOnetoNine: String = '1886DB8ACDCBFEAB1E7EE3780400536F';
    FExpectedHashOfabcde: String = 'A0A954BE2A779BFB2129B72110C5782D';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRIPEMD160 = class(THashLibAlgorithmTestCase)

  private

    FRIPEMD160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '9C1185A5C5E9FC54612808977EE8F548B2258D31';
    FExpectedHashOfDefaultData
      : String = '0B8EAC9A2EA1E267750CE639D83A84B92631462B';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '4C373970BDB829BE3B6E0B2D9F510E9C35C9B583';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '76D728D9BF39ED42E0C451A9526E3F0D929F067D';
    FExpectedHashOfOnetoNine
      : String = 'D3D0379126C1E5E0BA70AD6E5E53FF6AEAB9F4FA';
    FExpectedHashOfabcde: String = '973398B6E6C6CFA6B5E6A5173F195CE3274BF828';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRIPEMD256 = class(THashLibAlgorithmTestCase)

  private

    FRIPEMD256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '02BA4C4E5F8ECD1877FC52D64D30E37A2D9774FB1E5D026380AE0168E3C5522D';
    FExpectedHashOfDefaultData
      : String =
      '95EF1FFAB0EF6229F58CAE347426ADE3C412BCEB1057DAED0062BBDEE4BEACC6';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'F1149704222B7ABA1F9C14B0E9A67909C53605E07614CF8C47CB357083EA3A6B';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      'D59B820A708FA31C39BD33BA88CB9A25516A3BA2BA99A74223FCE0EC0F9BFB1B';
    FExpectedHashOfOnetoNine
      : String =
      '6BE43FF65DD40EA4F2FF4AD58A7C1ACC7C8019137698945B16149EB95DF244B7';
    FExpectedHashOfabcde
      : String =
      '81D8B58A3110A9139B4DDECCB031409E8AF023067CF4C6F0B701DAB9ECC0EB4E';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestRIPEMD320 = class(THashLibAlgorithmTestCase)

  private

    FRIPEMD320: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '22D65D5661536CDC75C1FDF5C6DE7B41B9F27325EBC61E8557177D705A0EC880151C3A32A00899B8';
    FExpectedHashOfDefaultData
      : String =
      '004A1899CCA02BFD4055129304D55F364E35F033BB74B784AFC93F7268291D8AF84F2C64C5CCACD0';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '248D14ED08F0F49D175F4DC487A64B81F06D78077D1CF975BBE5D47627995990EBE45E6B7EDF9362';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '4D3DFCCB43E5A60611A850C2141086CB16752505BA12E1B7953EA8859CB1E1DF3A698562A46DB41C';
    FExpectedHashOfOnetoNine
      : String =
      '7E36771775A8D279475D4FD76B0C8E412B6AD085A0002475A148923CCFA5D71492E12FA88EEAF1A9';
    FExpectedHashOfabcde
      : String =
      'A94DC1BC825DB64E97718305CE36BFEF32CC5410A630999678BCD89CC38C424269012EC8C5A95830';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA0 = class(THashLibAlgorithmTestCase)

  private

    FSHA0: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'F96CEA198AD1DD5617AC084A3D92C6107708C0EF';
    FExpectedHashOfDefaultData
      : String = 'C9CBBE593DE122CA36B13CC37FE2CA8D5606FEED';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'CDA87167A558311B9154F372F21A453030BBE16A';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'EAA73E85DCAC5BAD0A0E71C0695F901FC32DB38A';
    FExpectedHashOfOnetoNine
      : String = 'F0360779D2AF6615F306BB534223CF762A92E988';
    FExpectedHashOfabcde: String = 'D624E34951BB800F0ACAE773001DF8CFFE781BA8';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA1 = class(THashLibAlgorithmTestCase)

  private

    FSHA1: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709';
    FExpectedHashOfDefaultData
      : String = 'C8389876E94C043C47BA4BFF3D359884071DC310';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'E70699720F4222E3A4A4474F14F13CBC3316D9B2';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'CD409025AA5F34ABDC660856463155B23C89B16A';
    FExpectedHashOfOnetoNine
      : String = 'F7C3BC1D808E04732ADF679965CCC34CA7AE3441';
    FExpectedHashOfabcde: String = '03DE6C570BFE24BFC328CCD7CA46B76EADAF4334';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_224 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F';
    FExpectedHashOfDefaultData
      : String = 'DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '86855E59D8B09A3C7632D4E176C4B65C549255F417FEF9EEF2D4167D';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1';
    FExpectedHashOfOnetoNine
      : String = '9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521';
    FExpectedHashOfabcde
      : String = 'BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_256 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
    FExpectedHashOfDefaultData
      : String =
      'BCF45544CB98DDAB731927F8760F81821489ED04C0792A4D254134887BEA9E38';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'BC05A7D3B13A4A67445C62389564D35B18F33A0C6408EC8DA0CB2506AE6E2D14';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '92678A1C746AAEAA1D3F0C9DAC4BCA73801D278B51C1F6861D49C9A2C1175687';
    FExpectedHashOfOnetoNine
      : String =
      '15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225';
    FExpectedHashOfabcde
      : String =
      '36BBE50ED96841D10443BCB670D6554F0A34B761BE67EC9C4A8AD2C0C44CA42C';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_384 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_384: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B';
    FExpectedHashOfDefaultData
      : String =
      '05D165ADA4A6F9F550CB6F9A0E00401E628B302FA5D7F3824361768758421F83102AC611B2710F5168579CFB11942869';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '162295D136DB47205EDF45BF8687E5599DFA80C6AE79D83C03E729C48D373E19638ADD5B5D603558234DF755404CCF9E';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '3D6DCED731DAF3599CC0971646C1A8B8CCC61650722F111A9EB26CE7B65189EB220EACB09152D9A09065099FE6C1FDC9';
    FExpectedHashOfOnetoNine
      : String =
      'EB455D56D2C1A69DE64E832011F3393D45F3FA31D6842F21AF92D2FE469C499DA5E3179847334A18479C8D1DEDEA1BE3';
    FExpectedHashOfabcde
      : String =
      '4C525CBEAC729EAF4B4665815BC5DB0C84FE6300068A727CF74E2813521565ABC0EC57A37EE4D8BE89D097C0D2AD52F0';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_512 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_512: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E';
    FExpectedHashOfDefaultData
      : String =
      '0A5DA12B113EBD3DEA4C51FD10AFECF1E2A8EE6C3848A0DD4407141ADDA04375068D85A1EEF980FAFF68DC3BF5B1B3FBA31344178042197B5180BD95530D61AC';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'FB795F2A85271149E6A6E2668AAF54DB5946DC669C1C8432BED856AEC9A1A461B5FC13FE8AE0861E6A8F53D711FDDF76AC60A5CCC8BA334325FDB9472A7A71F4';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      'DEDFCEAD40225068527D0E53B7C892226E188891D939E21A0777A40EA2E29D7233638C178C879F26088A502A887674C01DF61EAF1635D707D114097ED1D0D762';
    FExpectedHashOfOnetoNine
      : String =
      'D9E6762DD1C8EAF6D61B3C6192FC408D4D6D5F1176D0C29169BC24E71C3F274AD27FCD5811B313D681F7E55EC02D73D499C95455B6B5BB503ACF574FBA8FFE85';
    FExpectedHashOfabcde
      : String =
      '878AE65A92E86CAC011A570D4C30A7EAEC442B85CE8ECA0C2952B5E3CC0628C2E79D889AD4D5C7C626986D452DD86374B6FFAA7CD8B67665BEF2289A5C70B0A1';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_512_224 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_512_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4';
    FExpectedHashOfDefaultData
      : String = '7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'B932866547894977F6E4C61D137FFC2508C639BA6786F45AC64731C8';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4';
    FExpectedHashOfOnetoNine
      : String = 'F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314';
    FExpectedHashOfabcde
      : String = '880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA2_512_256 = class(THashLibAlgorithmTestCase)

  private

    FSHA2_512_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A';
    FExpectedHashOfDefaultData
      : String =
      'E1792BAAAEBFC58E213D0BA628BF2FF22CBA10526075702F7C1727B76BEB107B';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '5EF407B913662BE3D98F5DA20D55C2A45D3F3E4FF771B2C2A482E35F6A757E71';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '1467239C9D47E1962905D03D7006170A04D05E4508BB47E30AD9481FBDA975FF';
    FExpectedHashOfOnetoNine
      : String =
      '1877345237853A31AD79E14C1FCB0DDCD3DF9973B61AF7F906E4B4D052CC9416';
    FExpectedHashOfabcde
      : String =
      'DE8322B46E78B67D4431997070703E9764E03A1237B896FD8B379ED4576E8363';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA3_224 = class(THashLibAlgorithmTestCase)

  private

    FSHA3_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7';
    FExpectedHashOfDefaultData
      : String = '1D2BDFB95B0203C2BB7C739D813D69521EC7A3047E3FCA15CD305C95';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '38FABCD5E29DE7AD7429BD9124F804FFD340D7B9F77A83DC25EC53B8';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'DA17722BA1E4BD728A83015A83430A67577F283A0EFCB457C327A980';
    FExpectedHashOfOnetoNine
      : String = '5795C3D628FD638C9835A4C79A55809F265068C88729A1A3FCDF8522';
    FExpectedHashOfabcde
      : String = '6ACFAAB70AFD8439CEA3616B41088BD81C939B272548F6409CF30E57';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA3_256 = class(THashLibAlgorithmTestCase)

  private

    FSHA3_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A';
    FExpectedHashOfDefaultData
      : String =
      'C334674D808EBB8B7C2926F043D1CAE78D168A05B70B9210C9167EA6DC300CE2';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'B8EC49AF4DE71CB0561A9F0DF7B156CC7784AC044F12B65048CE6DBB27A57E66';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '1019B70021A038345192F00D02E33FA4AF8949E80AD592C4671A438DCCBCFBDF';
    FExpectedHashOfOnetoNine
      : String =
      '87CD084D190E436F147322B90E7384F6A8E0676C99D21EF519EA718E51D45F9C';
    FExpectedHashOfabcde
      : String =
      'D716EC61E18904A8F58679B71CB065D4D5DB72E0E0C3F155A4FEFF7ADD0E58EB';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA3_384 = class(THashLibAlgorithmTestCase)

  private

    FSHA3_384: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004';
    FExpectedHashOfDefaultData
      : String =
      '87DD2935CD0DDEFFB8694E70ED1D33EABCEA848BD93A7A7B7227603B7C080A70BCF29FCEED66F456A7FB593EB23F950C';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '802D520828C580A61EE4BFA138BE23708C22DB97F94913AF5897E3C9C12BA6C4EC33BFEB79691D2F302315B27674EA40';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '52A4A926B60AA9F6B7DB1C8F5344A097540A8E2115164BF75734907E88C2BC1F7DD84D0EE8569B9857590A39EB5FF499';
    FExpectedHashOfOnetoNine
      : String =
      '8B90EDE4D095409F1A12492C2520599683A9478DC70B7566D23B3E41ECE8538C6CDE92382A5E38786490375C54672ABF';
    FExpectedHashOfabcde
      : String =
      '348494236B82EDDA7602C78BA67FC3838E427C63C23E2C9D9AA5EA6354218A3C2CA564679ACABF3AC6BF5378047691C4';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSHA3_512 = class(THashLibAlgorithmTestCase)

  private

    FSHA3_512: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26';
    FExpectedHashOfDefaultData
      : String =
      'FAA213B928B942C521FD2A4B5F918C9AB6479A1DD122B9485440E56E729976D57C5E7C62F65D8453DCAAADA6B79743DB939F22773FD44C9ECD54B4B7FAFDAE33';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'ADD449377F25EC360F87B04AE6334D5D7CA90EAF3568D4EBDA3A977B820271952D7D93A7804E29B9791DC19FF7B523E6CCABED180B0B035CCDDA38A7E92DC7E0';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '439C673B33F0F6D9273124782611EA96F1BB62F90672551310C1230ADAAD0D40F63C6D2B17DAFECEFD9CE8848576001D9D68FAD1B9E7DDC146F00CEBE5AFED27';
    FExpectedHashOfOnetoNine
      : String =
      'E1E44D20556E97A180B6DD3ED7AE5C465CAFD553FA8747DCA038FB95635B77A37318F7DDF7AEC1F6C3C14BB160BA2497007DECF38DD361CAB199E3B8C8FE1F5C';
    FExpectedHashOfabcde
      : String =
      '1D7C3AA6EE17DA5F4AEB78BE968AA38476DBEE54842E1AE2856F4C9A5CD04D45DC75C2902182B07C130ED582D476995B502B8777CCF69F60574471600386639B';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestShake_128 = class(THashLibAlgorithmTestCase)

  private

    FShake_128: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF263CB1EEA988004B93103CFB0AEEFD2A686E01FA4A58E8A3639CA8A1E3F9AE57E2';
    FExpectedHashOfDefaultData
      : String =
      '10F69AD42A1BDE254004CD13B5176D6DAAD5E92198CD4715AA923017FFC809C4B3AA88E2CCBF4ABA98A0E9B7B49FC1A39ABAEC03F020CE4A72601B80E158F515';
    FExpectedHashOfOnetoNine
      : String =
      '1ACA6B9E651B5F20079A305CA8F86D39B9451C4C32873F95F8B315834BD5F272C3044114D6F3E2C2F5F4EAA1825FC80F8CE10CF3E7DE557408811F54D1AF85FD';
    FExpectedHashOfabcde
      : String =
      '907C1B3F41470218D0DFD8FEDDDA93C1074F0D608F08980E4F17BE0853D0A684324815152908BE3DFB69D8A01EA8DD41A3413CD1F635F449D9875DE319469648';

    FVeryLongShakeOfEmptyString
      : String =
      '7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF263CB1EEA988004B93103CFB0AEEFD2A686E01FA4A58E8A3639CA8A1E3F9'
      + 'AE57E235B8CC873C23DC62B8D260169AFA2F75AB916A58D974918835D25E6A435085B2BADFD6DFAAC359A5EFBB7BCC4B59D538DF9A04302E10C8BC1CBF1A0B3A5120EA17CDA7CFA'
      + 'D765F5623474D368CCCA8AF0007CD9F5E4C849F167A580B14AABDEFAEE7EEF47CB0FCA9767BE1FDA69419DFB927E9DF07348B196691ABAEB580B32D'
      + 'EF58538B8D23F87732EA63B02B4FA0F4873360E2841928CD60DD4CEE8CC0D4C922A96188D032675C8AC850933C7AFF1533B94C834ADBB69C6115BAD4692D8619F90B0CDF8A7B9'
      + 'C264029AC185B70B83F2801F2F4B3F70C593EA3AEEB613A7F1B1DE33FD75081F592305F2E4526EDC09631B10958F464D889F31BA010250FDA7F1368EC2967FC84EF2AE9AFF268E0B1700AFFC6820B523A3D917135F2DFF2EE06BFE72B3124721D'
      + '4A26C04E53A75E30E73A7A9C4A95D91C55D495E9F51DD0B5E9D83C6D5E8CE803AA62B8D654DB53D09B8DCFF273CDFEB573FAD8BCD45578BEC2E770D'
      + '01EFDE86E721A3F7C6CCE275DABE6E2143F1AF18DA7EFDDC4C7B70B5E345DB93CC936BEA323491CCB38A388F546A9FF00DD4E1300B9B2153D2041D205B443E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F4CFFDA2CF990051634A4B1EDF6114F'
      + 'B49083C1FA3B302EE097F051266BE69DC716FDEEF91B0D4AB2DE525550BF80DC8A684BC3B5A4D46B7EFAE7AFDC6292988DC9ACAE03F8634486C1ABE2781AAE4C02F3460D2CD4E6A'
      + '463A2BA9562EE623CF0E9F82AB4D0B5C9D040A269366479DFF0038ABFAF2E0FF21F36968972E3F104DDCBE1EB831A87C213162E29B34ADFA564D121E9F6E7729F4203FC5C6C22FA7A7350AFDDB6209'
      + '23A4A129B8ACB19EA10F818C30E3B5B1C571FA79E57EE304388316A02FCD93A0D8EE02BB85701EE4FF097534B502C1B12FBB95C8CCB2F548921D99CC7C9FE17AC991B675E631144423EEF7A5869168DA63D1F4C21F650C02923BFD396CA6A5DB541068624CBC5FFE208C0D1A74E1A29618D0BB60036F524'
      + '9ABFA88898E393718D6EFAB05BB41279EFCD4C5A0CC837CCFC22BE4F725C081F6AA090749DBA7077BAE8D41AF3FEC5A6EE1B8ADCD25E72DE36434584EF567C643D344294E8B2086B87F69'
      + 'C3BDC0D5969857082987CA1C63B7182E86898FB9B8039E75EDA219E289331610369271867B145B2908293963CD677C9A1AE6CEB28289B254CDEB76B12F33CE5CF3743131BFB550F019'
      + '7BFE16AFF92367227ADC5074FE3DC0D8D116253980A38636BC9D29F799BBB2D76A0A5F138B8C73BA484D6588764E331D70C378C0641F2D9';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestVeryLongShakeOfEmptyString;

  end;

  TTestShake_256 = class(THashLibAlgorithmTestCase)

  private

    FShake_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762FD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE';
    FExpectedHashOfDefaultData
      : String =
      '922279516284A34F384ADA776D3606FBEC97875E716E6EA0FFCF9372AAB696BEEFAB7C34CC5D1C926CEAD58FD4D6DB597C8620782541D7D7B47498FE4AF4B7A4';
    FExpectedHashOfOnetoNine
      : String =
      '24347B9C4B6DA2FC9CDE08C87F33EDD2E603C8DCD6840E6B3920F62B1DD69D7BC4655A9E6F0EE6255940380DCD1488DBCA3E796AE58A2234CC31CD61DFD1EB56';
    FExpectedHashOfabcde
      : String =
      '98AD79D7ED29F585AD1AFFBC2BB5B5F244917F97CEA8B5424FDC6F7377A22042FD410C95237B587A0A13B10062034E1E3BF6B5766291CCC1F4C44229371991ED';

    FVeryLongShakeOfEmptyString
      : String =
      '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762FD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE141E96616FB13957692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853349EC755'
      + '46F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86F3D122109E3B1FDD943B6AEC468A2D621A7C06C6A957C62B54DAFC3BE87567D677231395F6147293B68CEAB7'
      + 'A9E0C58D864E8EFDE4E1B9A46CBE854713672F5CAAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8FCF3F3CB53FB8E9EB2EA203BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F5A1AAA96D313EACC890936C173CDCD0FA'
      + 'B882C45755FEB3AED96D477FF96390BF9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DCF722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11F0477DE055A81A9EDA57A4A2CFB0C83929D31091'
      + '2F729EC6CFA36C6AC6A75837143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB78F3AC45F8C4AC5671D85735CDDDB09D2B1E34A1FC066FF4A162CB263D6541274AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341'
      + 'EF274BDAB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A5B8D548A728C9444ECB879ADC19DE0C1B8587DE3E73E15D3CE2DB7C9FA7B58FFC0E87251773FAF3E8F3'
      + 'E3CF1D4DFA723AFD4DA9097CB3C866ACBE' +
      'FAB2C4E85E1918990FF93E0656B5F75B08729C60E6A9D7352B9EFD2E33E3D1BA6E6D89EDFA671266ECE6BE7BB5AC948B737E41590ABE138CE1869C08680162F08863D174E77E07A9DDB33B57DE04C443A5BD77C42036871AAE7893362B'
      + '27015B84B4139F0E313579B4EF5F6B6426563D7195B8C5B84736B14266160342C4093F8ABEA48371BA94CC06DCB6B8A8E7BCE6354F9BABC949A5F18F8C9F0AAEFE0B8BECAD386F078CA41CACF2E3D17F4'
      + 'EC21FED0E3B682435AD5B665C25D7B61B379E86824C2B22D5A54835F8B04D4C0B29667BAEB0C3258809EE698DBC03536A1C936C811F6E6F69210F5632080064923FDF9CF405301E45A3F96E3F57C55C4E0B538EFE8942F6B601AC49EA635F70'
      + 'E4BA39E5FCE513CFB672945BB92E17F7D222EAB2AA29BE89FC3FF24BC6B6D7A3D307CE7B1731E7DF59690D0530D7F2F5BB9ED37D180169A6C1BB022252AB8CC6860E3CF1F1414C90A19350B526E3741E500717769CDD09D268CC3F88B5D521C70AA8BBE631FBF08905A0A833D2005830717'
      + 'ADBA3233DD591BC505C7B13A9D5672AD4BE10C744AC33D9E92A23BDEE6E14D470EE7DC142FE4EFF4182A49BEEEC8E4';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestVeryLongShakeOfEmptyString;

  end;

type

  TTestSnefru_8_128 = class(THashLibAlgorithmTestCase)

  private

    FSnefru_8_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '8617F366566A011837F4FB4BA5BEDEA2';
    FExpectedHashOfDefaultData: String = '1EA32485C121D07D1BD22FC4EDCF554F';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '296DEC851C9F6A6C9E1FD42679CE3FD2';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'B7D06604FCA943939525BA82BA69706E';
    FExpectedHashOfOnetoNine: String = '486D27B1F5F4A20DEE14CC466EDA9069';
    FExpectedHashOfabcde: String = 'ADD78FA0BEA8F6283FE5D011BE6BCA3B';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestSnefru_8_256 = class(THashLibAlgorithmTestCase)

  private

    FSnefru_8_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '8617F366566A011837F4FB4BA5BEDEA2B892F3ED8B894023D16AE344B2BE5881';
    FExpectedHashOfDefaultData
      : String =
      '230826DA59215F22AF36663491AECC4872F663722A5A7932428CB8196F7AF78D';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'EEE63DC493FCDAA2F826FFF81DB4BAC53CBBFD933BEA3B65C8BEBB576D921623';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '7E33D94C5A09B2E5F800417128BCF3EF2EDCB971884789A35AE4AA7F13A18147';
    FExpectedHashOfOnetoNine
      : String =
      '1C7DEDC33125AF7517970B97B635777FFBA8905D7A0B359776E3E683B115F992';
    FExpectedHashOfabcde
      : String =
      '8D2891FC6020D7DC93F7561C0CFDDE26426192B3E364A1F52B634482009DC8C8';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_3_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger_3_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '3293AC630C13F0245F92BBB1766E1616';
    FExpectedHashOfDefaultData: String = 'C76C85CE853F6E9858B507DA64E33DA2';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '331B89BDEC8B418091A883C139B3F858';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '0FA849F65841F2E621E2C882BE7CF80F';
    FExpectedHashOfOnetoNine: String = '0672665140A491BB35040AA9943D769A';
    FExpectedHashOfabcde: String = 'BFD4041233531F1EF1E9A66D7A0CEF76';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_4_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger_4_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '24CC78A7F6FF3546E7984E59695CA13D';
    FExpectedHashOfDefaultData: String = '42CAAEB3A7218E379A78E4F1F7FBADA4';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '5365F31B5077249CA8C0C11FB29E06C1';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '856B697CEB606B1DF42B475D0C5587B5';
    FExpectedHashOfOnetoNine: String = 'D9902D13011BD217DE965A3BA709F5CE';
    FExpectedHashOfabcde: String = '7FD0E2FAEC50261EF48D3B87C554EE73';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_5_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger_5_128: IHash;

  const
    FExpectedHashOfEmptyData: String = 'E765EBE4C351724A1B99F96F2D7E62C9';
    FExpectedHashOfDefaultData: String = 'D6B8DCEA252160A4CBBF6A57DA9ABA78';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '67B3B43D5CE62BE8B54805E315576F06';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '49D450EC293D5565CE82284FA52FDC51';
    FExpectedHashOfOnetoNine: String = 'BCCCB6421B3EC291A062A33DFF21BA76';
    FExpectedHashOfabcde: String = '1AB49D19F3C93B6FF4AB536951E5A6D0';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_3_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger_3_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '3293AC630C13F0245F92BBB1766E16167A4E5849';
    FExpectedHashOfDefaultData
      : String = 'C76C85CE853F6E9858B507DA64E33DA27DE49F86';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '6C256489CD5E62C9B9F236523B030A56CCDF5A8C';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '45AF6513756EB15B9504CE8212F3D43AE739E470';
    FExpectedHashOfOnetoNine
      : String = '0672665140A491BB35040AA9943D769A47BE83FE';
    FExpectedHashOfabcde: String = 'BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE75';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_4_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger_4_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '24CC78A7F6FF3546E7984E59695CA13D804E0B68';
    FExpectedHashOfDefaultData
      : String = '42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'FE4F2273571AD900BB6A2935AD9E4E53DE98B24B';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'E8E8B8EF52CF7866A4E0AEAE7DE79878D5564997';
    FExpectedHashOfOnetoNine
      : String = 'D9902D13011BD217DE965A3BA709F5CE7E75ED2C';
    FExpectedHashOfabcde: String = '7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_5_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger_5_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'E765EBE4C351724A1B99F96F2D7E62C9AACBE64C';
    FExpectedHashOfDefaultData
      : String = 'D6B8DCEA252160A4CBBF6A57DA9ABA78E4564864';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '5ACE8DB66A68836ADAC0BD563D43C01E82181E32';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '5F403B5F7F9A341545F55265698DD77DB8D3D6D4';
    FExpectedHashOfOnetoNine
      : String = 'BCCCB6421B3EC291A062A33DFF21BA764596C58E';
    FExpectedHashOfabcde: String = '1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_3_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger_3_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3';
    FExpectedHashOfDefaultData
      : String = 'C76C85CE853F6E9858B507DA64E33DA27DE49F8601F6A830';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'E46789FA64BFEE51EE17C7D257B6DF892A39FA9A7BC65CF9';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '9B53DDED2647666E9C31CF0F93B3B83E9FF64DF4532F3DDC';
    FExpectedHashOfOnetoNine
      : String = '0672665140A491BB35040AA9943D769A47BE83FEF2126E50';
    FExpectedHashOfabcde
      : String = 'BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE756B36A7D7';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_4_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger_4_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '24CC78A7F6FF3546E7984E59695CA13D804E0B686E255194';
    FExpectedHashOfDefaultData
      : String = '42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6A41827B0';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '31C5440140BD657ECEBA5172E7853E526290060C1A6335D1';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'D1113A9110545D0F3C97BE1451A8FAED205B1F27B3D74560';
    FExpectedHashOfOnetoNine
      : String = 'D9902D13011BD217DE965A3BA709F5CE7E75ED2CB791FEA6';
    FExpectedHashOfabcde
      : String = '7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98F9A0B332';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger_5_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger_5_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'E765EBE4C351724A1B99F96F2D7E62C9AACBE64C63B5BCA2';
    FExpectedHashOfDefaultData
      : String = 'D6B8DCEA252160A4CBBF6A57DA9ABA78E45648645715E3CE';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'C8A09D6DB257C85B99051F3BC410F56C4D92EEBA311005DC';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '8D56E7164C246EAF4708AAEECFE4DD439F5B4396A54049A6';
    FExpectedHashOfOnetoNine
      : String = 'BCCCB6421B3EC291A062A33DFF21BA764596C58E30854A92';
    FExpectedHashOfabcde
      : String = '1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C3471A08F';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_3_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_3_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '4441BE75F6018773C206C22745374B92';
    FExpectedHashOfDefaultData: String = 'DEB1924D290E3D5567792A8171BFC44F';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '9B3B854233FD1AFC80D17179039F6F7B';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '0393C69DD393D9E15C723DFAE88C3059';
    FExpectedHashOfOnetoNine: String = '82FAF69673762B9FD8A0C902BDB395C1';
    FExpectedHashOfabcde: String = 'E1F0DAC9E852ECF1270FB691C35506D4';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_4_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_4_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '6A7201A47AAC2065913811175553489A';
    FExpectedHashOfDefaultData: String = '22EE5BFE174B8C1C23361306C3E8F32C';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '787FFD7B098895A03139CBEBA0FBCCE8';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'A24C1DD76CACA54D3CB2BDDE5E40D84E';
    FExpectedHashOfOnetoNine: String = '75B7D71ACD40FE5B5D3263C1F68F4CF5';
    FExpectedHashOfabcde: String = '9FBB0FBF818C0302890CE373559D2370';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_5_128 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_5_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '61C657CC0C3C147ED90779B36A1E811F';
    FExpectedHashOfDefaultData: String = '7F71F95B346733E7022D4B85BDA9C51E';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'B0D4AAA0A3239A5B242979DBE02C3373';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'F545BB88FBE3E5FB85E6DE063D081B66';
    FExpectedHashOfOnetoNine: String = 'F720446C9BFDC8479D9FA53BC8B9144F';
    FExpectedHashOfabcde: String = '14F45FAC4BE0302E740CCC6FE99D75A6';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_3_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_3_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '4441BE75F6018773C206C22745374B924AA8313F';
    FExpectedHashOfDefaultData
      : String = 'DEB1924D290E3D5567792A8171BFC44F70B5CD13';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '74B33C922DD679DC7144EF9F6BE807A8F1C370FE';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '71028DCDC197492195110EA5CFF6B3E04912FF25';
    FExpectedHashOfOnetoNine
      : String = '82FAF69673762B9FD8A0C902BDB395C12B0CBDDC';
    FExpectedHashOfabcde: String = 'E1F0DAC9E852ECF1270FB691C35506D4BEDB12A0';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_4_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_4_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '6A7201A47AAC2065913811175553489ADD0F8B99';
    FExpectedHashOfDefaultData
      : String = '22EE5BFE174B8C1C23361306C3E8F32C92075577';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '4C7CE724E7021DF3B53FA997C49E07E4DF9EA0F7';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '283A6ED11043AAA947A12843DC5C4B16283BE633';
    FExpectedHashOfOnetoNine
      : String = '75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B';
    FExpectedHashOfabcde: String = '9FBB0FBF818C0302890CE373559D23702D87C69B';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_5_160 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_5_160: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '61C657CC0C3C147ED90779B36A1E811F1D27F406';
    FExpectedHashOfDefaultData
      : String = '7F71F95B346733E7022D4B85BDA9C51E904825F7';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '89CFB85851EA674DF045CDDE4BAC3C3037E01BDE';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'DDEE30DCE9CD2A11C38ADA8AC94FD5BD90EC1BA4';
    FExpectedHashOfOnetoNine
      : String = 'F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED';
    FExpectedHashOfabcde: String = '14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_3_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_3_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '4441BE75F6018773C206C22745374B924AA8313FEF919F41';
    FExpectedHashOfDefaultData
      : String = 'DEB1924D290E3D5567792A8171BFC44F70B5CD13480D6D5C';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '8540FF4EBA4C823EEC5EDC244D83B93381B75CE92F753005';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'C70FA522EACE7D870F914A086BD1D9807A6FDC405C5A09DB';
    FExpectedHashOfOnetoNine
      : String = '82FAF69673762B9FD8A0C902BDB395C12B0CBDDC66957838';
    FExpectedHashOfabcde
      : String = 'E1F0DAC9E852ECF1270FB691C35506D4BEDB12A09D6BF911';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_4_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_4_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '6A7201A47AAC2065913811175553489ADD0F8B99E65A0955';
    FExpectedHashOfDefaultData
      : String = '22EE5BFE174B8C1C23361306C3E8F32C92075577F9115C2A';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '0B3BB091C80889FB2E65FCA6ADCEC87147311F242AEC5519';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '3B182344C171E8843B3D30887274FC7248A7CCD49AA84E77';
    FExpectedHashOfOnetoNine
      : String = '75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B39413ACA';
    FExpectedHashOfabcde
      : String = '9FBB0FBF818C0302890CE373559D23702D87C69B9D1B29D5';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestTiger2_5_192 = class(THashLibAlgorithmTestCase)

  private

    FTiger2_5_192: IHash;

  const
    FExpectedHashOfEmptyData
      : String = '61C657CC0C3C147ED90779B36A1E811F1D27F406E3F37010';
    FExpectedHashOfDefaultData
      : String = '7F71F95B346733E7022D4B85BDA9C51E904825F73AF0E8AE';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = 'C583EDE2D12E49F48BD29642C69D4470016293F47374339F';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = '19AD11BA8D3534C41CAA2A9DAA80958EDCDB0B67FF3BF55D';
    FExpectedHashOfOnetoNine
      : String = 'F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED1440C213';
    FExpectedHashOfabcde
      : String = '14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177B4ADF2A8';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestWhirlPool = class(THashLibAlgorithmTestCase)

  private

    FWhirlPool: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3';
    FExpectedHashOfDefaultData
      : String =
      '9D2BB47D6F6D9F0DBAF08BEF416DE06C98CDF293F3D1AD2422A63A9ADFBD9AA33F888A1C6FE7C16DF33B2BD9FFD8EF160BCF6AB4F21B682DC238A3BE03AB0F12';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'A2CF231E2E01B310A91A7BF92435AE0258997AB969D0B2E09378C0F30C73E4434894A836B3F580683F58FC56DA87C685927AE0FC80D2548A35CD3C7528A83AC1';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '72B3CFC10CC32F9203670984407594B9F2A6C9F1A46C3FF7DF76AD07207758F96CF46C448A7687EBBA5EBC046984B4837320306EB27978A58B8CF447978CADEA';
    FExpectedHashOfOnetoNine
      : String =
      '21D5CB651222C347EA1284C0ACF162000B4D3E34766F0D00312E3480F633088822809B6A54BA7EDFA17E8FCB5713F8912EE3A218DD98D88C38BBF611B1B1ED2B';
    FExpectedHashOfabcde
      : String =
      '5D745E26CCB20FE655D39C9E7F69455758FBAE541CB892B3581E4869244AB35B4FD6078F5D28B1F1A217452A67D9801033D92724A221255A5E377FE9E9E5F0B2';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestBlake2B = class(THashLibAlgorithmTestCase)

  private

    FBlake2B: IHash;
    Fconfig: IBlake2BConfig;
    FInput: TBytes;

  const
    FExpectedHashOfEmptyData
      : String =
      '786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE';

    FExpectedHashOfQuickBrownDog
      : String =
      'A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918';

    // https://docs.python.org/3/library/hashlib.html#tree-mode
    FBlake2BTreeHashingMode
      : String =
      '3AD2A9B37C6070E374C7A8C508FE20CA86B6ED54E286E93A0318E95E881DB5AA';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCheckTestVectors();
    procedure TestCheckKeyedTestVectors();
    procedure TestSplits();
    procedure TestEmpty();
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestQuickBrownDog();
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;
    procedure TestNullKeyVsUnKeyed;
    // https://docs.python.org/3/library/hashlib.html#tree-mode
    procedure TestBlake2BTreeHashingMode;

  end;

type

  TTestBlake2S = class(THashLibAlgorithmTestCase)

  private

    FBlake2S: IHash;
    Fconfig: IBlake2SConfig;
    FInput, FSalt, FPersonalisation, FValue: TBytes;

  const
    FExpectedHashOfEmptyData
      : String =
      '69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9';

    FExpectedHashOfQuickBrownDog
      : String =
      '606BEEEC743CCBEFF6CBCDF5D5302AA855C256C29B88C8ED331EA1A6BF3C8812';

    // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
    FBlake2STreeHashingMode: String = 'C81CD326CA1CA6F40E090A9D9E738892';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCheckTestVectors();
    procedure TestCheckKeyedTestVectors();
    procedure TestSplits();
    procedure TestWithSaltPersonalisation();
    procedure TestWithSaltPersonalisationKey();
    procedure TestEmpty();
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestQuickBrownDog();
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;
    procedure TestNullKeyVsUnKeyed;
    // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
    procedure TestBlake2STreeHashingMode;

  end;

type

  TTestKeccak_224 = class(THashLibAlgorithmTestCase)

  private

    FKeccak_224: IHash;

  const
    FExpectedHashOfEmptyData
      : String = 'F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD';
    FExpectedHashOfDefaultData
      : String = '1BA678212F840E95F076B4E3E75310D4DA4308E04396E07EF1683ACE';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String = '8C500F95CB013CBC16DEB6CB742D470E20404E0A1776647EAAB6E869';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String = 'D6CE783743A36717F893DFF82DE89633F21089AFBE4F26431E269650';
    FExpectedHashOfOnetoNine
      : String = '06471DE6C635A88E7470284B2C2EBF9BD7E5E888CBBD128C21CB8308';
    FExpectedHashOfabcde
      : String = '16F91F7E036DF526340440C34C231862D8F6319772B670EEFD4703FF';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestKeccak_256 = class(THashLibAlgorithmTestCase)

  private

    FKeccak_256: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      'C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470';
    FExpectedHashOfDefaultData
      : String =
      '3FE42FE8CD6DAEF5ED7891846577F56AB35DC806424FC84A494C81E73BB06B5F';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '925FE69CEF38AA0D2CCBF6741ADD808F204CAA64EFA7E301A0A3EC332E40075E';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '1660234E7CCC29CFC8DEC8C6508AAF54EE48004EA9B56A15AC5742C89AAADA08';
    FExpectedHashOfOnetoNine
      : String =
      '2A359FEEB8E488A1AF2C03B908B3ED7990400555DB73E1421181D97CAC004D48';
    FExpectedHashOfabcde
      : String =
      '6377C7E66081CB65E473C1B95DB5195A27D04A7108B468890224BEDBE1A8A6EB';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestKeccak_288 = class(THashLibAlgorithmTestCase)

  private

    FKeccak_288: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D01';
    FExpectedHashOfDefaultData
      : String =
      'A81F64CA8FAFFA1FC64A8E40E3F6A6FEA3303753B8F7F25E7E6EABA3D99A13F1EDF0F125';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'EDC893C0E0E9E70F299098D5049D82EE6811582B93B5C38A5DC9FD14F984A352042365D0';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '615143BAA85817D4F6F051E33801A900AEA480E716A01826E1392743A92B46EED587E9F7';
    FExpectedHashOfOnetoNine
      : String =
      '2B87D3D1907AA78236C7037752CA8C456611C24CE8FBAAAC961AABF3137B471C93A8F031';
    FExpectedHashOfabcde
      : String =
      'F996518E4703A5D660B250D720A143B0A44C5DE31819A82FEF0F30158D18E74E6DF405F6';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

type

  TTestKeccak_384 = class(THashLibAlgorithmTestCase)

  private

    FKeccak_384: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF';
    FExpectedHashOfDefaultData
      : String =
      '6A53977DFA0BCDCF069635CF541AB64C7E41923FCB3A5B049AB98878411D0E71DF95FCAB0072F1AE8B931BF4490B823E';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      'A7740E29EEF80306DA09D7AF0868E925D6144996F99A01F973F03C4BD85D1EC20567936CA34A443B62A890AD8D263D2A';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '044628643016E3EA30DE6CA3A8A1276F6BF1A5443CEF96BAA73199CF64FFC52D7F38254C671DB2933FFC8DD3E5B77223';
    FExpectedHashOfOnetoNine
      : String =
      'EFCCAE72CE14656C434751CF737E70A57AB8DD2C76F5ABE01E52770AFFD77B66D2B80977724A00A6D971B702906F8032';
    FExpectedHashOfabcde
      : String =
      '6E577A02A783232ACF34841399883F5F69D9AC78F48C7F4431CBC4F669C2A0F1CA3B1BECB7701B8315588D64D6C3746A';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

  TTestKeccak_512 = class(THashLibAlgorithmTestCase)

  private

    FKeccak_512: IHash;

  const
    FExpectedHashOfEmptyData
      : String =
      '0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E';
    FExpectedHashOfDefaultData
      : String =
      '27E67744299C2229F5008141E410B650BB7D70366B8A60BEAE52F8D6F4A8889D1BAEF53191FF53277FD6CFFE76937CDFAC40EB8EE6F32E3B146C05F961E970A8';
    FExpectedHashOfDefaultDataWithHMACWithLongKey
      : String =
      '53D5520C2E31F7EAAE1D95CF04663B18C2144AAF141F2630D6454162B3A890D75D59A9D99096411870FBF7A92A563AEA35AFED836DF652C6DF2AB4D373A754E3';
    FExpectedHashOfDefaultDataWithHMACWithShortKey
      : String =
      '6FA826F0AFFE589DFD1665264F5516D076F9FEC585FD4227095B467A50E963D45C1730232549E8DDB590C1518BA310612839BBCCDF34F6A0AD6AC8B91D393BE6';
    FExpectedHashOfOnetoNine
      : String =
      '40B787E94778266FB196A73B7A77EDF9DE2EF172451A2B87531324812250DF8F26FCC11E69B35AFDDBE639956C96153E71363F97010BC99405DD2D77B8C41986';
    FExpectedHashOfabcde
      : String =
      '37491BD4BF2A4629D4E35602E09812FA94BFC63BAEE4487075E2B6D73F36D01A7392A1719EDBBB5D1D6FA3BA0D144F18229ABC13B7933A4736D6AAB4A3177F18';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestHMACWithDefaultDataAndLongKey;
    procedure TestHMACWithDefaultDataAndShortKey;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneIsUnique;
    procedure TestHMACCloneIsCorrect;

  end;

implementation

// Crypto

{ TTestGost }

procedure TTestGost.SetUp;
begin
  inherited;
  FGost := THashFactory.TCrypto.CreateGost();
end;

procedure TTestGost.TearDown;
begin
  FGost := Nil;
  inherited;
end;

procedure TTestGost.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FGost.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FGost;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FGost;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestGost.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FGost);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FGost.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateGost);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateGost);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FGost.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestGost.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGost.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateGost();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGost.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FGost.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestGrindahl256 }

procedure TTestGrindahl256.SetUp;
begin
  inherited;
  FGrindahl256 := THashFactory.TCrypto.CreateGrindahl256();
end;

procedure TTestGrindahl256.TearDown;
begin
  FGrindahl256 := Nil;
  inherited;
end;

procedure TTestGrindahl256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FGrindahl256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FGrindahl256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FGrindahl256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FGrindahl256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestGrindahl256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FGrindahl256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateGrindahl256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateGrindahl256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FGrindahl256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestGrindahl256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGrindahl256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateGrindahl256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FGrindahl256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestGrindahl512 }

procedure TTestGrindahl512.SetUp;
begin
  inherited;
  FGrindahl512 := THashFactory.TCrypto.CreateGrindahl512();
end;

procedure TTestGrindahl512.TearDown;
begin
  FGrindahl512 := Nil;
  inherited;
end;

procedure TTestGrindahl512.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FGrindahl512.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FGrindahl512.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FGrindahl512;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FGrindahl512;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestGrindahl512.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FGrindahl512);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateGrindahl512);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateGrindahl512);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FGrindahl512.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestGrindahl512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGrindahl512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateGrindahl512();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGrindahl512.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FGrindahl512.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHAS160 }

procedure TTestHAS160.SetUp;
begin
  inherited;
  FHAS160 := THashFactory.TCrypto.CreateHAS160();
end;

procedure TTestHAS160.TearDown;
begin
  FHAS160 := Nil;
  inherited;
end;

procedure TTestHAS160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHAS160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHAS160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHAS160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHAS160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHAS160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHAS160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateHAS160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateHAS160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHAS160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHAS160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHAS160.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHAS160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHAS160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHAS160.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_3_128 }

procedure TTestHaval_3_128.SetUp;
begin
  inherited;
  FHaval_3_128 := THashFactory.TCrypto.CreateHaval_3_128();
end;

procedure TTestHaval_3_128.TearDown;
begin
  FHaval_3_128 := Nil;
  inherited;
end;

procedure TTestHaval_3_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_3_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_3_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_3_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_3_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_3_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_3_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_3_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_3_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_3_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_3_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_3_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_4_128 }

procedure TTestHaval_4_128.SetUp;
begin
  inherited;
  FHaval_4_128 := THashFactory.TCrypto.CreateHaval_4_128();
end;

procedure TTestHaval_4_128.TearDown;
begin
  FHaval_4_128 := Nil;
  inherited;
end;

procedure TTestHaval_4_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_4_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_4_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_4_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_4_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_4_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_4_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_4_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_4_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_4_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_4_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_4_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_5_128 }

procedure TTestHaval_5_128.SetUp;
begin
  inherited;
  FHaval_5_128 := THashFactory.TCrypto.CreateHaval_5_128();
end;

procedure TTestHaval_5_128.TearDown;
begin
  FHaval_5_128 := Nil;
  inherited;
end;

procedure TTestHaval_5_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_5_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_5_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_5_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_5_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_5_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_5_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_5_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_5_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_5_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_5_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_5_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_3_160 }

procedure TTestHaval_3_160.SetUp;
begin
  inherited;
  FHaval_3_160 := THashFactory.TCrypto.CreateHaval_3_160();
end;

procedure TTestHaval_3_160.TearDown;
begin
  FHaval_3_160 := Nil;
  inherited;
end;

procedure TTestHaval_3_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_3_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_3_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_3_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_3_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_3_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_3_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_3_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_3_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_3_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_3_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_3_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_4_160 }

procedure TTestHaval_4_160.SetUp;
begin
  inherited;
  FHaval_4_160 := THashFactory.TCrypto.CreateHaval_4_160();
end;

procedure TTestHaval_4_160.TearDown;
begin
  FHaval_4_160 := Nil;
  inherited;
end;

procedure TTestHaval_4_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_4_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_4_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_4_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_4_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_4_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_4_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_4_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_4_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_4_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_4_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_4_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_5_160 }

procedure TTestHaval_5_160.SetUp;
begin
  inherited;
  FHaval_5_160 := THashFactory.TCrypto.CreateHaval_5_160();
end;

procedure TTestHaval_5_160.TearDown;
begin
  FHaval_5_160 := Nil;
  inherited;
end;

procedure TTestHaval_5_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_5_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_5_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_5_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_5_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_5_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_5_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_5_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_5_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_5_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_5_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_5_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_3_192 }

procedure TTestHaval_3_192.SetUp;
begin
  inherited;
  FHaval_3_192 := THashFactory.TCrypto.CreateHaval_3_192();
end;

procedure TTestHaval_3_192.TearDown;
begin
  FHaval_3_192 := Nil;
  inherited;
end;

procedure TTestHaval_3_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_3_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_3_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_3_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_3_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_3_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_3_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_3_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_3_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_3_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_3_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_3_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_4_192 }

procedure TTestHaval_4_192.SetUp;
begin
  inherited;
  FHaval_4_192 := THashFactory.TCrypto.CreateHaval_4_192();
end;

procedure TTestHaval_4_192.TearDown;
begin
  FHaval_4_192 := Nil;
  inherited;
end;

procedure TTestHaval_4_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_4_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_4_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_4_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_4_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_4_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_4_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_4_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_4_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_4_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_4_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_4_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_5_192 }

procedure TTestHaval_5_192.SetUp;
begin
  inherited;
  FHaval_5_192 := THashFactory.TCrypto.CreateHaval_5_192();
end;

procedure TTestHaval_5_192.TearDown;
begin
  FHaval_5_192 := Nil;
  inherited;
end;

procedure TTestHaval_5_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_5_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_5_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_5_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_5_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_5_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_5_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_5_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_5_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_5_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_5_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_5_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_3_224 }

procedure TTestHaval_3_224.SetUp;
begin
  inherited;
  FHaval_3_224 := THashFactory.TCrypto.CreateHaval_3_224();
end;

procedure TTestHaval_3_224.TearDown;
begin
  FHaval_3_224 := Nil;
  inherited;
end;

procedure TTestHaval_3_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_3_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_3_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_3_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_3_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_3_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_3_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_3_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_3_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_3_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_3_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_3_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_4_224 }

procedure TTestHaval_4_224.SetUp;
begin
  inherited;
  FHaval_4_224 := THashFactory.TCrypto.CreateHaval_4_224();
end;

procedure TTestHaval_4_224.TearDown;
begin
  FHaval_4_224 := Nil;
  inherited;
end;

procedure TTestHaval_4_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_4_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_4_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_4_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_4_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_4_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_4_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_4_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_4_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_4_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_4_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_4_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_5_224 }

procedure TTestHaval_5_224.SetUp;
begin
  inherited;
  FHaval_5_224 := THashFactory.TCrypto.CreateHaval_5_224();
end;

procedure TTestHaval_5_224.TearDown;
begin
  FHaval_5_224 := Nil;
  inherited;
end;

procedure TTestHaval_5_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_5_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_5_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_5_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_5_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_5_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_5_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_5_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_5_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_5_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_5_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_5_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_3_256 }

procedure TTestHaval_3_256.SetUp;
begin
  inherited;
  FHaval_3_256 := THashFactory.TCrypto.CreateHaval_3_256();
end;

procedure TTestHaval_3_256.TearDown;
begin
  FHaval_3_256 := Nil;
  inherited;
end;

procedure TTestHaval_3_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_3_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_3_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_3_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_3_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_3_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_3_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_3_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_3_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_3_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_3_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_3_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_3_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_3_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_4_256 }

procedure TTestHaval_4_256.SetUp;
begin
  inherited;
  FHaval_4_256 := THashFactory.TCrypto.CreateHaval_4_256();
end;

procedure TTestHaval_4_256.TearDown;
begin
  FHaval_4_256 := Nil;
  inherited;
end;

procedure TTestHaval_4_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_4_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_4_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_4_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_4_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_4_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_4_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_4_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_4_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_4_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_4_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_4_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_4_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_4_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestHaval_5_256 }

procedure TTestHaval_5_256.SetUp;
begin
  inherited;
  FHaval_5_256 := THashFactory.TCrypto.CreateHaval_5_256();
end;

procedure TTestHaval_5_256.TearDown;
begin
  FHaval_5_256 := Nil;
  inherited;
end;

procedure TTestHaval_5_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FHaval_5_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FHaval_5_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FHaval_5_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FHaval_5_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestHaval_5_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FHaval_5_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateHaval_5_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FHaval_5_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestHaval_5_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FHaval_5_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateHaval_5_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestHaval_5_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FHaval_5_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMD2 }

procedure TTestMD2.SetUp;
begin
  inherited;
  FMD2 := THashFactory.TCrypto.CreateMD2();
end;

procedure TTestMD2.TearDown;
begin
  FMD2 := Nil;
  inherited;
end;

procedure TTestMD2.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMD2.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMD2.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMD2;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMD2;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMD2.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FMD2);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD2);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD2);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMD2.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMD2.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMD2.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateMD2();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD2.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMD2.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMD4 }

procedure TTestMD4.SetUp;
begin
  inherited;
  FMD4 := THashFactory.TCrypto.CreateMD4();
end;

procedure TTestMD4.TearDown;
begin
  FMD4 := Nil;
  inherited;
end;

procedure TTestMD4.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMD4.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMD4.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMD4;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMD4;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMD4.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FMD4);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD4);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD4);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMD4.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMD4.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMD4.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateMD4();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD4.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMD4.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMD5 }

procedure TTestMD5.SetUp;
begin
  inherited;
  FMD5 := THashFactory.TCrypto.CreateMD5();
end;

procedure TTestMD5.TearDown;
begin
  FMD5 := Nil;
  inherited;
end;

procedure TTestMD5.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMD5.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMD5.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FMD5;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FMD5;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestMD5.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FMD5);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD5);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateMD5);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMD5.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMD5.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMD5.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateMD5();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMD5.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMD5.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestPanama }

procedure TTestPanama.SetUp;
begin
  inherited;
  FPanama := THashFactory.TCrypto.CreatePanama();
end;

procedure TTestPanama.TearDown;
begin
  FPanama := Nil;
  inherited;
end;

procedure TTestPanama.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FPanama.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FPanama.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FPanama;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FPanama;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestPanama.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FPanama);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreatePanama);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreatePanama);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FPanama.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestPanama.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FPanama.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreatePanama();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPanama.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FPanama.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRadioGatun32 }

procedure TTestRadioGatun32.SetUp;
begin
  inherited;
  FRadioGatun32 := THashFactory.TCrypto.CreateRadioGatun32();
end;

procedure TTestRadioGatun32.TearDown;
begin
  FRadioGatun32 := Nil;
  inherited;
end;

procedure TTestRadioGatun32.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRadioGatun32.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRadioGatun32.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRadioGatun32;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRadioGatun32;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRadioGatun32.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRadioGatun32);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateRadioGatun32);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateRadioGatun32);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRadioGatun32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRadioGatun32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRadioGatun32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRadioGatun32();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun32.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRadioGatun32.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRadioGatun64 }

procedure TTestRadioGatun64.SetUp;
begin
  inherited;
  FRadioGatun64 := THashFactory.TCrypto.CreateRadioGatun64();
end;

procedure TTestRadioGatun64.TearDown;
begin
  FRadioGatun64 := Nil;
  inherited;
end;

procedure TTestRadioGatun64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRadioGatun64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRadioGatun64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRadioGatun64;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRadioGatun64;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRadioGatun64.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRadioGatun64);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateRadioGatun64);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateRadioGatun64);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRadioGatun64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRadioGatun64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRadioGatun64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRadioGatun64();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRadioGatun64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRadioGatun64.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRIPEMD }

procedure TTestRIPEMD.SetUp;
begin
  inherited;
  FRIPEMD := THashFactory.TCrypto.CreateRIPEMD();
end;

procedure TTestRIPEMD.TearDown;
begin
  FRIPEMD := Nil;
  inherited;
end;

procedure TTestRIPEMD.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRIPEMD.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRIPEMD.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRIPEMD;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRIPEMD;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRIPEMD.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRIPEMD);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRIPEMD.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRIPEMD.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRIPEMD.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRIPEMD();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRIPEMD.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRIPEMD128 }

procedure TTestRIPEMD128.SetUp;
begin
  inherited;
  FRIPEMD128 := THashFactory.TCrypto.CreateRIPEMD128();
end;

procedure TTestRIPEMD128.TearDown;
begin
  FRIPEMD128 := Nil;
  inherited;
end;

procedure TTestRIPEMD128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRIPEMD128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRIPEMD128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRIPEMD128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRIPEMD128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRIPEMD128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRIPEMD128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRIPEMD128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRIPEMD128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRIPEMD128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRIPEMD128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRIPEMD128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRIPEMD160 }

procedure TTestRIPEMD160.SetUp;
begin
  inherited;
  FRIPEMD160 := THashFactory.TCrypto.CreateRIPEMD160();
end;

procedure TTestRIPEMD160.TearDown;
begin
  FRIPEMD160 := Nil;
  inherited;
end;

procedure TTestRIPEMD160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRIPEMD160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRIPEMD160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRIPEMD160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRIPEMD160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRIPEMD160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRIPEMD160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRIPEMD160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRIPEMD160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRIPEMD160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRIPEMD160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRIPEMD160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRIPEMD256 }

procedure TTestRIPEMD256.SetUp;
begin
  inherited;
  FRIPEMD256 := THashFactory.TCrypto.CreateRIPEMD256();
end;

procedure TTestRIPEMD256.TearDown;
begin
  FRIPEMD256 := Nil;
  inherited;
end;

procedure TTestRIPEMD256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRIPEMD256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRIPEMD256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRIPEMD256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRIPEMD256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRIPEMD256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRIPEMD256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRIPEMD256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRIPEMD256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRIPEMD256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRIPEMD256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRIPEMD256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRIPEMD320 }

procedure TTestRIPEMD320.SetUp;
begin
  inherited;
  FRIPEMD320 := THashFactory.TCrypto.CreateRIPEMD320();
end;

procedure TTestRIPEMD320.TearDown;
begin
  FRIPEMD320 := Nil;
  inherited;
end;

procedure TTestRIPEMD320.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRIPEMD320.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRIPEMD320.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FRIPEMD320;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FRIPEMD320;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestRIPEMD320.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FRIPEMD320);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD320);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateRIPEMD320);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRIPEMD320.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRIPEMD320.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRIPEMD320.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateRIPEMD320();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRIPEMD320.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRIPEMD320.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA0 }

procedure TTestSHA0.SetUp;
begin
  inherited;
  FSHA0 := THashFactory.TCrypto.CreateSHA0();
end;

procedure TTestSHA0.TearDown;
begin
  FSHA0 := Nil;
  inherited;
end;

procedure TTestSHA0.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA0.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA0.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA0;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA0;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA0.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA0);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA0);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA0);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA0.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA0.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA0.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA0();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA0.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA0.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA1 }

procedure TTestSHA1.SetUp;
begin
  inherited;
  FSHA1 := THashFactory.TCrypto.CreateSHA1();
end;

procedure TTestSHA1.TearDown;
begin
  FSHA1 := Nil;
  inherited;
end;

procedure TTestSHA1.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA1.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA1.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA1;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA1;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA1.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA1);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA1);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA1);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA1.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA1.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA1.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA1();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA1.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA1.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_224 }

procedure TTestSHA2_224.SetUp;
begin
  inherited;
  FSHA2_224 := THashFactory.TCrypto.CreateSHA2_224();
end;

procedure TTestSHA2_224.TearDown;
begin
  FSHA2_224 := Nil;
  inherited;
end;

procedure TTestSHA2_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_256 }

procedure TTestSHA2_256.SetUp;
begin
  inherited;
  FSHA2_256 := THashFactory.TCrypto.CreateSHA2_256();
end;

procedure TTestSHA2_256.TearDown;
begin
  FSHA2_256 := Nil;
  inherited;
end;

procedure TTestSHA2_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_384 }

procedure TTestSHA2_384.SetUp;
begin
  inherited;
  FSHA2_384 := THashFactory.TCrypto.CreateSHA2_384();
end;

procedure TTestSHA2_384.TearDown;
begin
  FSHA2_384 := Nil;
  inherited;
end;

procedure TTestSHA2_384.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_384.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_384.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_384;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_384;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_384.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_384);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_384.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_384.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_384.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_384();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_384.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_384.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_512 }

procedure TTestSHA2_512.SetUp;
begin
  inherited;
  FSHA2_512 := THashFactory.TCrypto.CreateSHA2_512();
end;

procedure TTestSHA2_512.TearDown;
begin
  FSHA2_512 := Nil;
  inherited;
end;

procedure TTestSHA2_512.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_512.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_512.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_512;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_512;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_512.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_512);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_512.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_512();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_512.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_512_224 }

procedure TTestSHA2_512_224.SetUp;
begin
  inherited;
  FSHA2_512_224 := THashFactory.TCrypto.CreateSHA2_512_224();
end;

procedure TTestSHA2_512_224.TearDown;
begin
  FSHA2_512_224 := Nil;
  inherited;
end;

procedure TTestSHA2_512_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_512_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_512_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_512_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_512_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_512_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_512_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSHA2_512_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSHA2_512_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_512_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_512_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_512_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_512_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_512_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA2_512_256 }

procedure TTestSHA2_512_256.SetUp;
begin
  inherited;
  FSHA2_512_256 := THashFactory.TCrypto.CreateSHA2_512_256();
end;

procedure TTestSHA2_512_256.TearDown;
begin
  FSHA2_512_256 := Nil;
  inherited;
end;

procedure TTestSHA2_512_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA2_512_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA2_512_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA2_512_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA2_512_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA2_512_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA2_512_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSHA2_512_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSHA2_512_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA2_512_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA2_512_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA2_512_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA2_512_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA2_512_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA2_512_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA3_224 }

procedure TTestSHA3_224.SetUp;
begin
  inherited;
  FSHA3_224 := THashFactory.TCrypto.CreateSHA3_224();
end;

procedure TTestSHA3_224.TearDown;
begin
  FSHA3_224 := Nil;
  inherited;
end;

procedure TTestSHA3_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA3_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA3_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA3_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA3_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA3_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA3_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA3_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA3_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA3_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA3_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA3_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA3_256 }

procedure TTestSHA3_256.SetUp;
begin
  inherited;
  FSHA3_256 := THashFactory.TCrypto.CreateSHA3_256();
end;

procedure TTestSHA3_256.TearDown;
begin
  FSHA3_256 := Nil;
  inherited;
end;

procedure TTestSHA3_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA3_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA3_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA3_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA3_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA3_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA3_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA3_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA3_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA3_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA3_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA3_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA3_384 }

procedure TTestSHA3_384.SetUp;
begin
  inherited;
  FSHA3_384 := THashFactory.TCrypto.CreateSHA3_384();
end;

procedure TTestSHA3_384.TearDown;
begin
  FSHA3_384 := Nil;
  inherited;
end;

procedure TTestSHA3_384.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA3_384.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA3_384.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA3_384;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA3_384;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA3_384.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA3_384);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_384);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_384);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA3_384.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA3_384.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA3_384.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA3_384();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_384.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA3_384.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSHA3_512 }

procedure TTestSHA3_512.SetUp;
begin
  inherited;
  FSHA3_512 := THashFactory.TCrypto.CreateSHA3_512();
end;

procedure TTestSHA3_512.TearDown;
begin
  FSHA3_512 := Nil;
  inherited;
end;

procedure TTestSHA3_512.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSHA3_512.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSHA3_512.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSHA3_512;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSHA3_512;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSHA3_512.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSHA3_512);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_512);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA3_512);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSHA3_512.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSHA3_512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSHA3_512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSHA3_512();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSHA3_512.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSHA3_512.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestShake_128 }

procedure TTestShake_128.SetUp;
begin
  inherited;
  FShake_128 := THashFactory.TXOF.CreateShake_128(512);
end;

procedure TTestShake_128.TearDown;
begin
  FShake_128 := Nil;
  inherited;
end;

procedure TTestShake_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FShake_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FShake_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FShake_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FShake_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FShake_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  (Original as IXOF).XOFSizeInBits := 128;
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb
  (Copy as IXOF).XOFSizeInBits := 256;

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));

  CheckNotEquals((Original as IXOF).XOFSizeInBits, (Copy as IXOF).XOFSizeInBits,
    Format('Expected %u but got %u.', [(Original as IXOF).XOFSizeInBits,
    (Copy as IXOF).XOFSizeInBits]));
end;

procedure TTestShake_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FShake_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestShake_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TXOF.CreateShake_128(512);

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FShake_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_128.TestVeryLongShakeOfEmptyString;
var
  VeryLongShake_128: IHash;
begin
  VeryLongShake_128 := THashFactory.TXOF.CreateShake_128(8000);
  FActualString := VeryLongShake_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  FExpectedString := FVeryLongShakeOfEmptyString;
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestShake_256 }

procedure TTestShake_256.SetUp;
begin
  inherited;
  FShake_256 := THashFactory.TXOF.CreateShake_256(512);
end;

procedure TTestShake_256.TearDown;
begin
  FShake_256 := Nil;
  inherited;
end;

procedure TTestShake_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FShake_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FShake_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FShake_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FShake_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FShake_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  (Original as IXOF).XOFSizeInBits := 128;
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb
  (Copy as IXOF).XOFSizeInBits := 256;

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));

  CheckNotEquals((Original as IXOF).XOFSizeInBits, (Copy as IXOF).XOFSizeInBits,
    Format('Expected %u but got %u.', [(Original as IXOF).XOFSizeInBits,
    (Copy as IXOF).XOFSizeInBits]));
end;

procedure TTestShake_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FShake_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestShake_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TXOF.CreateShake_256(512);

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FShake_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShake_256.TestVeryLongShakeOfEmptyString;
var
  VeryLongShake_256: IHash;
begin
  VeryLongShake_256 := THashFactory.TXOF.CreateShake_256(8000);
  FActualString := VeryLongShake_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  FExpectedString := FVeryLongShakeOfEmptyString;
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSnefru_8_128 }

procedure TTestSnefru_8_128.SetUp;
begin
  inherited;
  FSnefru_8_128 := THashFactory.TCrypto.CreateSnefru_8_128();
end;

procedure TTestSnefru_8_128.TearDown;
begin
  FSnefru_8_128 := Nil;
  inherited;
end;

procedure TTestSnefru_8_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSnefru_8_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSnefru_8_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSnefru_8_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSnefru_8_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSnefru_8_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSnefru_8_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSnefru_8_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSnefru_8_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSnefru_8_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSnefru_8_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSnefru_8_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSnefru_8_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSnefru_8_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSnefru_8_256 }

procedure TTestSnefru_8_256.SetUp;
begin
  inherited;
  FSnefru_8_256 := THashFactory.TCrypto.CreateSnefru_8_256();
end;

procedure TTestSnefru_8_256.TearDown;
begin
  FSnefru_8_256 := Nil;
  inherited;
end;

procedure TTestSnefru_8_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSnefru_8_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSnefru_8_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FSnefru_8_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FSnefru_8_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestSnefru_8_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FSnefru_8_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSnefru_8_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateSnefru_8_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSnefru_8_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSnefru_8_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSnefru_8_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateSnefru_8_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSnefru_8_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSnefru_8_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_3_128 }

procedure TTestTiger_3_128.SetUp;
begin
  inherited;
  FTiger_3_128 := THashFactory.TCrypto.CreateTiger_3_128();
end;

procedure TTestTiger_3_128.TearDown;
begin
  FTiger_3_128 := Nil;
  inherited;
end;

procedure TTestTiger_3_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_3_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_3_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_3_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_3_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_3_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_3_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_3_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_3_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_3_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_3_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_3_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_4_128 }

procedure TTestTiger_4_128.SetUp;
begin
  inherited;
  FTiger_4_128 := THashFactory.TCrypto.CreateTiger_4_128();
end;

procedure TTestTiger_4_128.TearDown;
begin
  FTiger_4_128 := Nil;
  inherited;
end;

procedure TTestTiger_4_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_4_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_4_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_4_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_4_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_4_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_4_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_4_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_4_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_4_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_4_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_4_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_5_128 }

procedure TTestTiger_5_128.SetUp;
begin
  inherited;
  FTiger_5_128 := THashFactory.TCrypto.CreateTiger_5_128();
end;

procedure TTestTiger_5_128.TearDown;
begin
  FTiger_5_128 := Nil;
  inherited;
end;

procedure TTestTiger_5_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_5_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_5_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_5_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_5_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_5_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_5_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_5_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_5_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_5_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_5_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_5_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_3_160 }

procedure TTestTiger_3_160.SetUp;
begin
  inherited;
  FTiger_3_160 := THashFactory.TCrypto.CreateTiger_3_160();
end;

procedure TTestTiger_3_160.TearDown;
begin
  FTiger_3_160 := Nil;
  inherited;
end;

procedure TTestTiger_3_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_3_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_3_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_3_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_3_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_3_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_3_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_3_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_3_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_3_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_3_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_3_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_4_160 }

procedure TTestTiger_4_160.SetUp;
begin
  inherited;
  FTiger_4_160 := THashFactory.TCrypto.CreateTiger_4_160();
end;

procedure TTestTiger_4_160.TearDown;
begin
  FTiger_4_160 := Nil;
  inherited;
end;

procedure TTestTiger_4_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_4_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_4_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_4_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_4_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_4_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_4_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_4_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_4_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_4_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_4_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_4_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_5_160 }

procedure TTestTiger_5_160.SetUp;
begin
  inherited;
  FTiger_5_160 := THashFactory.TCrypto.CreateTiger_5_160();
end;

procedure TTestTiger_5_160.TearDown;
begin
  FTiger_5_160 := Nil;
  inherited;
end;

procedure TTestTiger_5_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_5_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_5_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_5_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_5_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_5_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_5_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_5_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_5_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_5_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_5_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_5_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_3_192 }

procedure TTestTiger_3_192.SetUp;
begin
  inherited;
  FTiger_3_192 := THashFactory.TCrypto.CreateTiger_3_192();
end;

procedure TTestTiger_3_192.TearDown;
begin
  FTiger_3_192 := Nil;
  inherited;
end;

procedure TTestTiger_3_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_3_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_3_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_3_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_3_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_3_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_3_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_3_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_3_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_3_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_3_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_3_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_3_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_3_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_4_192 }

procedure TTestTiger_4_192.SetUp;
begin
  inherited;
  FTiger_4_192 := THashFactory.TCrypto.CreateTiger_4_192();
end;

procedure TTestTiger_4_192.TearDown;
begin
  FTiger_4_192 := Nil;
  inherited;
end;

procedure TTestTiger_4_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_4_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_4_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_4_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_4_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_4_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_4_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_4_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_4_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_4_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_4_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_4_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_4_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_4_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger_5_192 }

procedure TTestTiger_5_192.SetUp;
begin
  inherited;
  FTiger_5_192 := THashFactory.TCrypto.CreateTiger_5_192();
end;

procedure TTestTiger_5_192.TearDown;
begin
  FTiger_5_192 := Nil;
  inherited;
end;

procedure TTestTiger_5_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger_5_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger_5_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger_5_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger_5_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger_5_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger_5_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger_5_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger_5_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger_5_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger_5_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger_5_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger_5_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger_5_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_3_128 }

procedure TTestTiger2_3_128.SetUp;
begin
  inherited;
  FTiger2_3_128 := THashFactory.TCrypto.CreateTiger2_3_128();
end;

procedure TTestTiger2_3_128.TearDown;
begin
  FTiger2_3_128 := Nil;
  inherited;
end;

procedure TTestTiger2_3_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_3_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_3_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_3_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_3_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_3_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_3_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_3_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_3_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_3_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_3_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_3_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_4_128 }

procedure TTestTiger2_4_128.SetUp;
begin
  inherited;
  FTiger2_4_128 := THashFactory.TCrypto.CreateTiger2_4_128();
end;

procedure TTestTiger2_4_128.TearDown;
begin
  FTiger2_4_128 := Nil;
  inherited;
end;

procedure TTestTiger2_4_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_4_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_4_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_4_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_4_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_4_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_4_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_4_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_4_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_4_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_4_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_4_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_5_128 }

procedure TTestTiger2_5_128.SetUp;
begin
  inherited;
  FTiger2_5_128 := THashFactory.TCrypto.CreateTiger2_5_128();
end;

procedure TTestTiger2_5_128.TearDown;
begin
  FTiger2_5_128 := Nil;
  inherited;
end;

procedure TTestTiger2_5_128.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_5_128.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_5_128.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_5_128;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_5_128;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_5_128.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_5_128);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_128);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_128);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_5_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_5_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_5_128.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_5_128();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_128.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_5_128.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_3_160 }

procedure TTestTiger2_3_160.SetUp;
begin
  inherited;
  FTiger2_3_160 := THashFactory.TCrypto.CreateTiger2_3_160();
end;

procedure TTestTiger2_3_160.TearDown;
begin
  FTiger2_3_160 := Nil;
  inherited;
end;

procedure TTestTiger2_3_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_3_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_3_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_3_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_3_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_3_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_3_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_3_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_3_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_3_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_3_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_3_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_4_160 }

procedure TTestTiger2_4_160.SetUp;
begin
  inherited;
  FTiger2_4_160 := THashFactory.TCrypto.CreateTiger2_4_160();
end;

procedure TTestTiger2_4_160.TearDown;
begin
  FTiger2_4_160 := Nil;
  inherited;
end;

procedure TTestTiger2_4_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_4_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_4_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_4_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_4_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_4_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_4_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_4_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_4_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_4_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_4_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_4_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_5_160 }

procedure TTestTiger2_5_160.SetUp;
begin
  inherited;
  FTiger2_5_160 := THashFactory.TCrypto.CreateTiger2_5_160();
end;

procedure TTestTiger2_5_160.TearDown;
begin
  FTiger2_5_160 := Nil;
  inherited;
end;

procedure TTestTiger2_5_160.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_5_160.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_5_160.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_5_160;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_5_160;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_5_160.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_5_160);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_160);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_160);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_5_160.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_5_160.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_5_160.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_5_160();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_160.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_5_160.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_3_192 }

procedure TTestTiger2_3_192.SetUp;
begin
  inherited;
  FTiger2_3_192 := THashFactory.TCrypto.CreateTiger2_3_192();
end;

procedure TTestTiger2_3_192.TearDown;
begin
  FTiger2_3_192 := Nil;
  inherited;
end;

procedure TTestTiger2_3_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_3_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_3_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_3_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_3_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_3_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_3_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_3_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_3_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_3_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_3_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_3_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_3_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_3_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_4_192 }

procedure TTestTiger2_4_192.SetUp;
begin
  inherited;
  FTiger2_4_192 := THashFactory.TCrypto.CreateTiger2_4_192();
end;

procedure TTestTiger2_4_192.TearDown;
begin
  FTiger2_4_192 := Nil;
  inherited;
end;

procedure TTestTiger2_4_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_4_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_4_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_4_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_4_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_4_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_4_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_4_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_4_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_4_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_4_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_4_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_4_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_4_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestTiger2_5_192 }

procedure TTestTiger2_5_192.SetUp;
begin
  inherited;
  FTiger2_5_192 := THashFactory.TCrypto.CreateTiger2_5_192();
end;

procedure TTestTiger2_5_192.TearDown;
begin
  FTiger2_5_192 := Nil;
  inherited;
end;

procedure TTestTiger2_5_192.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FTiger2_5_192.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FTiger2_5_192.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FTiger2_5_192;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FTiger2_5_192;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestTiger2_5_192.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FTiger2_5_192);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_192);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC
    (THashFactory.TCrypto.CreateTiger2_5_192);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FTiger2_5_192.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestTiger2_5_192.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FTiger2_5_192.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateTiger2_5_192();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestTiger2_5_192.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FTiger2_5_192.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestWhirlPool }

procedure TTestWhirlPool.SetUp;
begin
  inherited;
  FWhirlPool := THashFactory.TCrypto.CreateWhirlPool();
end;

procedure TTestWhirlPool.TearDown;
begin
  FWhirlPool := Nil;
  inherited;
end;

procedure TTestWhirlPool.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FWhirlPool.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FWhirlPool.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FWhirlPool;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FWhirlPool;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestWhirlPool.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FWhirlPool);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateWhirlPool);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateWhirlPool);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FWhirlPool.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestWhirlPool.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FWhirlPool.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateWhirlPool();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestWhirlPool.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FWhirlPool.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBlake2B }

procedure TTestBlake2B.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FBlake2B.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FBlake2B.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FBlake2B.TransformString(temp, TEncoding.UTF8);

    FActualString := FBlake2B.TransformFinal().ToString();
    FExpectedString := THashFactory.TCrypto.CreateBlake2B()
      .ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestBlake2B.TestBlake2BTreeHashingMode;
const
  FAN_OUT = Byte(2);
  DEPTH = Byte(2); // MaxDepth
  LEAF_SIZE = UInt32(4096);
  INNER_SIZE = Byte(64);
var
  Buf: TBytes;
  Blake2BTreeConfigh00, Blake2BTreeConfigh01, Blake2BTreeConfigh10
    : IBlake2BTreeConfig;
  h00, h01, h10: IHash;
begin
  System.SetLength(Buf, 6000);
  // Left leaf
  Blake2BTreeConfigh00 := TBlake2BTreeConfig.Create();
  Blake2BTreeConfigh00.FanOut := FAN_OUT;
  Blake2BTreeConfigh00.MaxDepth := DEPTH;
  Blake2BTreeConfigh00.LeafSize := LEAF_SIZE;
  Blake2BTreeConfigh00.InnerHashSize := INNER_SIZE;
  Blake2BTreeConfigh00.NodeOffset := 0;
  Blake2BTreeConfigh00.NodeDepth := 0;
  Blake2BTreeConfigh00.IsLastNode := False;
  h00 := THashFactory.TCrypto.CreateBlake2B(TBlake2BConfig.Create()
    as IBlake2BConfig, Blake2BTreeConfigh00);
  h00.Initialize;

  // Right leaf
  Blake2BTreeConfigh01 := TBlake2BTreeConfig.Create();
  Blake2BTreeConfigh01.FanOut := FAN_OUT;
  Blake2BTreeConfigh01.MaxDepth := DEPTH;
  Blake2BTreeConfigh01.LeafSize := LEAF_SIZE;
  Blake2BTreeConfigh01.InnerHashSize := INNER_SIZE;
  Blake2BTreeConfigh01.NodeOffset := 1;
  Blake2BTreeConfigh01.NodeDepth := 0;
  Blake2BTreeConfigh01.IsLastNode := True;
  h01 := THashFactory.TCrypto.CreateBlake2B(TBlake2BConfig.Create()
    as IBlake2BConfig, Blake2BTreeConfigh01);
  h01.Initialize;

  // Root node
  Blake2BTreeConfigh10 := TBlake2BTreeConfig.Create();
  Blake2BTreeConfigh10.FanOut := FAN_OUT;
  Blake2BTreeConfigh10.MaxDepth := DEPTH;
  Blake2BTreeConfigh10.LeafSize := LEAF_SIZE;
  Blake2BTreeConfigh10.InnerHashSize := INNER_SIZE;
  Blake2BTreeConfigh10.NodeOffset := 0;
  Blake2BTreeConfigh10.NodeDepth := 1;
  Blake2BTreeConfigh10.IsLastNode := True;
  h10 := THashFactory.TCrypto.CreateBlake2B(TBlake2BConfig.Create(32)
    as IBlake2BConfig, Blake2BTreeConfigh10);
  h10.Initialize;

  h10.TransformBytes(h00.ComputeBytes(System.Copy(Buf, 0, LEAF_SIZE))
    .GetBytes());

  h10.TransformBytes(h01.ComputeBytes(System.Copy(Buf, LEAF_SIZE,
    UInt32(System.Length(Buf)) - LEAF_SIZE)).GetBytes());

  FActualString := h10.TransformFinal().ToString();
  FExpectedString := FBlake2BTreeHashingMode;

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2B.TestCheckKeyedTestVectors;
var
  len, i: Int32;
  Key: TBytes;
  FBlake2BWithKey: IHash;
begin

  System.SetLength(Key, 64);
  for i := 0 to 63 do
  begin
    Key[i] := i;
  end;

  Fconfig := TBlake2BConfig.Create();
  Fconfig.Key := Key;
  FBlake2BWithKey := THashFactory.TCrypto.CreateBlake2B(Fconfig);

  for len := 0 to High(TBlake2BTestVectors.FkeyedBlake2B) do
  begin

    if len = 0 then
    begin
      FInput := Nil;
    end
    else
    begin
      System.SetLength(FInput, len);
      for i := 0 to Pred(len) do
      begin
        FInput[i] := i;
      end;
    end;

    FActualString := FBlake2BWithKey.ComputeBytes(FInput).ToString();
    FExpectedString := TBlake2BTestVectors.FkeyedBlake2B[len];

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

  FBlake2BWithKey := Nil;

end;

procedure TTestBlake2B.TestCheckTestVectors;
var
  len, i: Int32;
  Input: TBytes;
begin

  for len := 0 to High(TBlake2BTestVectors.FUnkeyedBlake2B) do
  begin

    if len = 0 then
    begin
      Input := Nil;
    end
    else
    begin
      System.SetLength(Input, len);
      for i := 0 to Pred(len) do
      begin
        Input[i] := i;
      end;
    end;

    FActualString := FBlake2B.ComputeBytes(Input).ToString();
    FExpectedString := TBlake2BTestVectors.FUnkeyedBlake2B[len];

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestBlake2B.TestSplits;
var
  len, split1, split2: Int32;
  hash0, hash1: String;

begin
  for len := 0 to 20 do
  begin
    FBlake2B.Initialize();
    FBlake2B.TransformBytes(FInput, 0, len);
    hash0 := FBlake2B.TransformFinal.ToString();

    for split1 := 0 to len do
    begin
      for split2 := split1 to len do
      begin
        FBlake2B.Initialize();
        FBlake2B.TransformBytes(FInput, 0, split1);
        FBlake2B.TransformBytes(FInput, split1, split2 - split1);
        FBlake2B.TransformBytes(FInput, split2, len - split2);
        hash1 := FBlake2B.TransformFinal.ToString();
        CheckEquals(hash0, hash1, Format('Expected %s but got %s.',
          [hash0, hash1]));
      end;
    end;

  end;

end;

procedure TTestBlake2B.TestEmpty;
// Note: results taken from https://en.wikipedia.org/wiki/BLAKE_(hash_function)
begin
  FBlake2B.Initialize();
  FBlake2B.TransformString(FEmptyData, TEncoding.UTF8);
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBlake2B.TransformFinal.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2B.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FBlake2B;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2B.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FBlake2B;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestBlake2B.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FBlake2B);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2B.TestNullKeyVsUnKeyed;
var
  LConfigNoKeyed, LConfigNullKeyed: IBlake2BConfig;
  MainData: TBytes;
  Idx: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  for Idx := 1 to 64 do
  begin
    LConfigNoKeyed := TBlake2BConfig.Create(Idx);
    LConfigNullKeyed := TBlake2BConfig.Create(Idx);
    LConfigNullKeyed.Key := Nil;

    FExpectedString := THashFactory.TCrypto.CreateBlake2B(LConfigNoKeyed)
      .ComputeBytes(MainData).ToString();

    FActualString := THashFactory.TCrypto.CreateBlake2B(LConfigNullKeyed)
      .ComputeBytes(MainData).ToString();

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s at Index %d', [FExpectedString,
      FActualString, Idx]));
  end;
end;

procedure TTestBlake2B.TestQuickBrownDog;
// Note: results taken from https://en.wikipedia.org/wiki/BLAKE_(hash_function)
begin
  FBlake2B.Initialize();
  FBlake2B.TransformString(FQuickBrownDog, TEncoding.UTF8);
  FExpectedString := FExpectedHashOfQuickBrownDog;
  FActualString := FBlake2B.TransformFinal.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2B.SetUp;
var
  i: Int32;
begin
  inherited;
  FBlake2B := THashFactory.TCrypto.CreateBlake2B();
  System.SetLength(FInput, 20);
  for i := 0 to 19 do
  begin
    FInput[i] := i;
  end;

end;

procedure TTestBlake2B.TearDown;
begin
  FBlake2B := Nil;
  Fconfig := Nil;
  inherited;

end;

{ TTestBlake2S }

procedure TTestBlake2S.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FBlake2S.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FBlake2S.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FBlake2S.TransformString(temp, TEncoding.UTF8);

    FActualString := FBlake2S.TransformFinal().ToString();
    FExpectedString := THashFactory.TCrypto.CreateBlake2S()
      .ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestBlake2S.TestBlake2STreeHashingMode;
const
  FAN_OUT = Byte(2);
  DEPTH = Byte(2); // MaxDepth
  LEAF_SIZE = UInt32(4096);
  INNER_SIZE = Byte(32);
var
  Buf: TBytes;
  Blake2STreeConfigh00, Blake2STreeConfigh01, Blake2STreeConfigh10
    : IBlake2STreeConfig;
  h00, h01, h10: IHash;
begin
  System.SetLength(Buf, 6000);
  // Left leaf
  Blake2STreeConfigh00 := TBlake2STreeConfig.Create();
  Blake2STreeConfigh00.FanOut := FAN_OUT;
  Blake2STreeConfigh00.MaxDepth := DEPTH;
  Blake2STreeConfigh00.LeafSize := LEAF_SIZE;
  Blake2STreeConfigh00.InnerHashSize := INNER_SIZE;
  Blake2STreeConfigh00.NodeOffset := 0;
  Blake2STreeConfigh00.NodeDepth := 0;
  Blake2STreeConfigh00.IsLastNode := False;
  h00 := THashFactory.TCrypto.CreateBlake2S(TBlake2SConfig.Create()
    as IBlake2SConfig, Blake2STreeConfigh00);
  h00.Initialize;

  // Right leaf
  Blake2STreeConfigh01 := TBlake2STreeConfig.Create();
  Blake2STreeConfigh01.FanOut := FAN_OUT;
  Blake2STreeConfigh01.MaxDepth := DEPTH;
  Blake2STreeConfigh01.LeafSize := LEAF_SIZE;
  Blake2STreeConfigh01.InnerHashSize := INNER_SIZE;
  Blake2STreeConfigh01.NodeOffset := 1;
  Blake2STreeConfigh01.NodeDepth := 0;
  Blake2STreeConfigh01.IsLastNode := True;
  h01 := THashFactory.TCrypto.CreateBlake2S(TBlake2SConfig.Create()
    as IBlake2SConfig, Blake2STreeConfigh01);
  h01.Initialize;

  // Root node
  Blake2STreeConfigh10 := TBlake2STreeConfig.Create();
  Blake2STreeConfigh10.FanOut := FAN_OUT;
  Blake2STreeConfigh10.MaxDepth := DEPTH;
  Blake2STreeConfigh10.LeafSize := LEAF_SIZE;
  Blake2STreeConfigh10.InnerHashSize := INNER_SIZE;
  Blake2STreeConfigh10.NodeOffset := 0;
  Blake2STreeConfigh10.NodeDepth := 1;
  Blake2STreeConfigh10.IsLastNode := True;
  h10 := THashFactory.TCrypto.CreateBlake2S(TBlake2SConfig.Create(16)
    as IBlake2SConfig, Blake2STreeConfigh10);
  h10.Initialize;

  h10.TransformBytes(h00.ComputeBytes(System.Copy(Buf, 0, LEAF_SIZE))
    .GetBytes());

  h10.TransformBytes(h01.ComputeBytes(System.Copy(Buf, LEAF_SIZE,
    UInt32(System.Length(Buf)) - LEAF_SIZE)).GetBytes());

  FActualString := h10.TransformFinal().ToString();
  FExpectedString := FBlake2STreeHashingMode;

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2S.TestCheckKeyedTestVectors;
var
  len, i: Int32;
  Key: TBytes;
  FBlake2SWithKey: IHash;
begin

  System.SetLength(Key, 32);
  for i := 0 to 31 do
  begin
    Key[i] := i;
  end;

  Fconfig := TBlake2SConfig.Create();
  Fconfig.Key := Key;
  FBlake2SWithKey := THashFactory.TCrypto.CreateBlake2S(Fconfig);

  for len := 0 to High(TBlake2STestVectors.FkeyedBlake2S) do
  begin

    if len = 0 then
    begin
      FInput := Nil;
    end
    else
    begin
      System.SetLength(FInput, len);
      for i := 0 to Pred(len) do
      begin
        FInput[i] := i;
      end;
    end;

    FActualString := FBlake2SWithKey.ComputeBytes(FInput).ToString();
    FExpectedString := TBlake2STestVectors.FkeyedBlake2S[len];

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

  FBlake2SWithKey := Nil;

end;

procedure TTestBlake2S.TestCheckTestVectors;
var
  len, i: Int32;
  Input: TBytes;
begin

  for len := 0 to High(TBlake2STestVectors.FUnkeyedBlake2S) do
  begin

    if len = 0 then
    begin
      Input := Nil;
    end
    else
    begin
      System.SetLength(Input, len);
      for i := 0 to Pred(len) do
      begin
        Input[i] := i;
      end;
    end;

    FActualString := FBlake2S.ComputeBytes(Input).ToString();
    FExpectedString := TBlake2STestVectors.FUnkeyedBlake2S[len];

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestBlake2S.TestSplits;
var
  len, split1, split2: Int32;
  hash0, hash1: String;

begin
  for len := 0 to 20 do
  begin
    FBlake2S.Initialize();
    FBlake2S.TransformBytes(FInput, 0, len);
    hash0 := FBlake2S.TransformFinal.ToString();

    for split1 := 0 to len do
    begin
      for split2 := split1 to len do
      begin
        FBlake2S.Initialize();
        FBlake2S.TransformBytes(FInput, 0, split1);
        FBlake2S.TransformBytes(FInput, split1, split2 - split1);
        FBlake2S.TransformBytes(FInput, split2, len - split2);
        hash1 := FBlake2S.TransformFinal.ToString();
        CheckEquals(hash0, hash1, Format('Expected %s but got %s.',
          [hash0, hash1]));
      end;
    end;

  end;

end;

procedure TTestBlake2S.TestWithSaltPersonalisation;
var
  FBlake2SWithConfig: IHash;
begin

  Fconfig := TBlake2SConfig.Create();
  Fconfig.HashSize := 16;
  Fconfig.Salt := FSalt;
  Fconfig.Personalisation := FPersonalisation;

  FBlake2SWithConfig := THashFactory.TCrypto.CreateBlake2S(Fconfig);

  FActualString := FBlake2SWithConfig.ComputeBytes(FValue).ToString();
  FExpectedString := 'B3BA5F552E1BFA639B7F092065E41F79';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FBlake2SWithConfig := Nil;
end;

procedure TTestBlake2S.TestWithSaltPersonalisationKey;
var
  FBlake2SWithConfig: IHash;
  Key: TBytes;
  i: Int32;
begin

  System.SetLength(Key, 32);
  for i := 0 to 31 do
  begin
    Key[i] := i;
  end;

  Fconfig := TBlake2SConfig.Create();
  Fconfig.HashSize := 32;
  Fconfig.Salt := FSalt;
  Fconfig.Personalisation := FPersonalisation;
  Fconfig.Key := Key;

  FBlake2SWithConfig := THashFactory.TCrypto.CreateBlake2S(Fconfig);

  FActualString := FBlake2SWithConfig.ComputeBytes(FValue).ToString();
  FExpectedString :=
    'ED1B7315F06E4AC734DC4FC23D3DFB1A86DDA2CDB2FFFD5893EE3796495231B6';

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));

  FBlake2SWithConfig := Nil;
end;

procedure TTestBlake2S.TestEmpty;
// Note: Results taken from http://corz.org/windows/software/checksum/files/Standard%20Test%20Vectors/[Standard%20Test%20Vectors].nfo
begin
  FBlake2S.Initialize();
  FBlake2S.TransformString(FEmptyData, TEncoding.UTF8);
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBlake2S.TransformFinal.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2S.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FBlake2S;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2S.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FBlake2S;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestBlake2S.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FBlake2S);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2S.TestNullKeyVsUnKeyed;
var
  LConfigNoKeyed, LConfigNullKeyed: IBlake2SConfig;
  MainData: TBytes;
  Idx: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  for Idx := 1 to 32 do
  begin
    LConfigNoKeyed := TBlake2SConfig.Create(Idx);
    LConfigNullKeyed := TBlake2SConfig.Create(Idx);
    LConfigNullKeyed.Key := Nil;

    FExpectedString := THashFactory.TCrypto.CreateBlake2S(LConfigNoKeyed)
      .ComputeBytes(MainData).ToString();

    FActualString := THashFactory.TCrypto.CreateBlake2S(LConfigNullKeyed)
      .ComputeBytes(MainData).ToString();

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s at Index %d', [FExpectedString,
      FActualString, Idx]));
  end;
end;

procedure TTestBlake2S.TestQuickBrownDog;
// Note: results taken from http://corz.org/windows/software/checksum/files/Standard%20Test%20Vectors/[Standard%20Test%20Vectors].nfo
begin
  FBlake2S.Initialize();
  FBlake2S.TransformString(FQuickBrownDog, TEncoding.UTF8);
  FExpectedString := FExpectedHashOfQuickBrownDog;
  FActualString := FBlake2S.TransformFinal.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBlake2S.SetUp;
var
  i: Int32;
begin
  inherited;
  FSalt := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  FPersonalisation := TBytes.Create(9, 10, 11, 12, 13, 14, 15, 16);
  FValue := TBytes.Create(255, 254, 253, 252, 251, 250);
  FBlake2S := THashFactory.TCrypto.CreateBlake2S();
  System.SetLength(FInput, 20);
  for i := 0 to 19 do
  begin
    FInput[i] := i;
  end;

end;

procedure TTestBlake2S.TearDown;
begin
  FBlake2S := Nil;
  Fconfig := Nil;
  inherited;

end;

{ TTestKeccak_224 }

procedure TTestKeccak_224.SetUp;
begin
  inherited;
  FKeccak_224 := THashFactory.TCrypto.CreateKeccak_224();
end;

procedure TTestKeccak_224.TearDown;
begin
  FKeccak_224 := Nil;
  inherited;
end;

procedure TTestKeccak_224.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FKeccak_224.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FKeccak_224.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FKeccak_224;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FKeccak_224;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestKeccak_224.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FKeccak_224);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_224);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_224);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FKeccak_224.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestKeccak_224.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FKeccak_224.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateKeccak_224();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_224.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FKeccak_224.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestKeccak_256 }

procedure TTestKeccak_256.SetUp;
begin
  inherited;
  FKeccak_256 := THashFactory.TCrypto.CreateKeccak_256();
end;

procedure TTestKeccak_256.TearDown;
begin
  FKeccak_256 := Nil;
  inherited;
end;

procedure TTestKeccak_256.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FKeccak_256.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FKeccak_256.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FKeccak_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FKeccak_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestKeccak_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FKeccak_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_256);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_256);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FKeccak_256.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestKeccak_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FKeccak_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateKeccak_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_256.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FKeccak_256.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestKeccak_288 }

procedure TTestKeccak_288.SetUp;
begin
  inherited;
  FKeccak_288 := THashFactory.TCrypto.CreateKeccak_288();
end;

procedure TTestKeccak_288.TearDown;
begin
  FKeccak_288 := Nil;
  inherited;
end;

procedure TTestKeccak_288.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FKeccak_288.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FKeccak_288.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FKeccak_288;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FKeccak_288;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestKeccak_288.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FKeccak_288);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_288);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_288);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FKeccak_288.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestKeccak_288.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FKeccak_288.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateKeccak_288();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_288.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FKeccak_288.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestKeccak_384 }

procedure TTestKeccak_384.SetUp;
begin
  inherited;
  FKeccak_384 := THashFactory.TCrypto.CreateKeccak_384();
end;

procedure TTestKeccak_384.TearDown;
begin
  FKeccak_384 := Nil;
  inherited;
end;

procedure TTestKeccak_384.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FKeccak_384.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FKeccak_384.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FKeccak_384;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FKeccak_384;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestKeccak_384.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FKeccak_384);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_384);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_384);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FKeccak_384.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestKeccak_384.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FKeccak_384.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateKeccak_384();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_384.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FKeccak_384.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestKeccak_512 }

procedure TTestKeccak_512.SetUp;
begin
  inherited;
  FKeccak_512 := THashFactory.TCrypto.CreateKeccak_512();
end;

procedure TTestKeccak_512.TearDown;
begin
  FKeccak_512 := Nil;
  inherited;
end;

procedure TTestKeccak_512.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FKeccak_512.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FKeccak_512.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FKeccak_512;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FKeccak_512;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestKeccak_512.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FKeccak_512);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestHMACWithDefaultDataAndLongKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithLongKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_512);

  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACLongStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestHMACWithDefaultDataAndShortKey;
var
  LHMAC: IHMAC;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithHMACWithShortKey;
  LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateKeccak_512);
  LHMAC.Key := TConverters.ConvertStringToBytes(FHMACShortStringKey,
    TEncoding.UTF8);
  FActualString := LHMAC.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FKeccak_512.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestKeccak_512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FKeccak_512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TCrypto.CreateKeccak_512();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FDefaultData, 1, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 4, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 7, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 10, 3), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FDefaultData, 13, 2), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestKeccak_512.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FKeccak_512.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestGOST3411_2012_256 }

procedure TTestGOST3411_2012_256.SetUp;
begin
  inherited;
  FGOST3411_2012_256 := THashFactory.TCrypto.CreateGOST3411_2012_256();
end;

procedure TTestGOST3411_2012_256.TearDown;
begin
  inherited;
  FGOST3411_2012_256 := Nil;
end;

procedure TTestGOST3411_2012_256.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FGOST3411_2012_256.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FGOST3411_2012_256.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FGOST3411_2012_256.TransformString(temp, TEncoding.UTF8);

    FActualString := FGOST3411_2012_256.TransformFinal().ToString();
    FExpectedString := THashFactory.TCrypto.CreateGOST3411_2012_256.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestGOST3411_2012_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGOST3411_2012_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_256.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FGOST3411_2012_256;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_256.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FGOST3411_2012_256;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestGOST3411_2012_256.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FGOST3411_2012_256);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_256.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfQuickBrownFox;
  FHash := THashFactory.TCrypto.CreateGOST3411_2012_256();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FQuickBrownDog, 1, 16), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FQuickBrownDog, 17, 16), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FQuickBrownDog, 33, 11), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_256.TestQuickBrownFox;
begin
  FExpectedString := FExpectedHashOfQuickBrownFox;
  FActualString := FGOST3411_2012_256.ComputeString(FQuickBrownDog,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestGOST3411_2012_512 }

procedure TTestGOST3411_2012_512.SetUp;
begin
  inherited;
  FGOST3411_2012_512 := THashFactory.TCrypto.CreateGOST3411_2012_512();
end;

procedure TTestGOST3411_2012_512.TearDown;
begin
  inherited;
  FGOST3411_2012_512 := Nil;
end;

procedure TTestGOST3411_2012_512.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FGOST3411_2012_512.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FGOST3411_2012_512.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FGOST3411_2012_512.TransformString(temp, TEncoding.UTF8);

    FActualString := FGOST3411_2012_512.TransformFinal().ToString();
    FExpectedString := THashFactory.TCrypto.CreateGOST3411_2012_512.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

end;

procedure TTestGOST3411_2012_512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGOST3411_2012_512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_512.TestHashCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := FGOST3411_2012_512;
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_512.TestHashCloneIsUnique;
var
  Original, Copy: IHash;
begin
  Original := FGOST3411_2012_512;
  Original.Initialize;
  Original.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  Copy := Original.Clone();
  Copy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(Original.BufferSize, Copy.BufferSize,
    Format('Expected %d but got %d.', [Original.BufferSize, Copy.BufferSize]));
end;

procedure TTestGOST3411_2012_512.TestHMACCloneIsCorrect;
var
  Original, Copy: IHash;
  MainData, ChunkOne, ChunkTwo: TBytes;
  Count: Int32;
begin
  MainData := TConverters.ConvertStringToBytes(FDefaultData, TEncoding.UTF8);
  Count := System.Length(MainData) - 3;
  ChunkOne := System.Copy(MainData, 0, Count);
  ChunkTwo := System.Copy(MainData, Count, System.Length(MainData) - Count);
  Original := THashFactory.THMAC.CreateHMAC(FGOST3411_2012_512);
  (Original as IHMAC).Key := TConverters.ConvertStringToBytes
    (FHMACLongStringKey, TEncoding.UTF8);
  Original.Initialize;

  Original.TransformBytes(ChunkOne);
  // Make Copy Of Current State
  Copy := Original.Clone();
  Original.TransformBytes(ChunkTwo);
  FExpectedString := Original.TransformFinal().ToString();
  Copy.TransformBytes(ChunkTwo);
  FActualString := Copy.TransformFinal().ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_512.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfQuickBrownFox;
  FHash := THashFactory.TCrypto.CreateGOST3411_2012_512();

  FHash.Initialize();
  FHash.TransformString(System.Copy(FQuickBrownDog, 1, 16), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FQuickBrownDog, 17, 16), TEncoding.UTF8);
  FHash.TransformString(System.Copy(FQuickBrownDog, 33, 11), TEncoding.UTF8);
  FHashResult := FHash.TransformFinal();
  FActualString := FHashResult.ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestGOST3411_2012_512.TestQuickBrownFox;
begin
  FExpectedString := FExpectedHashOfQuickBrownFox;
  FActualString := FGOST3411_2012_512.ComputeString(FQuickBrownDog,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
// Crypto
RegisterTest(TTestGost);
RegisterTest(TTestGOST3411_2012_256);
RegisterTest(TTestGOST3411_2012_512);
RegisterTest(TTestGrindahl256);
RegisterTest(TTestGrindahl512);
RegisterTest(TTestHAS160);
RegisterTest(TTestHaval_3_128);
RegisterTest(TTestHaval_4_128);
RegisterTest(TTestHaval_5_128);
RegisterTest(TTestHaval_3_160);
RegisterTest(TTestHaval_4_160);
RegisterTest(TTestHaval_5_160);
RegisterTest(TTestHaval_3_192);
RegisterTest(TTestHaval_4_192);
RegisterTest(TTestHaval_5_192);
RegisterTest(TTestHaval_3_224);
RegisterTest(TTestHaval_4_224);
RegisterTest(TTestHaval_5_224);
RegisterTest(TTestHaval_3_256);
RegisterTest(TTestHaval_4_256);
RegisterTest(TTestHaval_5_256);
RegisterTest(TTestMD2);
RegisterTest(TTestMD4);
RegisterTest(TTestMD5);
RegisterTest(TTestPanama);
RegisterTest(TTestRadioGatun32);
RegisterTest(TTestRadioGatun64);
RegisterTest(TTestRIPEMD);
RegisterTest(TTestRIPEMD128);
RegisterTest(TTestRIPEMD160);
RegisterTest(TTestRIPEMD256);
RegisterTest(TTestRIPEMD320);
RegisterTest(TTestSHA0);
RegisterTest(TTestSHA1);
RegisterTest(TTestSHA2_224);
RegisterTest(TTestSHA2_256);
RegisterTest(TTestSHA2_384);
RegisterTest(TTestSHA2_512);
RegisterTest(TTestSHA2_512_224);
RegisterTest(TTestSHA2_512_256);
RegisterTest(TTestSHA3_224);
RegisterTest(TTestSHA3_256);
RegisterTest(TTestSHA3_384);
RegisterTest(TTestSHA3_512);
RegisterTest(TTestShake_128);
RegisterTest(TTestShake_256);
RegisterTest(TTestKeccak_224);
RegisterTest(TTestKeccak_256);
RegisterTest(TTestKeccak_288);
RegisterTest(TTestKeccak_384);
RegisterTest(TTestKeccak_512);
RegisterTest(TTestBlake2B);
RegisterTest(TTestBlake2S);
RegisterTest(TTestSnefru_8_128);
RegisterTest(TTestSnefru_8_256);
RegisterTest(TTestTiger_3_128);
RegisterTest(TTestTiger_4_128);
RegisterTest(TTestTiger_5_128);
RegisterTest(TTestTiger_3_160);
RegisterTest(TTestTiger_4_160);
RegisterTest(TTestTiger_5_160);
RegisterTest(TTestTiger_3_192);
RegisterTest(TTestTiger_4_192);
RegisterTest(TTestTiger_5_192);
RegisterTest(TTestTiger2_3_128);
RegisterTest(TTestTiger2_4_128);
RegisterTest(TTestTiger2_5_128);
RegisterTest(TTestTiger2_3_160);
RegisterTest(TTestTiger2_4_160);
RegisterTest(TTestTiger2_5_160);
RegisterTest(TTestTiger2_3_192);
RegisterTest(TTestTiger2_4_192);
RegisterTest(TTestTiger2_5_192);
RegisterTest(TTestWhirlPool);
{$ELSE}
// Crypto
RegisterTest(TTestGost.Suite);
RegisterTest(TTestGOST3411_2012_256.Suite);
RegisterTest(TTestGOST3411_2012_512.Suite);
RegisterTest(TTestGrindahl256.Suite);
RegisterTest(TTestGrindahl512.Suite);
RegisterTest(TTestHAS160.Suite);
RegisterTest(TTestHaval_3_128.Suite);
RegisterTest(TTestHaval_4_128.Suite);
RegisterTest(TTestHaval_5_128.Suite);
RegisterTest(TTestHaval_3_160.Suite);
RegisterTest(TTestHaval_4_160.Suite);
RegisterTest(TTestHaval_5_160.Suite);
RegisterTest(TTestHaval_3_192.Suite);
RegisterTest(TTestHaval_4_192.Suite);
RegisterTest(TTestHaval_5_192.Suite);
RegisterTest(TTestHaval_3_224.Suite);
RegisterTest(TTestHaval_4_224.Suite);
RegisterTest(TTestHaval_5_224.Suite);
RegisterTest(TTestHaval_3_256.Suite);
RegisterTest(TTestHaval_4_256.Suite);
RegisterTest(TTestHaval_5_256.Suite);
RegisterTest(TTestMD2.Suite);
RegisterTest(TTestMD4.Suite);
RegisterTest(TTestMD5.Suite);
RegisterTest(TTestPanama.Suite);
RegisterTest(TTestRadioGatun32.Suite);
RegisterTest(TTestRadioGatun64.Suite);
RegisterTest(TTestRIPEMD.Suite);
RegisterTest(TTestRIPEMD128.Suite);
RegisterTest(TTestRIPEMD160.Suite);
RegisterTest(TTestRIPEMD256.Suite);
RegisterTest(TTestRIPEMD320.Suite);
RegisterTest(TTestSHA0.Suite);
RegisterTest(TTestSHA1.Suite);
RegisterTest(TTestSHA2_224.Suite);
RegisterTest(TTestSHA2_256.Suite);
RegisterTest(TTestSHA2_384.Suite);
RegisterTest(TTestSHA2_512.Suite);
RegisterTest(TTestSHA2_512_224.Suite);
RegisterTest(TTestSHA2_512_256.Suite);
RegisterTest(TTestSHA3_224.Suite);
RegisterTest(TTestSHA3_256.Suite);
RegisterTest(TTestSHA3_384.Suite);
RegisterTest(TTestSHA3_512.Suite);
RegisterTest(TTestShake_128.Suite);
RegisterTest(TTestShake_256.Suite);
RegisterTest(TTestKeccak_224.Suite);
RegisterTest(TTestKeccak_256.Suite);
RegisterTest(TTestKeccak_288.Suite);
RegisterTest(TTestKeccak_384.Suite);
RegisterTest(TTestKeccak_512.Suite);
RegisterTest(TTestBlake2B.Suite);
RegisterTest(TTestBlake2S.Suite);
RegisterTest(TTestSnefru_8_128.Suite);
RegisterTest(TTestSnefru_8_256.Suite);
RegisterTest(TTestTiger_3_128.Suite);
RegisterTest(TTestTiger_4_128.Suite);
RegisterTest(TTestTiger_5_128.Suite);
RegisterTest(TTestTiger_3_160.Suite);
RegisterTest(TTestTiger_4_160.Suite);
RegisterTest(TTestTiger_5_160.Suite);
RegisterTest(TTestTiger_3_192.Suite);
RegisterTest(TTestTiger_4_192.Suite);
RegisterTest(TTestTiger_5_192.Suite);
RegisterTest(TTestTiger2_3_128.Suite);
RegisterTest(TTestTiger2_4_128.Suite);
RegisterTest(TTestTiger2_5_128.Suite);
RegisterTest(TTestTiger2_3_160.Suite);
RegisterTest(TTestTiger2_4_160.Suite);
RegisterTest(TTestTiger2_5_160.Suite);
RegisterTest(TTestTiger2_3_192.Suite);
RegisterTest(TTestTiger2_4_192.Suite);
RegisterTest(TTestTiger2_5_192.Suite);
RegisterTest(TTestWhirlPool.Suite);
{$ENDIF FPC}

end.
