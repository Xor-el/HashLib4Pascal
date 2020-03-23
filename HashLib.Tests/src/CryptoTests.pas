unit CryptoTests;

interface

uses
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
  HlpIBlake2BParams,
  HlpBlake2BParams,
  HlpIBlake2SParams,
  HlpBlake2SParams,
  HlpBlake3,
  HlpHashLibTypes,
  TestVectors;

// Crypto
type
  TTestGost = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestGOST3411_2012_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestGOST3411_2012_512 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestGrindahl256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestGrindahl512 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type

  TTestHAS160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_3_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_4_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_5_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_3_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_4_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_5_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_3_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_4_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_5_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_3_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_4_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_5_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_3_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_4_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestHaval_5_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMD2 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMD4 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestMD5 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestPanama = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRadioGatun32 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRadioGatun64 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRIPEMD = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRIPEMD128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRIPEMD160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRIPEMD256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestRIPEMD320 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA0 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA1 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_384 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_512 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_512_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA2_512_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA3_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA3_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA3_384 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSHA3_512 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestShake_128 = class(TShakeAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestShake_256 = class(TShakeAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestCShake_128 = class(TCShakeAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestCShake_256 = class(TCShakeAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSnefru_8_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestSnefru_8_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_3_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_4_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_5_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_3_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_4_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_5_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_3_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_4_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger_5_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_3_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_4_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_5_128 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_3_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_4_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_5_160 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_3_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_4_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestTiger2_5_192 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestWhirlPool = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBlake2B = class(TBlakeCryptoAlgorithmTestCase)

  private

    const
    // https://docs.python.org/3/library/hashlib.html#tree-mode
    Blake2BTreeHashingMode =
      '3AD2A9B37C6070E374C7A8C508FE20CA86B6ED54E286E93A0318E95E881DB5AA';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestNullKeyVsUnKeyed;
    // https://docs.python.org/3/library/hashlib.html#tree-mode
    procedure TestBlake2BTreeHashingMode;

  end;

type
  TTestBlake2S = class(TBlakeCryptoAlgorithmTestCase)

  private

    const
    // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
    Blake2STreeHashingMode = 'C81CD326CA1CA6F40E090A9D9E738892';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestNullKeyVsUnKeyed;
    // https://docs.python.org/3/library/hashlib.html#tree-mode modified for Blake2s
    procedure TestBlake2STreeHashingMode;

  end;

type
  TTestBlake3 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBlake2XS = class(TXofAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCheckTestVectors();

  end;

type
  TTestBlake2XB = class(TXofAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCheckTestVectors();

  end;

type
  TTestBlake3XOF = class(TXofAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestCheckTestVectors();

  end;

type
  TTestKeccak_224 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestKeccak_256 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestKeccak_288 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestKeccak_384 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestKeccak_512 = class(TCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestKMAC = class(THashLibAlgorithmTestCase)

  protected

    const
    RawKeyInHex =
      '404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F';
    CustomizationMessage: String = 'My Tagged Application';

  var
    FData: String;

  end;

type
  TTestKMAC128 = class(TTestKMAC)

  private

    const
    OutputSizeInBits = UInt64(32 * 8);

    procedure DoComputeKMAC128(const AKey, ACustomization, AData,
      AExpectedResult: String; AOutputSizeInBits: UInt64; IsXOF: Boolean);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestKMAC128NISTSample1;
    procedure TestKMAC128NISTSample2;
    procedure TestKMAC128NISTSample3;
    procedure TestKMAC128XOFNISTSample1;
    procedure TestKMAC128XOFNISTSample2;
    procedure TestKMAC128XOFNISTSample3;

  end;

type
  TTestKMAC256 = class(TTestKMAC)

  private

    const
    OutputSizeInBits = UInt64(64 * 8);

    procedure DoComputeKMAC256(const AKey, ACustomization, AData,
      AExpectedResult: String; AOutputSizeInBits: UInt64; IsXOF: Boolean);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestKMAC256NISTSample1;
    procedure TestKMAC256NISTSample2;
    procedure TestKMAC256NISTSample3;
    procedure TestKMAC256XOFNISTSample1;
    procedure TestKMAC256XOFNISTSample2;
    procedure TestKMAC256XOFNISTSample3;

  end;

type
  TTestBlake2BMAC = class(THashLibAlgorithmTestCase)

  private

    procedure DoComputeBlake2BMAC(const AKey, APersonalisation, ASalt, AData,
      AExpectedResult: String; AOutputSizeInBits: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBlake2BMACSample1;
    procedure TestBlake2BMACSample2;
    procedure TestBlake2BMACSample3;

  end;

type
  TTestBlake2SMAC = class(THashLibAlgorithmTestCase)

  private

    procedure DoComputeBlake2SMAC(const AKey, APersonalisation, ASalt, AData,
      AExpectedResult: String; AOutputSizeInBits: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestBlake2SMACSample1;
    procedure TestBlake2SMACSample2;
    procedure TestBlake2SMACSample3;

  end;

type
  TTestBlake2BP = class(TBlakeCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

type
  TTestBlake2SP = class(TBlakeCryptoAlgorithmTestCase)

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  end;

implementation

// Crypto

{ TTestGost }

procedure TTestGost.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateGost();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'CE85B99CC46752FFFEE35CAB9A7B0278ABB4C2D2055CFF685AF4912C49490F8D';
  HashOfDefaultData :=
    '21DCCFBF20D313170333BA15596338FB5964267328EB42CA10E269B7045FF856';
  HashOfOnetoNine :=
    '264B4E433DEE474AEC465FA9C725FE963BC4B4ABC4FDAC63B7F73B671663AFC9';
  HashOfABCDE :=
    'B18CFD04F92DC1D83325036BC723D36DB25EDE41AE879D2545FC7F377B700899';
  HashOfDefaultDataHMACWithShortKey :=
    '6E4E2895E194BEB0A083B1DED6C4084F5E7F37BAAB988D288D9707235F2F8294';
  HashOfDefaultDataHMACWithLongKey :=
    'DE9D68F7793C829E7369AC09493A7749B2637A7B1D572A70549936E09F2D1D82';
end;

procedure TTestGost.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestGrindahl256 }

procedure TTestGrindahl256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateGrindahl256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '45A7600159AF54AE110FCB6EA0F38AD57875EAC814F74D2CBC247D28C89923E6';
  HashOfDefaultData :=
    'AC72E90B0F3F5864A0AF3C43E2A73E393DEBF22AB81B6786ADE22B4517DAAAB6';
  HashOfOnetoNine :=
    'D2460846C5FE9E4750985CC9244D2458BEFD884435121FE56528022A3C7605B7';
  HashOfABCDE :=
    '5CDA73422F36E41087795BB6C21D577BAAF114E4A6CCF33D919E700EE2489FE2';
  HashOfDefaultDataHMACWithShortKey :=
    '65BA6F8EFA5B566D556EC8E3A2EC67DB7EE9BDEE663F17A8B8E7FAD067481023';
  HashOfDefaultDataHMACWithLongKey :=
    '02D964EE346B0C333CEC0F5D7E68C5CFAAC1E3CB0C06FE36418E17AA3AFCA2BE';
end;

procedure TTestGrindahl256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestGrindahl512 }

procedure TTestGrindahl512.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateGrindahl512();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'EE0BA85F90B6D232430BA43DD0EDD008462591816962A355602ED214FAAE54A9A4607D6F577CE950421FF58AEA53F51A7A9F5CCA894C3776104D43568FEA1207';
  HashOfDefaultData :=
    '540F3C6A5070DA391BBA7121DB8F8745752D3515164498FC82CB5B4D837632CF3F256D85C4A0B7F34A86936FAB07BDA2DF2BFDD59AFDBD901E1347C2001DB1AD';
  HashOfOnetoNine :=
    '6845F20B8A9DB083F307844506D342ED0FEE0D16BAF64B22E6C07552CB8C907E936FEDCD885B72C1B05813F722B5706C112AD59D3421CFD88CAA1CFB40EF1BEF';
  HashOfABCDE :=
    'F282C47F31831EAB58B8EE9D1EEE3B9B5A6A86354EEFE84CA3176BED5AB447E6D5AC82316F2D6FAAD350848E2D418336A57772D96311DA8BC51C93087204C6A5';
  HashOfDefaultDataHMACWithShortKey :=
    '7F067A454A4F6300982CAE37900171C627992A75A5567E0D3A51BC6672F79C5AC0CEF5978E933B713F38494DDF26114994C47689AC93EEC9B8EF7892C3B24087';
  HashOfDefaultDataHMACWithLongKey :=
    '59A3F868AE1844BA9B683760D62C73E6E254BE6F46DF923F45118F32E9E1AB80A9056AA8A4792F0D6B8C709919C0ACC64EF64FC013C919758841AE6026F47E61';
end;

procedure TTestGrindahl512.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHAS160 }

procedure TTestHAS160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHAS160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '307964EF34151D37C8047ADEC7AB50F4FF89762D';
  HashOfDefaultData := '2773EDAC4501514254D7B1DF091D6B7652250A52';
  HashOfOnetoNine := 'A0DA48CCD36C9D24AA630D4B3673525E9109A83C';
  HashOfABCDE := 'EEEA94C2F0450B639BC2ACCAF4AEB172A5885313';
  HashOfDefaultDataHMACWithShortKey :=
    '53970A7AC510A85D0E22FF506FED5B57188A8B3F';
  HashOfDefaultDataHMACWithLongKey :=
    '7D2F0051F2BD817A4C27F126882353BCD300B7CA';
end;

procedure TTestHAS160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_3_128 }

procedure TTestHaval_3_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_3_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'C68F39913F901F3DDF44C707357A7D70';
  HashOfDefaultData := '04AF7562BA75D5767ADE2A71E4BE33DE';
  HashOfOnetoNine := 'F2F92D4E5CA6B92A5B5FC5AC822C39D2';
  HashOfABCDE := '51D4032478AA59182916E6C111FA79A6';
  HashOfDefaultDataHMACWithShortKey := '9D49ED7B5D42C64F590A164C5D1AAE9F';
  HashOfDefaultDataHMACWithLongKey := 'E5639CDBE9AE8B58DEC50065909624D4';
end;

procedure TTestHaval_3_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_4_128 }

procedure TTestHaval_4_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_4_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'EE6BBF4D6A46A679B3A856C88538BB98';
  HashOfDefaultData := 'C815192C498CF266D0EB32E90D60892E';
  HashOfOnetoNine := '52DFE2F3DA02591061B02DBDC1510F1C';
  HashOfABCDE := '61634059D9B8336FEB32CA27533ED284';
  HashOfDefaultDataHMACWithShortKey := '9A0B60DEB9F9FBB2A9DAD87A8C653E72';
  HashOfDefaultDataHMACWithLongKey := '37A443E8FB7DE00C28BCE8D3F47BECE8';
end;

procedure TTestHaval_4_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_5_128 }

procedure TTestHaval_5_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_5_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '184B8482A0C050DCA54B59C7F05BF5DD';
  HashOfDefaultData := 'B335D2DC38EFB9D937B803F7581AF88D';
  HashOfOnetoNine := '8AA1C1CA3A7E4F983654C4F689DE6F8D';
  HashOfABCDE := '11C0532F713332D45D6769376DD6EB3B';
  HashOfDefaultDataHMACWithShortKey := '1D5D93E71FF0B324C54ADD1FBDE1F4E4';
  HashOfDefaultDataHMACWithLongKey := 'AB287584D5D67B006986F039321FBA2F';
end;

procedure TTestHaval_5_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_3_160 }

procedure TTestHaval_3_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_3_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'D353C3AE22A25401D257643836D7231A9A95F953';
  HashOfDefaultData := '4A5E28CA30029D2D04287E6C807E74D297A7FC74';
  HashOfOnetoNine := '39A83AF3293CDAC04DE1DF3D0BE7A1F9D8AAB923';
  HashOfABCDE := '8D7C2218BDD8CB0608BA2479751B44BB15F1FC1F';
  HashOfDefaultDataHMACWithShortKey :=
    'E686A2E785EA222FA28911D9243567EB72362D3C';
  HashOfDefaultDataHMACWithLongKey :=
    'B42F2273A6220C65B5ADAE1A9A1188B9D4398D2A';
end;

procedure TTestHaval_3_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_4_160 }

procedure TTestHaval_4_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_4_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '1D33AAE1BE4146DBAACA0B6E70D7A11F10801525';
  HashOfDefaultData := '9E86A9E2D964CCF9019593C88F40AA5C725E0912';
  HashOfOnetoNine := 'B03439BE6F2A3EBED93AC86846D029D76F62FD99';
  HashOfABCDE := 'F74B326FE2CE8F5BA151B85B16E67B28FE71F131';
  HashOfDefaultDataHMACWithShortKey :=
    '6FEAC0105DA74AEDC8FA76A1CF0848C8CA94BA28';
  HashOfDefaultDataHMACWithLongKey :=
    'E7969DB764172896F2467CF74F62BBE231E2772D';
end;

procedure TTestHaval_4_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_5_160 }

procedure TTestHaval_5_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_5_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '255158CFC1EED1A7BE7C55DDD64D9790415B933B';
  HashOfDefaultData := 'A9AB9AB152BB4413B717228C3A65E75644542A35';
  HashOfOnetoNine := '11F592B3A1A1A9C0F9C638C33B69E442D06C1D99';
  HashOfABCDE := '53734616DD6761E2A1D2BD520035287972625385';
  HashOfDefaultDataHMACWithShortKey :=
    'A0FFFE2DE177281E64C5D0A9DC81BFFDF14F6031';
  HashOfDefaultDataHMACWithLongKey :=
    'EF034569FB10312F89F3FC09DDD9AA5C783A7E21';
end;

procedure TTestHaval_5_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_3_192 }

procedure TTestHaval_3_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_3_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'E9C48D7903EAF2A91C5B350151EFCB175C0FC82DE2289A4E';
  HashOfDefaultData := '4235822851EB1B63D6B1DB56CF18EBD28E0BC2327416D5D1';
  HashOfOnetoNine := '6B92F078E73AF2E0F9F049FAA5016D32173A3D62D2F08554';
  HashOfABCDE := '4A106D88931B60DF1BA352782141C473E79019022D65D7A5';
  HashOfDefaultDataHMACWithShortKey :=
    '3E72C9200EAA6ED8D2EF60B8773BAF147A94E98A1FF4E70B';
  HashOfDefaultDataHMACWithLongKey :=
    'AE216E5FA60AE76305DA19EE908FA0531FFE52BCC6A2AB5F';
end;

procedure TTestHaval_3_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_4_192 }

procedure TTestHaval_4_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_4_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4A8372945AFA55C7DEAD800311272523CA19D42EA47B72DA';
  HashOfDefaultData := '54D4FD0DE4228D55F826B627A128A765378B1DC1F8E6CD75';
  HashOfOnetoNine := 'A5C285EAD0FF2F47C15C27B991C4A3A5007BA57137B18D07';
  HashOfABCDE := '88A58D9011CA363A3F3CD113FFEAA44870C07CC14E94FB1B';
  HashOfDefaultDataHMACWithShortKey :=
    '8AB3C2ED5E17CC15EE9D0740185BFFC53C054BC71B9A44AA';
  HashOfDefaultDataHMACWithLongKey :=
    'F5C16DFD598655201E6C636B363484FFAED4CCA27F3366A1';
end;

procedure TTestHaval_4_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_5_192 }

procedure TTestHaval_5_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_5_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4839D0626F95935E17EE2FC4509387BBE2CC46CB382FFE85';
  HashOfDefaultData := 'ED197F026B20DB6362CBC62BDD28E0B34F1E287966D84E3B';
  HashOfOnetoNine := 'EC32312AA79775539675C9BA83D079FFC7EA498FA6173A46';
  HashOfABCDE := 'CDDF16E273A09E9E2F1D7D4761C2D35E1DD6EE327F1F5AFD';
  HashOfDefaultDataHMACWithShortKey :=
    'AB2C407C403A82EEADF2A0B3F4B66B34A12322159E7A95B6';
  HashOfDefaultDataHMACWithLongKey :=
    'C28A804383403F608CB4A6473BCAF744CF25E62AF28C5934';
end;

procedure TTestHaval_5_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_3_224 }

procedure TTestHaval_3_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_3_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'C5AAE9D47BFFCAAF84A8C6E7CCACD60A0DD1932BE7B1A192B9214B6D';
  HashOfDefaultData :=
    '12B7BFA1D36D0163E876A1474EB33CF5BC24C1BBBB181F28ACEE8D36';
  HashOfOnetoNine := '28E8CC65356B43ACBED4DD70F11D0827F17C4442D323AAA0A0DE285F';
  HashOfABCDE := '177DA8770D5BF50E1B5D82DD60DF2635102D490D86F876E70F7A4080';
  HashOfDefaultDataHMACWithShortKey :=
    '2C403CCE41533900919919CA9B8A637AEC0A1E1F7FA154F978592B6B';
  HashOfDefaultDataHMACWithLongKey :=
    '64F21A46C5B17F4AAD8C28F970428BAA00C4096132369A7E5C0B2F67';
end;

procedure TTestHaval_3_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_4_224 }

procedure TTestHaval_4_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_4_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '3E56243275B3B81561750550E36FCD676AD2F5DD9E15F2E89E6ED78E';
  HashOfDefaultData :=
    'DA7AB9D08D42C1819C04C7064891DB700DD05C960C3192CB615758B0';
  HashOfOnetoNine := '9A08D0CF1D52BB1AC22F6421CFB902E700C4C496B3E990F4606F577D';
  HashOfABCDE := '3EEF5DC9C3B3DE0F142DB08B89C21A1FDB1C64D7B169425DBA161190';
  HashOfDefaultDataHMACWithShortKey :=
    '334328027BA2D8F218F8BF374853252D3150FA774D0CBD6F674AEFE0';
  HashOfDefaultDataHMACWithLongKey :=
    '462C126C107ADA83089EB66168831EB6804BA6062EC8D049B9B47D2B';
end;

procedure TTestHaval_4_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_5_224 }

procedure TTestHaval_5_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_5_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4A0513C032754F5582A758D35917AC9ADF3854219B39E3AC77D1837E';
  HashOfDefaultData :=
    'D5FEA825ED7B8CBF23938425BAFDBEE9AD127A685EFCA4559BD54892';
  HashOfOnetoNine := '2EAADFB8007D9A4D8D7F21182C2913D569F801B44D0920D4CE8A01F0';
  HashOfABCDE := 'D8CBE8D06DC58095EC0E69F1C1A4D4A90893AAE80401779CEB6646A9';
  HashOfDefaultDataHMACWithShortKey :=
    '12B6415C63F4BBA34F0ADD23EEB74AC7EE8A07420D652BF619B9E9D1';
  HashOfDefaultDataHMACWithLongKey :=
    '1DD7A2CF3F32F5C447F50D5A3F6B9C421B243E310C3C292581F95447';
end;

procedure TTestHaval_5_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_3_256 }

procedure TTestHaval_3_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_3_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '4F6938531F0BC8991F62DA7BBD6F7DE3FAD44562B8C6F4EBF146D5B4E46F7C17';
  HashOfDefaultData :=
    '9AA25FF9D7559F108E01014C27EBEEA34E8D82BD1A6105D28A53791B74C4C024';
  HashOfOnetoNine :=
    '63E8D0AEEC87738F1E820294CBDF7961CD2246B3620B4BAC81BE0B9827D612C7';
  HashOfABCDE :=
    '3913AB70F6219EEFE10B202DE5991EFDBC4A808203BD60BBFBFC043383AE8F90';
  HashOfDefaultDataHMACWithShortKey :=
    '7E24B475617096B102F0F64572E297144B35683476D1768CB35C0E0A43A6BF8F';
  HashOfDefaultDataHMACWithLongKey :=
    'A587C118D2A575F91A7D3986F0893A32F8DBE13218D4B3CDB93DD0B7566E5003';
end;

procedure TTestHaval_3_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_4_256 }

procedure TTestHaval_4_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_4_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'C92B2E23091E80E375DADCE26982482D197B1A2521BE82DA819F8CA2C579B99B';
  HashOfDefaultData :=
    'B5E97F406CBD4C36CC549072713E733EE31A5F9F23DD6C5982D3A239A9B38434';
  HashOfOnetoNine :=
    'DDC95DF473DD169456484BEB4B04EDCA83A5572D9D7ECCD00092365AE4EF8D79';
  HashOfABCDE :=
    '8F9B46785E52C6C48A0178EDC66D3C23C220D15E52C3C8A13E1CD45D21369193';
  HashOfDefaultDataHMACWithShortKey :=
    'FD0122B375A581D3F06DB6EB992F9A3F46657091E427BB8BD247D835CC086437';
  HashOfDefaultDataHMACWithLongKey :=
    'ED5D88C730ED3EB103DDE96AD42DA60825A9B8B0D8BD2ED580EBF92B851B12E7';
end;

procedure TTestHaval_4_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestHaval_5_256 }

procedure TTestHaval_5_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateHaval_5_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'BE417BB4DD5CFB76C7126F4F8EEB1553A449039307B1A3CD451DBFDC0FBBE330';
  HashOfDefaultData :=
    'E5061D6F4F8645262C5C923F8E607CD77D69CE772E3DE559132B460309BFB516';
  HashOfOnetoNine :=
    '77FD61460DB5F89DEFC9A9296FAB68A1730EA6C9C0037A9793DAC8492C0A953C';
  HashOfABCDE :=
    'C464C9A669D5B43E4C34808114DCE4ECC732D1B71407E7F05468D0B15BFF7E30';
  HashOfDefaultDataHMACWithShortKey :=
    'C702F985817A2596D7E0BB073D71DFEF72D77BD45599DD4F7E5D83A8EAF7268B';
  HashOfDefaultDataHMACWithLongKey :=
    '267B5C9F0A093726E47541C8F1DEADD400AD9AEE0145A59FBD5A18BA2877101E';
end;

procedure TTestHaval_5_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestMD2 }

procedure TTestMD2.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateMD2();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '8350E5A3E24C153DF2275C9F80692773';
  HashOfDefaultData := 'DFBE28FF5A3C23CAA85BE5848F16524E';
  HashOfOnetoNine := '12BD4EFDD922B5C8C7B773F26EF4E35F';
  HashOfABCDE := 'DFF9959487649F5C7AF5D0680A9A5D22';
  HashOfDefaultDataHMACWithShortKey := 'C5F4625462CD5CF7723C19E8566F6790';
  HashOfDefaultDataHMACWithLongKey := '03D7546FEADF29A91CEB40290A27E081';
end;

procedure TTestMD2.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestMD4 }

procedure TTestMD4.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateMD4();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '31D6CFE0D16AE931B73C59D7E0C089C0';
  HashOfDefaultData := 'A77EAB8C3432FD9DD1B87C3C5C2E9C3C';
  HashOfOnetoNine := '2AE523785D0CAF4D2FB557C12016185C';
  HashOfABCDE := '9803F4A34E8EB14F96ADBA49064A0C41';
  HashOfDefaultDataHMACWithShortKey := 'BF21F9EC05E480EEDB12AF20181713E3';
  HashOfDefaultDataHMACWithLongKey := '7E30F4DA95992DBA450E345641DE5CEC';
end;

procedure TTestMD4.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestMD5 }

procedure TTestMD5.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateMD5();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'D41D8CD98F00B204E9800998ECF8427E';
  HashOfDefaultData := '462EC1E50C8F2D5C387682E98F9BC842';
  HashOfOnetoNine := '25F9E794323B453885F5181F1B624D0B';
  HashOfABCDE := 'AB56B4D92B40713ACC5AF89985D4B786';
  HashOfDefaultDataHMACWithShortKey := '09F705F43799213192622CCA6DF68941';
  HashOfDefaultDataHMACWithLongKey := '696D0706C43816B551D874B9B3E4B7E6';
end;

procedure TTestMD5.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestPanama }

procedure TTestPanama.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreatePanama();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'AA0CC954D757D7AC7779CA3342334CA471ABD47D5952AC91ED837ECD5B16922B';
  HashOfDefaultData :=
    '69A05A5A5DDB32F5589257458BBDD059FB30C4486C052D81029DDB2864E90813';
  HashOfOnetoNine :=
    '3C83D2C9109DE4D1FA64833683A7C280591A7CFD8516769EA879E56A4AD39B99';
  HashOfABCDE :=
    'B064E5476A3F511105B75305FC2EC31578A6B200FB5084CF937C179F1C52A891';
  HashOfDefaultDataHMACWithShortKey :=
    '3C15C9B7CDC77470BC02CA96711B66FAA976AC2044F6F177ABCA93B1442EA376';
  HashOfDefaultDataHMACWithLongKey :=
    '93226A060B4A82D1D9FBEE6B78424F8E3E871BE7DA77A9D17D5C78D5F415E631';
end;

procedure TTestPanama.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRadioGatun32 }

procedure TTestRadioGatun32.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRadioGatun32();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'F30028B54AFAB6B3E55355D277711109A19BEDA7091067E9A492FB5ED9F20117';
  HashOfDefaultData :=
    '17B20CF19B3FC84FD2FFE084F07D4CD4DBBC50E41048D8259EB963B0A7B9C784';
  HashOfOnetoNine :=
    'D77629174F56D8451F73CBE80EC7A20EF2DD65C46A1480CD004CBAA96F3FA1FD';
  HashOfABCDE :=
    'A593059B12513A1BD88A2D433F07B239BC14743AF0FF7294837B5DF756BF9C7A';
  HashOfDefaultDataHMACWithShortKey :=
    '72EB7D36180C1B1BBF88E062FEC7419DBB4849892623D332821C1B0D71D6D513';
  HashOfDefaultDataHMACWithLongKey :=
    'CD48D590665EA2C066A0C26E2620D567C75090DE38045B88C53BFAE685D67886';
end;

procedure TTestRadioGatun32.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRadioGatun64 }

procedure TTestRadioGatun64.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRadioGatun64();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '64A9A7FA139905B57BDAB35D33AA216370D5EAE13E77BFCDD85513408311A584';
  HashOfDefaultData :=
    '43B3208CE2E6B23D985087A84BD583F713A9002280BF2785B1EE569B12C15054';
  HashOfOnetoNine :=
    '76A565017A42B258F5C8C9D2D9FD4C7347947A659ED142FF61C1BEA592F103C5';
  HashOfABCDE :=
    '36B4DD23A97424844662E882AD1DA1DBAD8CB435A57F380455393C9FF9DE9D37';
  HashOfDefaultDataHMACWithShortKey :=
    'FA280F80C1323C32AACC7F1CAB3808FE2BB8880F901AE6F03BD14D6D1884B267';
  HashOfDefaultDataHMACWithLongKey :=
    'B9CBBB9FE06144CF5E369BDBBCB2C76EBBE8904061C356BA9A06FE2D96E4037F';
end;

procedure TTestRadioGatun64.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRIPEMD }

procedure TTestRIPEMD.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRIPEMD();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '9F73AA9B372A9DACFB86A6108852E2D9';
  HashOfDefaultData := 'B3F629A9786744AA105A2C150869C236';
  HashOfOnetoNine := 'C905B44C6429AD0A1934550037D4816F';
  HashOfABCDE := '68D2362617E85CF1BF7381DF14045DBB';
  HashOfDefaultDataHMACWithShortKey := '219ACFCF07BDB775FBA73DACE1E97E08';
  HashOfDefaultDataHMACWithLongKey := 'B06D09CE5452ADEEADF468E00DAC5C8B';
end;

procedure TTestRIPEMD.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRIPEMD128 }

procedure TTestRIPEMD128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRIPEMD128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'CDF26213A150DC3ECB610F18F6B38B46';
  HashOfDefaultData := '75891B00B2874EDCAF7002CA98264193';
  HashOfOnetoNine := '1886DB8ACDCBFEAB1E7EE3780400536F';
  HashOfABCDE := 'A0A954BE2A779BFB2129B72110C5782D';
  HashOfDefaultDataHMACWithShortKey := 'BA844D13A1215E20634A49D5599197EF';
  HashOfDefaultDataHMACWithLongKey := 'E93930A64EF6807C4D80EF30DF86AFA7';
end;

procedure TTestRIPEMD128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRIPEMD160 }

procedure TTestRIPEMD160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRIPEMD160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '9C1185A5C5E9FC54612808977EE8F548B2258D31';
  HashOfDefaultData := '0B8EAC9A2EA1E267750CE639D83A84B92631462B';
  HashOfOnetoNine := 'D3D0379126C1E5E0BA70AD6E5E53FF6AEAB9F4FA';
  HashOfABCDE := '973398B6E6C6CFA6B5E6A5173F195CE3274BF828';
  HashOfDefaultDataHMACWithShortKey :=
    '76D728D9BF39ED42E0C451A9526E3F0D929F067D';
  HashOfDefaultDataHMACWithLongKey :=
    '4C373970BDB829BE3B6E0B2D9F510E9C35C9B583';
end;

procedure TTestRIPEMD160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRIPEMD256 }

procedure TTestRIPEMD256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRIPEMD256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '02BA4C4E5F8ECD1877FC52D64D30E37A2D9774FB1E5D026380AE0168E3C5522D';
  HashOfDefaultData :=
    '95EF1FFAB0EF6229F58CAE347426ADE3C412BCEB1057DAED0062BBDEE4BEACC6';
  HashOfOnetoNine :=
    '6BE43FF65DD40EA4F2FF4AD58A7C1ACC7C8019137698945B16149EB95DF244B7';
  HashOfABCDE :=
    '81D8B58A3110A9139B4DDECCB031409E8AF023067CF4C6F0B701DAB9ECC0EB4E';
  HashOfDefaultDataHMACWithShortKey :=
    'D59B820A708FA31C39BD33BA88CB9A25516A3BA2BA99A74223FCE0EC0F9BFB1B';
  HashOfDefaultDataHMACWithLongKey :=
    'F1149704222B7ABA1F9C14B0E9A67909C53605E07614CF8C47CB357083EA3A6B';
end;

procedure TTestRIPEMD256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestRIPEMD320 }

procedure TTestRIPEMD320.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateRIPEMD320();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '22D65D5661536CDC75C1FDF5C6DE7B41B9F27325EBC61E8557177D705A0EC880151C3A32A00899B8';
  HashOfDefaultData :=
    '004A1899CCA02BFD4055129304D55F364E35F033BB74B784AFC93F7268291D8AF84F2C64C5CCACD0';
  HashOfOnetoNine :=
    '7E36771775A8D279475D4FD76B0C8E412B6AD085A0002475A148923CCFA5D71492E12FA88EEAF1A9';
  HashOfABCDE :=
    'A94DC1BC825DB64E97718305CE36BFEF32CC5410A630999678BCD89CC38C424269012EC8C5A95830';
  HashOfDefaultDataHMACWithShortKey :=
    '4D3DFCCB43E5A60611A850C2141086CB16752505BA12E1B7953EA8859CB1E1DF3A698562A46DB41C';
  HashOfDefaultDataHMACWithLongKey :=
    '248D14ED08F0F49D175F4DC487A64B81F06D78077D1CF975BBE5D47627995990EBE45E6B7EDF9362';
end;

procedure TTestRIPEMD320.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA0 }

procedure TTestSHA0.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA0();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'F96CEA198AD1DD5617AC084A3D92C6107708C0EF';
  HashOfDefaultData := 'C9CBBE593DE122CA36B13CC37FE2CA8D5606FEED';
  HashOfOnetoNine := 'F0360779D2AF6615F306BB534223CF762A92E988';
  HashOfABCDE := 'D624E34951BB800F0ACAE773001DF8CFFE781BA8';
  HashOfDefaultDataHMACWithShortKey :=
    'EAA73E85DCAC5BAD0A0E71C0695F901FC32DB38A';
  HashOfDefaultDataHMACWithLongKey :=
    'CDA87167A558311B9154F372F21A453030BBE16A';
end;

procedure TTestSHA0.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA1 }

procedure TTestSHA1.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA1();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709';
  HashOfDefaultData := 'C8389876E94C043C47BA4BFF3D359884071DC310';
  HashOfOnetoNine := 'F7C3BC1D808E04732ADF679965CCC34CA7AE3441';
  HashOfABCDE := '03DE6C570BFE24BFC328CCD7CA46B76EADAF4334';
  HashOfDefaultDataHMACWithShortKey :=
    'CD409025AA5F34ABDC660856463155B23C89B16A';
  HashOfDefaultDataHMACWithLongKey :=
    'E70699720F4222E3A4A4474F14F13CBC3316D9B2';
end;

procedure TTestSHA1.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_224 }

procedure TTestSHA2_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F';
  HashOfDefaultData :=
    'DF2B86ED008508F542443C4B1810AA5A0F5658692B808EEB1D0A2F7E';
  HashOfOnetoNine := '9B3E61BF29F17C75572FAE2E86E17809A4513D07C8A18152ACF34521';
  HashOfABCDE := 'BDD03D560993E675516BA5A50638B6531AC2AC3D5847C61916CFCED6';
  HashOfDefaultDataHMACWithShortKey :=
    'EC47E83DB5DD735EBB7AA4A898460950B16A3A0FA48E4BB9184EA3D1';
  HashOfDefaultDataHMACWithLongKey :=
    '86855E59D8B09A3C7632D4E176C4B65C549255F417FEF9EEF2D4167D';
end;

procedure TTestSHA2_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_256 }

procedure TTestSHA2_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855';
  HashOfDefaultData :=
    'BCF45544CB98DDAB731927F8760F81821489ED04C0792A4D254134887BEA9E38';
  HashOfOnetoNine :=
    '15E2B0D3C33891EBB0F1EF609EC419420C20E320CE94C65FBC8C3312448EB225';
  HashOfABCDE :=
    '36BBE50ED96841D10443BCB670D6554F0A34B761BE67EC9C4A8AD2C0C44CA42C';
  HashOfDefaultDataHMACWithShortKey :=
    '92678A1C746AAEAA1D3F0C9DAC4BCA73801D278B51C1F6861D49C9A2C1175687';
  HashOfDefaultDataHMACWithLongKey :=
    'BC05A7D3B13A4A67445C62389564D35B18F33A0C6408EC8DA0CB2506AE6E2D14';
end;

procedure TTestSHA2_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_384 }

procedure TTestSHA2_384.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_384();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B';
  HashOfDefaultData :=
    '05D165ADA4A6F9F550CB6F9A0E00401E628B302FA5D7F3824361768758421F83102AC611B2710F5168579CFB11942869';
  HashOfOnetoNine :=
    'EB455D56D2C1A69DE64E832011F3393D45F3FA31D6842F21AF92D2FE469C499DA5E3179847334A18479C8D1DEDEA1BE3';
  HashOfABCDE :=
    '4C525CBEAC729EAF4B4665815BC5DB0C84FE6300068A727CF74E2813521565ABC0EC57A37EE4D8BE89D097C0D2AD52F0';
  HashOfDefaultDataHMACWithShortKey :=
    '3D6DCED731DAF3599CC0971646C1A8B8CCC61650722F111A9EB26CE7B65189EB220EACB09152D9A09065099FE6C1FDC9';
  HashOfDefaultDataHMACWithLongKey :=
    '162295D136DB47205EDF45BF8687E5599DFA80C6AE79D83C03E729C48D373E19638ADD5B5D603558234DF755404CCF9E';
end;

procedure TTestSHA2_384.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_512 }

procedure TTestSHA2_512.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_512();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E';
  HashOfDefaultData :=
    '0A5DA12B113EBD3DEA4C51FD10AFECF1E2A8EE6C3848A0DD4407141ADDA04375068D85A1EEF980FAFF68DC3BF5B1B3FBA31344178042197B5180BD95530D61AC';
  HashOfOnetoNine :=
    'D9E6762DD1C8EAF6D61B3C6192FC408D4D6D5F1176D0C29169BC24E71C3F274AD27FCD5811B313D681F7E55EC02D73D499C95455B6B5BB503ACF574FBA8FFE85';
  HashOfABCDE :=
    '878AE65A92E86CAC011A570D4C30A7EAEC442B85CE8ECA0C2952B5E3CC0628C2E79D889AD4D5C7C626986D452DD86374B6FFAA7CD8B67665BEF2289A5C70B0A1';
  HashOfDefaultDataHMACWithShortKey :=
    'DEDFCEAD40225068527D0E53B7C892226E188891D939E21A0777A40EA2E29D7233638C178C879F26088A502A887674C01DF61EAF1635D707D114097ED1D0D762';
  HashOfDefaultDataHMACWithLongKey :=
    'FB795F2A85271149E6A6E2668AAF54DB5946DC669C1C8432BED856AEC9A1A461B5FC13FE8AE0861E6A8F53D711FDDF76AC60A5CCC8BA334325FDB9472A7A71F4';
end;

procedure TTestSHA2_512.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_512_224 }

procedure TTestSHA2_512_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_512_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '6ED0DD02806FA89E25DE060C19D3AC86CABB87D6A0DDD05C333B84F4';
  HashOfDefaultData :=
    '7A95749FB7F4489A45275556F5D905D28E1B637DCDD6537336AB6234';
  HashOfOnetoNine := 'F2A68A474BCBEA375E9FC62EAAB7B81FEFBDA64BB1C72D72E7C27314';
  HashOfABCDE := '880E79BB0A1D2C9B7528D851EDB6B8342C58C831DE98123B432A4515';
  HashOfDefaultDataHMACWithShortKey :=
    '9BC318A84B90F7FF55C53E3F4B602EAD13BB579EB1794455B29562B4';
  HashOfDefaultDataHMACWithLongKey :=
    'B932866547894977F6E4C61D137FFC2508C639BA6786F45AC64731C8';
end;

procedure TTestSHA2_512_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA2_512_256 }

procedure TTestSHA2_512_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA2_512_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'C672B8D1EF56ED28AB87C3622C5114069BDD3AD7B8F9737498D0C01ECEF0967A';
  HashOfDefaultData :=
    'E1792BAAAEBFC58E213D0BA628BF2FF22CBA10526075702F7C1727B76BEB107B';
  HashOfOnetoNine :=
    '1877345237853A31AD79E14C1FCB0DDCD3DF9973B61AF7F906E4B4D052CC9416';
  HashOfABCDE :=
    'DE8322B46E78B67D4431997070703E9764E03A1237B896FD8B379ED4576E8363';
  HashOfDefaultDataHMACWithShortKey :=
    '1467239C9D47E1962905D03D7006170A04D05E4508BB47E30AD9481FBDA975FF';
  HashOfDefaultDataHMACWithLongKey :=
    '5EF407B913662BE3D98F5DA20D55C2A45D3F3E4FF771B2C2A482E35F6A757E71';
end;

procedure TTestSHA2_512_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA3_224 }

procedure TTestSHA3_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA3_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7';
  HashOfDefaultData :=
    '1D2BDFB95B0203C2BB7C739D813D69521EC7A3047E3FCA15CD305C95';
  HashOfOnetoNine := '5795C3D628FD638C9835A4C79A55809F265068C88729A1A3FCDF8522';
  HashOfABCDE := '6ACFAAB70AFD8439CEA3616B41088BD81C939B272548F6409CF30E57';
  HashOfDefaultDataHMACWithShortKey :=
    'DA17722BA1E4BD728A83015A83430A67577F283A0EFCB457C327A980';
  HashOfDefaultDataHMACWithLongKey :=
    '38FABCD5E29DE7AD7429BD9124F804FFD340D7B9F77A83DC25EC53B8';
end;

procedure TTestSHA3_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA3_256 }

procedure TTestSHA3_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA3_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A';
  HashOfDefaultData :=
    'C334674D808EBB8B7C2926F043D1CAE78D168A05B70B9210C9167EA6DC300CE2';
  HashOfOnetoNine :=
    '87CD084D190E436F147322B90E7384F6A8E0676C99D21EF519EA718E51D45F9C';
  HashOfABCDE :=
    'D716EC61E18904A8F58679B71CB065D4D5DB72E0E0C3F155A4FEFF7ADD0E58EB';
  HashOfDefaultDataHMACWithShortKey :=
    '1019B70021A038345192F00D02E33FA4AF8949E80AD592C4671A438DCCBCFBDF';
  HashOfDefaultDataHMACWithLongKey :=
    'B8EC49AF4DE71CB0561A9F0DF7B156CC7784AC044F12B65048CE6DBB27A57E66';
end;

procedure TTestSHA3_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA3_384 }

procedure TTestSHA3_384.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA3_384();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE983A2AC3713831264ADB47FB6BD1E058D5F004';
  HashOfDefaultData :=
    '87DD2935CD0DDEFFB8694E70ED1D33EABCEA848BD93A7A7B7227603B7C080A70BCF29FCEED66F456A7FB593EB23F950C';
  HashOfOnetoNine :=
    '8B90EDE4D095409F1A12492C2520599683A9478DC70B7566D23B3E41ECE8538C6CDE92382A5E38786490375C54672ABF';
  HashOfABCDE :=
    '348494236B82EDDA7602C78BA67FC3838E427C63C23E2C9D9AA5EA6354218A3C2CA564679ACABF3AC6BF5378047691C4';
  HashOfDefaultDataHMACWithShortKey :=
    '52A4A926B60AA9F6B7DB1C8F5344A097540A8E2115164BF75734907E88C2BC1F7DD84D0EE8569B9857590A39EB5FF499';
  HashOfDefaultDataHMACWithLongKey :=
    '802D520828C580A61EE4BFA138BE23708C22DB97F94913AF5897E3C9C12BA6C4EC33BFEB79691D2F302315B27674EA40';
end;

procedure TTestSHA3_384.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSHA3_512 }

procedure TTestSHA3_512.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSHA3_512();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26';
  HashOfDefaultData :=
    'FAA213B928B942C521FD2A4B5F918C9AB6479A1DD122B9485440E56E729976D57C5E7C62F65D8453DCAAADA6B79743DB939F22773FD44C9ECD54B4B7FAFDAE33';
  HashOfOnetoNine :=
    'E1E44D20556E97A180B6DD3ED7AE5C465CAFD553FA8747DCA038FB95635B77A37318F7DDF7AEC1F6C3C14BB160BA2497007DECF38DD361CAB199E3B8C8FE1F5C';
  HashOfABCDE :=
    '1D7C3AA6EE17DA5F4AEB78BE968AA38476DBEE54842E1AE2856F4C9A5CD04D45DC75C2902182B07C130ED582D476995B502B8777CCF69F60574471600386639B';
  HashOfDefaultDataHMACWithShortKey :=
    '439C673B33F0F6D9273124782611EA96F1BB62F90672551310C1230ADAAD0D40F63C6D2B17DAFECEFD9CE8848576001D9D68FAD1B9E7DDC146F00CEBE5AFED27';
  HashOfDefaultDataHMACWithLongKey :=
    'ADD449377F25EC360F87B04AE6334D5D7CA90EAF3568D4EBDA3A977B820271952D7D93A7804E29B9791DC19FF7B523E6CCABED180B0B035CCDDA38A7E92DC7E0';
end;

procedure TTestSHA3_512.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestShake_128 }

procedure TTestShake_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateShake_128(128);
  XofInstance := THashFactory.TXOF.CreateShake_128(8000) as IXOF;
  HashOfEmptyData := '7F9C2BA4E88F827D616045507605853E';
  HashOfDefaultData := '10F69AD42A1BDE254004CD13B5176D6D';
  HashOfOnetoNine := '1ACA6B9E651B5F20079A305CA8F86D39';
  HashOfABCDE := '907C1B3F41470218D0DFD8FEDDDA93C1';
  XofOfEmptyData :=
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
end;

procedure TTestShake_128.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  inherited;
end;

{ TTestShake_256 }

procedure TTestShake_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateShake_256(256);
  XofInstance := THashFactory.TXOF.CreateShake_256(8000) as IXOF;
  HashOfEmptyData :=
    '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F';
  HashOfDefaultData :=
    '922279516284A34F384ADA776D3606FBEC97875E716E6EA0FFCF9372AAB696BE';
  HashOfOnetoNine :=
    '24347B9C4B6DA2FC9CDE08C87F33EDD2E603C8DCD6840E6B3920F62B1DD69D7B';
  HashOfABCDE :=
    '98AD79D7ED29F585AD1AFFBC2BB5B5F244917F97CEA8B5424FDC6F7377A22042';
  XofOfEmptyData :=
    '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762FD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE141E96616FB1395'
    + '7692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853349EC75546F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86F3D122109E3B1FDD943B6AEC468A2D'
    + '621A7C06C6A957C62B54DAFC3BE87567D677231395F6147293B68CEAB7A9E0C58D864E8EFDE4E1B9A46CBE854713672F5CAAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8F'
    + 'CF3F3CB53FB8E9EB2EA203BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F5A1AAA96D313EACC890936C173CDCD0FAB882C45755FEB3AED96D47'
    + '7FF96390BF9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DCF722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11F0477DE'
    + '055A81A9EDA57A4A2CFB0C83929D310912F729EC6CFA36C6AC6A75837143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB78F3AC45F8C4AC5671D85735C'
    + 'DDDB09D2B1E34A1FC066FF4A162CB263D6541274AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341EF274BDAB0BAE316339894304E35877B0C28A9B1FD166C796B9CC'
    + '258A064A8F57E27F2A5B8D548A728C9444ECB879ADC19DE0C1B8587DE3E73E15D3CE2DB7C9FA7B58FFC0E87251773FAF3E8F3E3CF1D4DFA723AFD4DA9097CB3C866ACBEFAB2C4E85E1918990'
    + 'FF93E0656B5F75B08729C60E6A9D7352B9EFD2E33E3D1BA6E6D89EDFA671266ECE6BE7BB5AC948B737E41590ABE138CE1869C08680162F08863D174E77E07A9DDB33B57DE04C'
    + '443A5BD77C42036871AAE7893362B27015B84B4139F0E313579B4EF5F6B6426563D7195B8C5B84736B14266160342C4093F8ABEA48371BA94CC06DCB6B8A8E7BCE6354F9BABC949A5F'
    + '18F8C9F0AAEFE0B8BECAD386F078CA41CACF2E3D17F4EC21FED0E3B682435AD5B665C25D7B61B379E86824C2B22D5A54835F8B04D4C0B29667BAEB0C3258809EE698DBC03536A1C'
    + '936C811F6E6F69210F5632080064923FDF9CF405301E45A3F96E3F57C55C4E0B538EFE8942F6B601AC49EA635F70E4BA39E5FCE513CFB672945BB92E17F7D222EAB2AA29BE89FC3F'
    + 'F24BC6B6D7A3D307CE7B1731E7DF59690D0530D7F2F5BB9ED37D180169A6C1BB022252AB8CC6860E3CF1F1414C90A19350B526E3741E500717769CDD09D268CC3F8'
    + '8B5D521C70AA8BBE631FBF08905A0A833D2005830717ADBA3233DD591BC505C7B13A9D5672AD4BE10C744AC33D9E92A23BDEE6E14D470EE7DC142FE4EFF4182A49BEEEC8E4';
end;

procedure TTestShake_256.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  inherited;
end;

{ TTestCShake_128 }

procedure TTestCShake_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateCShake_128(Nil, Nil, 128);
  XofInstance := THashFactory.TXOF.CreateCShake_128(Nil, Nil, 8000) as IXOF;
  XofInstanceShake := THashFactory.TXOF.CreateShake_128(8000) as IXOF;
  XofInstanceTestVector := THashFactory.TXOF.CreateCShake_128(Nil,
    TConverters.ConvertStringToBytes('Email Signature', TEncoding.UTF8),
    128) as IXOF;
  HashOfEmptyData := '7F9C2BA4E88F827D616045507605853E';
  HashOfDefaultData := '10F69AD42A1BDE254004CD13B5176D6D';
  HashOfOnetoNine := '1ACA6B9E651B5F20079A305CA8F86D39';
  HashOfABCDE := '907C1B3F41470218D0DFD8FEDDDA93C1';
  XofOfEmptyData :=
    '7F9C2BA4E88F827D616045507605853ED73B8093F6EFBC88EB1A6EACFA66EF263CB1EEA988004B93103CFB0AEEFD2A686E'
    + '01FA4A58E8A3639CA8A1E3F9AE57E235B8CC873C23DC62B8D260169AFA2F75AB916A58D974918835D25E6A435085B2BADFD6DFAAC359A5EFBB7BCC'
    + '4B59D538DF9A04302E10C8BC1CBF1A0B3A5120EA17CDA7CFAD765F5623474D368CCCA8AF0007CD9F5E4C849F167A580B14AABDEFAEE7EEF47CB0FCA9767BE1FDA69419DFB927E9DF07348B196691ABAEB580B32DEF58538B8D23F87732EA63B02B4FA0F4873360E2841928CD60DD4CEE8CC0D4C922A96188D0326'
    + '75C8AC850933C7AFF1533B94C834ADBB69C6115BAD4692D8619F90B0CDF8A7B9C264029AC185B70B83F2801F2F4B3F70C593EA3AEEB613A7F1B1DE33FD75081F592305F2E4526EDC09631B10958F464D889F31BA010250FDA7F1368EC2967FC84EF2AE9AFF268E0B1700AFFC6820B523A3D917135F2DFF2'
    + 'EE06BFE72B3124721D4A26C04E53A75E30E73A7A9C4A95D91C55D495E9F51DD0B5E9D83C6D5E8CE803AA62B8D654DB53D09B8DCFF273CDFEB573FAD8BCD45578BEC2E770D01EFDE86E721A3F7C6CCE275DABE6E2143'
    + 'F1AF18DA7EFDDC4C7B70B5E345DB93CC936BEA323491CCB38A388F546A9FF00DD4E1300B9B2153D2041D205B443E41B45A653F2A5C4492C1AD'
    + 'D544512DDA2529833462B71A41A45BE97290B6F4CFFDA2CF990051634A4B1EDF6114FB49083C1FA3B302EE097F051266BE69DC716FDEEF91B0D4AB2DE525550BF80DC8A684BC3B5A4D46B7EFAE7AFDC6292988DC9ACAE03F8634486C1ABE2781AAE4C02F3460D2CD4E6A463A2BA956'
    + '2EE623CF0E9F82AB4D0B5C9D040A269366479DFF0038ABFAF2E0FF21F36968972E3F104DDCBE1EB831A87C213162E29B34ADFA564D121E9F6E7729F4203FC5C6C22FA7A7350AFDDB620923A4A129B8ACB19EA10F818C30E3B5B1C571FA79E57EE304388316A02FCD93A0D8EE02BB85701EE4FF09753'
    + '4B502C1B12FBB95C8CCB2F548921D99CC7C9FE17AC991B675E631144423EEF7A5869168DA63D1F4C21F650C02923BFD396CA6A5DB541068624CBC5FFE208C0D1A'
    + '74E1A29618D0BB60036F5249ABFA88898E393718D6EFAB05BB41279EFCD4C5A0CC837CCFC22BE4F725C081F6AA090749DBA7077BAE8D41AF3FEC5A6EE1B8ADCD2'
    + '5E72DE36434584EF567C643D344294E8B2086B87F69C3BDC0D5969857082987CA1C63B7182E86898FB9B8039E75EDA219E289331610369271867B145B2908293963CD677C9A1AE6CEB28289B254CDEB76B12F33CE5CF3743131BFB550F0197BFE16AFF92367227ADC5074FE3DC0D8D116253980A38636BC9D29F79'
    + '9BBB2D76A0A5F138B8C73BA484D6588764E331D70C378C0641F2D9';
  XofOfZeroToOneHundredAndNinetyNineInHex := 'C5221D50E4F822D96A2E8881A961420F';
end;

procedure TTestCShake_128.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  XofInstanceShake := Nil;
  XofInstanceTestVector := Nil;
  inherited;
end;

{ TTestCShake_256 }

procedure TTestCShake_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateCShake_256(Nil, Nil, 256);
  XofInstance := THashFactory.TXOF.CreateCShake_256(Nil, Nil, 8000) as IXOF;
  XofInstanceShake := THashFactory.TXOF.CreateShake_256(8000) as IXOF;
  XofInstanceTestVector := THashFactory.TXOF.CreateCShake_256(Nil,
    TConverters.ConvertStringToBytes('Email Signature', TEncoding.UTF8),
    256) as IXOF;
  HashOfEmptyData :=
    '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762F';
  HashOfDefaultData :=
    '922279516284A34F384ADA776D3606FBEC97875E716E6EA0FFCF9372AAB696BE';
  HashOfOnetoNine :=
    '24347B9C4B6DA2FC9CDE08C87F33EDD2E603C8DCD6840E6B3920F62B1DD69D7B';
  HashOfABCDE :=
    '98AD79D7ED29F585AD1AFFBC2BB5B5F244917F97CEA8B5424FDC6F7377A22042';
  XofOfEmptyData :=
    '46B9DD2B0BA88D13233B3FEB743EEB243FCD52EA62B81B82B50C27646ED5762FD75DC4DDD8C0F200CB05019D67B592F6FC821C49479AB48640292EACB3B7C4BE141E96616FB1395'
    + '7692CC7EDD0B45AE3DC07223C8E92937BEF84BC0EAB862853349EC75546F58FB7C2775C38462C5010D846C185C15111E595522A6BCD16CF86F3D122109E3B1FDD943B6AEC468A2D'
    + '621A7C06C6A957C62B54DAFC3BE87567D677231395F6147293B68CEAB7A9E0C58D864E8EFDE4E1B9A46CBE854713672F5CAAAE314ED9083DAB4B099F8E300F01B8650F1F4B1D8F'
    + 'CF3F3CB53FB8E9EB2EA203BDC970F50AE55428A91F7F53AC266B28419C3778A15FD248D339EDE785FB7F5A1AAA96D313EACC890936C173CDCD0FAB882C45755FEB3AED96D47'
    + '7FF96390BF9A66D1368B208E21F7C10D04A3DBD4E360633E5DB4B602601C14CEA737DB3DCF722632CC77851CBDDE2AAF0A33A07B373445DF490CC8FC1E4160FF118378F11F0477DE'
    + '055A81A9EDA57A4A2CFB0C83929D310912F729EC6CFA36C6AC6A75837143045D791CC85EFF5B21932F23861BCF23A52B5DA67EAF7BAAE0F5FB1369DB78F3AC45F8C4AC5671D85735C'
    + 'DDDB09D2B1E34A1FC066FF4A162CB263D6541274AE2FCC865F618ABE27C124CD8B074CCD516301B91875824D09958F341EF274BDAB0BAE316339894304E35877B0C28A9B1FD166C796B9CC'
    + '258A064A8F57E27F2A5B8D548A728C9444ECB879ADC19DE0C1B8587DE3E73E15D3CE2DB7C9FA7B58FFC0E87251773FAF3E8F3E3CF1D4DFA723AFD4DA9097CB3C866ACBEFAB2C4E85E1918990'
    + 'FF93E0656B5F75B08729C60E6A9D7352B9EFD2E33E3D1BA6E6D89EDFA671266ECE6BE7BB5AC948B737E41590ABE138CE1869C08680162F08863D174E77E07A9DDB33B57DE04C'
    + '443A5BD77C42036871AAE7893362B27015B84B4139F0E313579B4EF5F6B6426563D7195B8C5B84736B14266160342C4093F8ABEA48371BA94CC06DCB6B8A8E7BCE6354F9BABC949A5F'
    + '18F8C9F0AAEFE0B8BECAD386F078CA41CACF2E3D17F4EC21FED0E3B682435AD5B665C25D7B61B379E86824C2B22D5A54835F8B04D4C0B29667BAEB0C3258809EE698DBC03536A1C'
    + '936C811F6E6F69210F5632080064923FDF9CF405301E45A3F96E3F57C55C4E0B538EFE8942F6B601AC49EA635F70E4BA39E5FCE513CFB672945BB92E17F7D222EAB2AA29BE89FC3F'
    + 'F24BC6B6D7A3D307CE7B1731E7DF59690D0530D7F2F5BB9ED37D180169A6C1BB022252AB8CC6860E3CF1F1414C90A19350B526E3741E500717769CDD09D268CC3F8'
    + '8B5D521C70AA8BBE631FBF08905A0A833D2005830717ADBA3233DD591BC505C7B13A9D5672AD4BE10C744AC33D9E92A23BDEE6E14D470EE7DC142FE4EFF4182A49BEEEC8E4';
  XofOfZeroToOneHundredAndNinetyNineInHex :=
    '07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC864302730917';
end;

procedure TTestCShake_256.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  XofInstanceShake := Nil;
  XofInstanceTestVector := Nil;
  inherited;
end;

{ TTestSnefru_8_128 }

procedure TTestSnefru_8_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSnefru_8_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '8617F366566A011837F4FB4BA5BEDEA2';
  HashOfDefaultData := '1EA32485C121D07D1BD22FC4EDCF554F';
  HashOfOnetoNine := '486D27B1F5F4A20DEE14CC466EDA9069';
  HashOfABCDE := 'ADD78FA0BEA8F6283FE5D011BE6BCA3B';
  HashOfDefaultDataHMACWithShortKey := 'B7D06604FCA943939525BA82BA69706E';
  HashOfDefaultDataHMACWithLongKey := '296DEC851C9F6A6C9E1FD42679CE3FD2';
end;

procedure TTestSnefru_8_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestSnefru_8_256 }

procedure TTestSnefru_8_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateSnefru_8_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '8617F366566A011837F4FB4BA5BEDEA2B892F3ED8B894023D16AE344B2BE5881';
  HashOfDefaultData :=
    '230826DA59215F22AF36663491AECC4872F663722A5A7932428CB8196F7AF78D';
  HashOfOnetoNine :=
    '1C7DEDC33125AF7517970B97B635777FFBA8905D7A0B359776E3E683B115F992';
  HashOfABCDE :=
    '8D2891FC6020D7DC93F7561C0CFDDE26426192B3E364A1F52B634482009DC8C8';
  HashOfDefaultDataHMACWithShortKey :=
    '7E33D94C5A09B2E5F800417128BCF3EF2EDCB971884789A35AE4AA7F13A18147';
  HashOfDefaultDataHMACWithLongKey :=
    'EEE63DC493FCDAA2F826FFF81DB4BAC53CBBFD933BEA3B65C8BEBB576D921623';
end;

procedure TTestSnefru_8_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_3_128 }

procedure TTestTiger_3_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_3_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '3293AC630C13F0245F92BBB1766E1616';
  HashOfDefaultData := 'C76C85CE853F6E9858B507DA64E33DA2';
  HashOfOnetoNine := '0672665140A491BB35040AA9943D769A';
  HashOfABCDE := 'BFD4041233531F1EF1E9A66D7A0CEF76';
  HashOfDefaultDataHMACWithShortKey := '0FA849F65841F2E621E2C882BE7CF80F';
  HashOfDefaultDataHMACWithLongKey := '331B89BDEC8B418091A883C139B3F858';
end;

procedure TTestTiger_3_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_4_128 }

procedure TTestTiger_4_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_4_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '24CC78A7F6FF3546E7984E59695CA13D';
  HashOfDefaultData := '42CAAEB3A7218E379A78E4F1F7FBADA4';
  HashOfOnetoNine := 'D9902D13011BD217DE965A3BA709F5CE';
  HashOfABCDE := '7FD0E2FAEC50261EF48D3B87C554EE73';
  HashOfDefaultDataHMACWithShortKey := '856B697CEB606B1DF42B475D0C5587B5';
  HashOfDefaultDataHMACWithLongKey := '5365F31B5077249CA8C0C11FB29E06C1';
end;

procedure TTestTiger_4_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_5_128 }

procedure TTestTiger_5_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_5_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'E765EBE4C351724A1B99F96F2D7E62C9';
  HashOfDefaultData := 'D6B8DCEA252160A4CBBF6A57DA9ABA78';
  HashOfOnetoNine := 'BCCCB6421B3EC291A062A33DFF21BA76';
  HashOfABCDE := '1AB49D19F3C93B6FF4AB536951E5A6D0';
  HashOfDefaultDataHMACWithShortKey := '49D450EC293D5565CE82284FA52FDC51';
  HashOfDefaultDataHMACWithLongKey := '67B3B43D5CE62BE8B54805E315576F06';
end;

procedure TTestTiger_5_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_3_160 }

procedure TTestTiger_3_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_3_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '3293AC630C13F0245F92BBB1766E16167A4E5849';
  HashOfDefaultData := 'C76C85CE853F6E9858B507DA64E33DA27DE49F86';
  HashOfOnetoNine := '0672665140A491BB35040AA9943D769A47BE83FE';
  HashOfABCDE := 'BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE75';
  HashOfDefaultDataHMACWithShortKey :=
    '45AF6513756EB15B9504CE8212F3D43AE739E470';
  HashOfDefaultDataHMACWithLongKey :=
    '6C256489CD5E62C9B9F236523B030A56CCDF5A8C';
end;

procedure TTestTiger_3_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_4_160 }

procedure TTestTiger_4_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_4_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '24CC78A7F6FF3546E7984E59695CA13D804E0B68';
  HashOfDefaultData := '42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6';
  HashOfOnetoNine := 'D9902D13011BD217DE965A3BA709F5CE7E75ED2C';
  HashOfABCDE := '7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98';
  HashOfDefaultDataHMACWithShortKey :=
    'E8E8B8EF52CF7866A4E0AEAE7DE79878D5564997';
  HashOfDefaultDataHMACWithLongKey :=
    'FE4F2273571AD900BB6A2935AD9E4E53DE98B24B';
end;

procedure TTestTiger_4_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_5_160 }

procedure TTestTiger_5_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_5_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'E765EBE4C351724A1B99F96F2D7E62C9AACBE64C';
  HashOfDefaultData := 'D6B8DCEA252160A4CBBF6A57DA9ABA78E4564864';
  HashOfOnetoNine := 'BCCCB6421B3EC291A062A33DFF21BA764596C58E';
  HashOfABCDE := '1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C';
  HashOfDefaultDataHMACWithShortKey :=
    '5F403B5F7F9A341545F55265698DD77DB8D3D6D4';
  HashOfDefaultDataHMACWithLongKey :=
    '5ACE8DB66A68836ADAC0BD563D43C01E82181E32';
end;

procedure TTestTiger_5_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_3_192 }

procedure TTestTiger_3_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_3_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '3293AC630C13F0245F92BBB1766E16167A4E58492DDE73F3';
  HashOfDefaultData := 'C76C85CE853F6E9858B507DA64E33DA27DE49F8601F6A830';
  HashOfOnetoNine := '0672665140A491BB35040AA9943D769A47BE83FEF2126E50';
  HashOfABCDE := 'BFD4041233531F1EF1E9A66D7A0CEF76A3E0FE756B36A7D7';
  HashOfDefaultDataHMACWithShortKey :=
    '9B53DDED2647666E9C31CF0F93B3B83E9FF64DF4532F3DDC';
  HashOfDefaultDataHMACWithLongKey :=
    'E46789FA64BFEE51EE17C7D257B6DF892A39FA9A7BC65CF9';
end;

procedure TTestTiger_3_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_4_192 }

procedure TTestTiger_4_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_4_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '24CC78A7F6FF3546E7984E59695CA13D804E0B686E255194';
  HashOfDefaultData := '42CAAEB3A7218E379A78E4F1F7FBADA432E1D4B6A41827B0';
  HashOfOnetoNine := 'D9902D13011BD217DE965A3BA709F5CE7E75ED2CB791FEA6';
  HashOfABCDE := '7FD0E2FAEC50261EF48D3B87C554EE739E8FBD98F9A0B332';
  HashOfDefaultDataHMACWithShortKey :=
    'D1113A9110545D0F3C97BE1451A8FAED205B1F27B3D74560';
  HashOfDefaultDataHMACWithLongKey :=
    '31C5440140BD657ECEBA5172E7853E526290060C1A6335D1';
end;

procedure TTestTiger_4_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger_5_192 }

procedure TTestTiger_5_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger_5_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'E765EBE4C351724A1B99F96F2D7E62C9AACBE64C63B5BCA2';
  HashOfDefaultData := 'D6B8DCEA252160A4CBBF6A57DA9ABA78E45648645715E3CE';
  HashOfOnetoNine := 'BCCCB6421B3EC291A062A33DFF21BA764596C58E30854A92';
  HashOfABCDE := '1AB49D19F3C93B6FF4AB536951E5A6D05EF6394C3471A08F';
  HashOfDefaultDataHMACWithShortKey :=
    '8D56E7164C246EAF4708AAEECFE4DD439F5B4396A54049A6';
  HashOfDefaultDataHMACWithLongKey :=
    'C8A09D6DB257C85B99051F3BC410F56C4D92EEBA311005DC';
end;

procedure TTestTiger_5_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_3_128 }

procedure TTestTiger2_3_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_3_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4441BE75F6018773C206C22745374B92';
  HashOfDefaultData := 'DEB1924D290E3D5567792A8171BFC44F';
  HashOfOnetoNine := '82FAF69673762B9FD8A0C902BDB395C1';
  HashOfABCDE := 'E1F0DAC9E852ECF1270FB691C35506D4';
  HashOfDefaultDataHMACWithShortKey := '0393C69DD393D9E15C723DFAE88C3059';
  HashOfDefaultDataHMACWithLongKey := '9B3B854233FD1AFC80D17179039F6F7B';
end;

procedure TTestTiger2_3_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_4_128 }

procedure TTestTiger2_4_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_4_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '6A7201A47AAC2065913811175553489A';
  HashOfDefaultData := '22EE5BFE174B8C1C23361306C3E8F32C';
  HashOfOnetoNine := '75B7D71ACD40FE5B5D3263C1F68F4CF5';
  HashOfABCDE := '9FBB0FBF818C0302890CE373559D2370';
  HashOfDefaultDataHMACWithShortKey := 'A24C1DD76CACA54D3CB2BDDE5E40D84E';
  HashOfDefaultDataHMACWithLongKey := '787FFD7B098895A03139CBEBA0FBCCE8';
end;

procedure TTestTiger2_4_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_5_128 }

procedure TTestTiger2_5_128.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_5_128();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '61C657CC0C3C147ED90779B36A1E811F';
  HashOfDefaultData := '7F71F95B346733E7022D4B85BDA9C51E';
  HashOfOnetoNine := 'F720446C9BFDC8479D9FA53BC8B9144F';
  HashOfABCDE := '14F45FAC4BE0302E740CCC6FE99D75A6';
  HashOfDefaultDataHMACWithShortKey := 'F545BB88FBE3E5FB85E6DE063D081B66';
  HashOfDefaultDataHMACWithLongKey := 'B0D4AAA0A3239A5B242979DBE02C3373';
end;

procedure TTestTiger2_5_128.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_3_160 }

procedure TTestTiger2_3_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_3_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4441BE75F6018773C206C22745374B924AA8313F';
  HashOfDefaultData := 'DEB1924D290E3D5567792A8171BFC44F70B5CD13';
  HashOfOnetoNine := '82FAF69673762B9FD8A0C902BDB395C12B0CBDDC';
  HashOfABCDE := 'E1F0DAC9E852ECF1270FB691C35506D4BEDB12A0';
  HashOfDefaultDataHMACWithShortKey :=
    '71028DCDC197492195110EA5CFF6B3E04912FF25';
  HashOfDefaultDataHMACWithLongKey :=
    '74B33C922DD679DC7144EF9F6BE807A8F1C370FE';
end;

procedure TTestTiger2_3_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_4_160 }

procedure TTestTiger2_4_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_4_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '6A7201A47AAC2065913811175553489ADD0F8B99';
  HashOfDefaultData := '22EE5BFE174B8C1C23361306C3E8F32C92075577';
  HashOfOnetoNine := '75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B';
  HashOfABCDE := '9FBB0FBF818C0302890CE373559D23702D87C69B';
  HashOfDefaultDataHMACWithShortKey :=
    '283A6ED11043AAA947A12843DC5C4B16283BE633';
  HashOfDefaultDataHMACWithLongKey :=
    '4C7CE724E7021DF3B53FA997C49E07E4DF9EA0F7';
end;

procedure TTestTiger2_4_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_5_160 }

procedure TTestTiger2_5_160.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_5_160();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '61C657CC0C3C147ED90779B36A1E811F1D27F406';
  HashOfDefaultData := '7F71F95B346733E7022D4B85BDA9C51E904825F7';
  HashOfOnetoNine := 'F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED';
  HashOfABCDE := '14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177';
  HashOfDefaultDataHMACWithShortKey :=
    'DDEE30DCE9CD2A11C38ADA8AC94FD5BD90EC1BA4';
  HashOfDefaultDataHMACWithLongKey :=
    '89CFB85851EA674DF045CDDE4BAC3C3037E01BDE';
end;

procedure TTestTiger2_5_160.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_3_192 }

procedure TTestTiger2_3_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_3_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '4441BE75F6018773C206C22745374B924AA8313FEF919F41';
  HashOfDefaultData := 'DEB1924D290E3D5567792A8171BFC44F70B5CD13480D6D5C';
  HashOfOnetoNine := '82FAF69673762B9FD8A0C902BDB395C12B0CBDDC66957838';
  HashOfABCDE := 'E1F0DAC9E852ECF1270FB691C35506D4BEDB12A09D6BF911';
  HashOfDefaultDataHMACWithShortKey :=
    'C70FA522EACE7D870F914A086BD1D9807A6FDC405C5A09DB';
  HashOfDefaultDataHMACWithLongKey :=
    '8540FF4EBA4C823EEC5EDC244D83B93381B75CE92F753005';
end;

procedure TTestTiger2_3_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_4_192 }

procedure TTestTiger2_4_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_4_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '6A7201A47AAC2065913811175553489ADD0F8B99E65A0955';
  HashOfDefaultData := '22EE5BFE174B8C1C23361306C3E8F32C92075577F9115C2A';
  HashOfOnetoNine := '75B7D71ACD40FE5B5D3263C1F68F4CF5A5DA963B39413ACA';
  HashOfABCDE := '9FBB0FBF818C0302890CE373559D23702D87C69B9D1B29D5';
  HashOfDefaultDataHMACWithShortKey :=
    '3B182344C171E8843B3D30887274FC7248A7CCD49AA84E77';
  HashOfDefaultDataHMACWithLongKey :=
    '0B3BB091C80889FB2E65FCA6ADCEC87147311F242AEC5519';
end;

procedure TTestTiger2_4_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestTiger2_5_192 }

procedure TTestTiger2_5_192.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateTiger2_5_192();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := '61C657CC0C3C147ED90779B36A1E811F1D27F406E3F37010';
  HashOfDefaultData := '7F71F95B346733E7022D4B85BDA9C51E904825F73AF0E8AE';
  HashOfOnetoNine := 'F720446C9BFDC8479D9FA53BC8B9144FC3FE42ED1440C213';
  HashOfABCDE := '14F45FAC4BE0302E740CCC6FE99D75A6CAB0E177B4ADF2A8';
  HashOfDefaultDataHMACWithShortKey :=
    '19AD11BA8D3534C41CAA2A9DAA80958EDCDB0B67FF3BF55D';
  HashOfDefaultDataHMACWithLongKey :=
    'C583EDE2D12E49F48BD29642C69D4470016293F47374339F';
end;

procedure TTestTiger2_5_192.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestWhirlPool }

procedure TTestWhirlPool.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateWhirlPool();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3';
  HashOfDefaultData :=
    '9D2BB47D6F6D9F0DBAF08BEF416DE06C98CDF293F3D1AD2422A63A9ADFBD9AA33F888A1C6FE7C16DF33B2BD9FFD8EF160BCF6AB4F21B682DC238A3BE03AB0F12';
  HashOfOnetoNine :=
    '21D5CB651222C347EA1284C0ACF162000B4D3E34766F0D00312E3480F633088822809B6A54BA7EDFA17E8FCB5713F8912EE3A218DD98D88C38BBF611B1B1ED2B';
  HashOfABCDE :=
    '5D745E26CCB20FE655D39C9E7F69455758FBAE541CB892B3581E4869244AB35B4FD6078F5D28B1F1A217452A67D9801033D92724A221255A5E377FE9E9E5F0B2';
  HashOfDefaultDataHMACWithShortKey :=
    '72B3CFC10CC32F9203670984407594B9F2A6C9F1A46C3FF7DF76AD07207758F96CF46C448A7687EBBA5EBC046984B4837320306EB27978A58B8CF447978CADEA';
  HashOfDefaultDataHMACWithLongKey :=
    'A2CF231E2E01B310A91A7BF92435AE0258997AB969D0B2E09378C0F30C73E4434894A836B3F580683F58FC56DA87C685927AE0FC80D2548A35CD3C7528A83AC1';
end;

procedure TTestWhirlPool.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestBlake2B }

procedure TTestBlake2B.TestBlake2BTreeHashingMode;
const
  FAN_OUT = Byte(2);
  DEPTH = Byte(2); // MaxDepth
  LEAF_SIZE = UInt32(4096);
  INNER_SIZE = Byte(64);
var
  LBuffer: TBytes;
  Blake2BTreeConfigh00, Blake2BTreeConfigh01, Blake2BTreeConfigh10
    : IBlake2BTreeConfig;
  h00, h01, h10: IHash;
begin
  LBuffer := Nil;
  System.SetLength(LBuffer, 6000);
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

  h10.TransformBytes(h00.ComputeBytes(System.Copy(LBuffer, 0, LEAF_SIZE))
    .GetBytes());

  h10.TransformBytes(h01.ComputeBytes(System.Copy(LBuffer, LEAF_SIZE,
    UInt32(System.Length(LBuffer)) - LEAF_SIZE)).GetBytes());

  ActualString := h10.TransformFinal().ToString();
  ExpectedString := Blake2BTreeHashingMode;

  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestBlake2B.TestNullKeyVsUnKeyed;
var
  LConfigNoKeyed, LConfigNullKeyed: IBlake2BConfig;
  LMainData: TBytes;
  LIdx: Int32;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  for LIdx := 1 to 64 do
  begin
    LConfigNoKeyed := TBlake2BConfig.Create(LIdx);
    LConfigNullKeyed := TBlake2BConfig.Create(LIdx);
    LConfigNullKeyed.Key := Nil;

    ExpectedString := THashFactory.TCrypto.CreateBlake2B(LConfigNoKeyed)
      .ComputeBytes(LMainData).ToString();

    ActualString := THashFactory.TCrypto.CreateBlake2B(LConfigNullKeyed)
      .ComputeBytes(LMainData).ToString();

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s at Index %d', [ExpectedString,
      ActualString, LIdx]));
  end;
end;

procedure TTestBlake2B.SetUp;
var
  LIdx: Int32;
  LConfig: IBlake2BConfig;
  LKey: TBytes;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateBlake2B();
  LConfig := TBlake2BConfig.Create();
  LKey := Nil;
  System.SetLength(LKey, 64);

  for LIdx := 0 to 63 do
  begin
    LKey[LIdx] := LIdx;
  end;

  LConfig.Key := LKey;
  HashInstanceWithKey := THashFactory.TCrypto.CreateBlake2B(LConfig);
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE';
  HashOfDefaultData :=
    '154F99998573B5FC21E3DF86EE1E0161A6E0E912C4361088FE46D2E3543070EFE9746E326BC09E77EC06BCA60955538821C010411B4D0D6BF9BF2D2221CC8017';
  HashOfOnetoNine :=
    'F5AB8BAFA6F2F72B431188AC38AE2DE7BB618FB3D38B6CBF639DEFCDD5E10A86B22FCCFF571DA37E42B23B80B657EE4D936478F582280A87D6DBB1DA73F5C47D';
  HashOfABCDE :=
    'F3E89A60EC4B0B1854744984E421D22B82F181BD4601FB9B1726B2662DA61C29DFF09E75814ACB2639FD79E56616E55FC135F8476F0302B3DC8D44E082EB83A8';
  HashOfDefaultDataHMACWithShortKey :=
    '945EF4F96C681CC9C30A3EB1193FA13FD4ACD87D7C4A86D62AC9D8DCA74A32BB0DDC055EA75383A653E06B8E25266154DE5BE6B23C69723B795A1680EE844834';
  HashOfDefaultDataHMACWithLongKey :=
    '8E6F664622E2637AE477C00F314087FF8F6A8142D8CCF8946A451982AB750566DFD9BF97A50D705389FBF450525098797924DC443EFFDB1A1C945ECEA5DE9553';

  UnkeyedTestVectors := TBlake2BTestVectors.FUnkeyedBlake2B;
  KeyedTestVectors := TBlake2BTestVectors.FKeyedBlake2B;
end;

procedure TTestBlake2B.TearDown;
begin
  HashInstance := Nil;
  HashInstanceWithKey := Nil;
  HMACInstance := Nil;
  inherited;

end;

{ TTestBlake2S }

procedure TTestBlake2S.TestBlake2STreeHashingMode;
const
  FAN_OUT = Byte(2);
  DEPTH = Byte(2); // MaxDepth
  LEAF_SIZE = UInt32(4096);
  INNER_SIZE = Byte(32);
var
  LBuffer: TBytes;
  Blake2STreeConfigh00, Blake2STreeConfigh01, Blake2STreeConfigh10
    : IBlake2STreeConfig;
  h00, h01, h10: IHash;
begin
  LBuffer := Nil;
  System.SetLength(LBuffer, 6000);
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

  h10.TransformBytes(h00.ComputeBytes(System.Copy(LBuffer, 0, LEAF_SIZE))
    .GetBytes());

  h10.TransformBytes(h01.ComputeBytes(System.Copy(LBuffer, LEAF_SIZE,
    UInt32(System.Length(LBuffer)) - LEAF_SIZE)).GetBytes());

  ActualString := h10.TransformFinal().ToString();
  ExpectedString := Blake2STreeHashingMode;

  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TTestBlake2S.TestNullKeyVsUnKeyed;
var
  LConfigNoKeyed, LConfigNullKeyed: IBlake2SConfig;
  LMainData: TBytes;
  LIdx: Int32;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  for LIdx := 1 to 32 do
  begin
    LConfigNoKeyed := TBlake2SConfig.Create(LIdx);
    LConfigNullKeyed := TBlake2SConfig.Create(LIdx);
    LConfigNullKeyed.Key := Nil;

    ExpectedString := THashFactory.TCrypto.CreateBlake2S(LConfigNoKeyed)
      .ComputeBytes(LMainData).ToString();

    ActualString := THashFactory.TCrypto.CreateBlake2S(LConfigNullKeyed)
      .ComputeBytes(LMainData).ToString();

    CheckEquals(ExpectedString, ActualString,
      Format('Expected %s but got %s at Index %d', [ExpectedString,
      ActualString, LIdx]));
  end;
end;

procedure TTestBlake2S.SetUp;
var
  LIdx: Int32;
  LConfig: IBlake2SConfig;
  LKey: TBytes;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateBlake2S();
  LConfig := TBlake2SConfig.Create();
  LKey := Nil;
  System.SetLength(LKey, 32);

  for LIdx := 0 to 31 do
  begin
    LKey[LIdx] := LIdx;
  end;

  LConfig.Key := LKey;
  HashInstanceWithKey := THashFactory.TCrypto.CreateBlake2S(LConfig);
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9';
  HashOfDefaultData :=
    'D9DB23D51529BC163546C2C76F9FDC4611118A691352524D6BCCF5C79AF89E14';
  HashOfOnetoNine :=
    '7ACC2DD21A2909140507F37396ACCE906864B5F118DFA766B107962B7A82A0D4';
  HashOfABCDE :=
    '4BD7246C13721CC5B96F045BE71D49D5C82535332C6903771AFE9EF7B772136F';
  HashOfDefaultDataHMACWithShortKey :=
    '105C7994CB1F775C709A9FBC9641FB2495311258268134F460B9895915A7519A';
  HashOfDefaultDataHMACWithLongKey :=
    '1CB9502C2FE830B46849F2C178BE527BF4B1B80B0B002F6FAC18C0A7ABD3B636';

  UnkeyedTestVectors := TBlake2STestVectors.FUnkeyedBlake2S;
  KeyedTestVectors := TBlake2STestVectors.FKeyedBlake2S;
end;

procedure TTestBlake2S.TearDown;
begin
  HashInstance := Nil;
  HashInstanceWithKey := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestKeccak_224 }

procedure TTestKeccak_224.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateKeccak_224();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData := 'F71837502BA8E10837BDD8D365ADB85591895602FC552B48B7390ABD';
  HashOfDefaultData :=
    '1BA678212F840E95F076B4E3E75310D4DA4308E04396E07EF1683ACE';
  HashOfOnetoNine := '06471DE6C635A88E7470284B2C2EBF9BD7E5E888CBBD128C21CB8308';
  HashOfABCDE := '16F91F7E036DF526340440C34C231862D8F6319772B670EEFD4703FF';
  HashOfDefaultDataHMACWithShortKey :=
    'D6CE783743A36717F893DFF82DE89633F21089AFBE4F26431E269650';
  HashOfDefaultDataHMACWithLongKey :=
    '8C500F95CB013CBC16DEB6CB742D470E20404E0A1776647EAAB6E869';
end;

procedure TTestKeccak_224.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestKeccak_256 }

procedure TTestKeccak_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateKeccak_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470';
  HashOfDefaultData :=
    '3FE42FE8CD6DAEF5ED7891846577F56AB35DC806424FC84A494C81E73BB06B5F';
  HashOfOnetoNine :=
    '2A359FEEB8E488A1AF2C03B908B3ED7990400555DB73E1421181D97CAC004D48';
  HashOfABCDE :=
    '6377C7E66081CB65E473C1B95DB5195A27D04A7108B468890224BEDBE1A8A6EB';
  HashOfDefaultDataHMACWithShortKey :=
    '1660234E7CCC29CFC8DEC8C6508AAF54EE48004EA9B56A15AC5742C89AAADA08';
  HashOfDefaultDataHMACWithLongKey :=
    '925FE69CEF38AA0D2CCBF6741ADD808F204CAA64EFA7E301A0A3EC332E40075E';
end;

procedure TTestKeccak_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestKeccak_288 }

procedure TTestKeccak_288.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateKeccak_288();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '6753E3380C09E385D0339EB6B050A68F66CFD60A73476E6FD6ADEB72F5EDD7C6F04A5D01';
  HashOfDefaultData :=
    'A81F64CA8FAFFA1FC64A8E40E3F6A6FEA3303753B8F7F25E7E6EABA3D99A13F1EDF0F125';
  HashOfOnetoNine :=
    '2B87D3D1907AA78236C7037752CA8C456611C24CE8FBAAAC961AABF3137B471C93A8F031';
  HashOfABCDE :=
    'F996518E4703A5D660B250D720A143B0A44C5DE31819A82FEF0F30158D18E74E6DF405F6';
  HashOfDefaultDataHMACWithShortKey :=
    '615143BAA85817D4F6F051E33801A900AEA480E716A01826E1392743A92B46EED587E9F7';
  HashOfDefaultDataHMACWithLongKey :=
    'EDC893C0E0E9E70F299098D5049D82EE6811582B93B5C38A5DC9FD14F984A352042365D0';
end;

procedure TTestKeccak_288.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestKeccak_384 }

procedure TTestKeccak_384.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateKeccak_384();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '2C23146A63A29ACF99E73B88F8C24EAA7DC60AA771780CCC006AFBFA8FE2479B2DD2B21362337441AC12B515911957FF';
  HashOfDefaultData :=
    '6A53977DFA0BCDCF069635CF541AB64C7E41923FCB3A5B049AB98878411D0E71DF95FCAB0072F1AE8B931BF4490B823E';
  HashOfOnetoNine :=
    'EFCCAE72CE14656C434751CF737E70A57AB8DD2C76F5ABE01E52770AFFD77B66D2B80977724A00A6D971B702906F8032';
  HashOfABCDE :=
    '6E577A02A783232ACF34841399883F5F69D9AC78F48C7F4431CBC4F669C2A0F1CA3B1BECB7701B8315588D64D6C3746A';
  HashOfDefaultDataHMACWithShortKey :=
    '044628643016E3EA30DE6CA3A8A1276F6BF1A5443CEF96BAA73199CF64FFC52D7F38254C671DB2933FFC8DD3E5B77223';
  HashOfDefaultDataHMACWithLongKey :=
    'A7740E29EEF80306DA09D7AF0868E925D6144996F99A01F973F03C4BD85D1EC20567936CA34A443B62A890AD8D263D2A';
end;

procedure TTestKeccak_384.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestKeccak_512 }

procedure TTestKeccak_512.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateKeccak_512();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '0EAB42DE4C3CEB9235FC91ACFFE746B29C29A8C366B7C60E4E67C466F36A4304C00FA9CAF9D87976BA469BCBE06713B435F091EF2769FB160CDAB33D3670680E';
  HashOfDefaultData :=
    '27E67744299C2229F5008141E410B650BB7D70366B8A60BEAE52F8D6F4A8889D1BAEF53191FF53277FD6CFFE76937CDFAC40EB8EE6F32E3B146C05F961E970A8';
  HashOfOnetoNine :=
    '40B787E94778266FB196A73B7A77EDF9DE2EF172451A2B87531324812250DF8F26FCC11E69B35AFDDBE639956C96153E71363F97010BC99405DD2D77B8C41986';
  HashOfABCDE :=
    '37491BD4BF2A4629D4E35602E09812FA94BFC63BAEE4487075E2B6D73F36D01A7392A1719EDBBB5D1D6FA3BA0D144F18229ABC13B7933A4736D6AAB4A3177F18';
  HashOfDefaultDataHMACWithShortKey :=
    '6FA826F0AFFE589DFD1665264F5516D076F9FEC585FD4227095B467A50E963D45C1730232549E8DDB590C1518BA310612839BBCCDF34F6A0AD6AC8B91D393BE6';
  HashOfDefaultDataHMACWithLongKey :=
    '53D5520C2E31F7EAAE1D95CF04663B18C2144AAF141F2630D6454162B3A890D75D59A9D99096411870FBF7A92A563AEA35AFED836DF652C6DF2AB4D373A754E3';
end;

procedure TTestKeccak_512.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestGOST3411_2012_256 }

procedure TTestGOST3411_2012_256.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateGOST3411_2012_256();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB';
  HashOfDefaultData :=
    '9CAC7A67CC162B3860E289849EF463B0EBA83138E974011CE1640CFE7869960A';
  HashOfOnetoNine :=
    '84DA1066A0205E1446EC4A858ED2314B6233E5790BA5999DDE8CD35D5D39F002';
  HashOfABCDE :=
    'DDA887AF02D8C39E0138BD4B95F8CF0DDAF7CD4637FCB94D55BB4003339EC01E';
  HashOfDefaultDataHMACWithShortKey :=
    'DD3972BF0032672E7BC09F62D07A3101A499829D5EF539CA805E2226C59EF493';
  HashOfDefaultDataHMACWithLongKey :=
    '85687C99A9C9B1812A95EA1203B153D869D1353B387EBE805E167FCDBD104C86';
end;

procedure TTestGOST3411_2012_256.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestGOST3411_2012_512 }

procedure TTestGOST3411_2012_512.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateGOST3411_2012_512();
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    '8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A';
  HashOfDefaultData :=
    '48D298A6C02F7D4F0E576CEA2C6AE32E172CDA3B623E1B4ACE8993383FB0562C2D4B34A6FC16FA31B4162827202366E4425BA745B2D2F8195800A8D35DC32EE7';
  HashOfOnetoNine :=
    'C36FADF5238435A7DDA541152C70014A3C2FF0211BBA50F15D2279BA13F6F1E4F4108C6B39FC12CA93E73453A95A135BFF756312165FC8E4C159DFD6F3A4BAF6';
  HashOfABCDE :=
    'C867AA7F3946FF1247CE937F49023871E400DD58E6615DC862597C018BB9C95200620B705624BD0F853521574D6A62721DE7A433719B403B6173AD710F20B219';
  HashOfDefaultDataHMACWithShortKey :=
    'AE0EF8058199079EA6D77DE161E843582F2F2EFA744BAB262462041AD0BDA125E300C4D203D1BCB89161AF35CD581C3EE0C26A8A71A7D8ED4E73EEDC91F75B59';
  HashOfDefaultDataHMACWithLongKey :=
    'ACFFECD016DF8ECE7E03EB15EFF91A3EDACC275C3EFBA51B2FA25B637E4B23F06B4885204F3E4FAFB754C3F0132E53464DA396E6BD58F2453D5D10A32FDB1B7E';
end;

procedure TTestGOST3411_2012_512.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestBlake2XS }

procedure TTestBlake2XS.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateBlake2XS(Nil, 256);
  XofInstance := THashFactory.TXOF.CreateBlake2XS(Nil, 8000) as IXOF;
  HashOfEmptyData :=
    'F4B358457E5563FB54DF3060AEC26EA3AA1C959CF89F55A22538117ECF708BFC';
  HashOfDefaultData :=
    '5ADFC3100CED2EDF93D530E747544B1FF88981E2C8BF4BCA95C434FAEA991718';
  HashOfOnetoNine :=
    'EA2BBB210CCC659A88EEE6D07900D719E26D801CC6A5E6214214EBA376FF28A5';
  HashOfABCDE :=
    '3B42907077820444C727CF6B1FD6CC5E9BF8AA5489F57010670D4045AC0A1466';
  XofOfEmptyData :=
    '217B64B104155F7158277FC5B0AFB954138C93A6F1269DC4C642A781BA20EB24B3B4B5C7E6C13645DD584D851BD4280B24E1DBA29C512D3CBD6A5C84A708C1D536A6654DDD1D8E3'
    + '885F0B520092E264C73BD11F8788F2841D9B5004CD643F3E39F4188A20A0E0F639E61B45759C68A7DA76CD657F71EB35E1CBC01D16B6DA21CE30CB6E9328451DB8B3F47323CDB0EBBB1BFA'
    + 'F1D038D8F6721B8A6268CE955FD58A08F2F38F18B6E51E4E787BC171C737CED8988D912F91A89FD8DB0F3BEC0BA9117E05A916350067A2AC55ED14D7B51A77C9D5B368D58871A6687424CC2C'
    + 'A92FC2F8FD6B1830548B8EC2B10E402F14DF43AAB9F93D73CDE95B14E667D2F00928192651D0681A4C8D9AF7951656162230792D49526E59AE204984E45E3D08F439C04B711E06AC4EB073AD18D95'
    + '8E1D853AA463D05646C98C37941CA909C6E6040983120DEE9EB99D03EBD6766D20909481979897B20E34AF07A2EA96637E9F8E9AAFB6A813360C392710D2A408FB6C5F24980ACCB106468'
    + '61B111BD5716DDAF96F3740BD6D10645DE8632C44643939D9C3CA8795F145DA32A61A7903EEFA12040A4AC9AC237C3DCD8BE742B384E1E60B37F8F471A7E9122498E48236783DAD631120C8E'
    + 'A8274F07592FBFF612227EBDB550E954BBA0E8BE25562C7344E5C124FCD96F6F272EF8092BC926735C812873228FE063C8F7B9C54CA7A401AF98A7CA8820D7055BA3B82B8F286B67B415F469'
    + 'D4A847ADA022AD05FCB75A27BFA3426225DD2C6D62A77EFD8B2A61AE7726876A658EF872B44625D42EA6005BF2207A33D210083B43555F16C60BE798F54080510B9EF53E181C3EA'
    + 'FA675818A5255A8E963B22170EA2C42AF9534AF29FC58DA8289F5BEB1B2F5CBA50DE3D9E3F2AA34A992B7634B780F8D8367274EECF4ACE2FDE88B92CCA35064521BA335C375C4F285F2537FF34'
    + '53F1E1F00D4CFDD91F5F349774DA1BC2D30D7BC0FC84CC087F056FB2425C00C5BD4B79BD048FE79048603961D8910F00EBA4200AF31FD77A9F6D5C051BE29A9555D829F236C425BB65531B'
    + '13E4ED3C7F4EEE77014AE46D1E99D32087AA0B4A984A4DEF9A258376F985820BBF97E5A2702F56EC3FD353F552042CDC9D09502393C2DD702CB434AADD632BB8C562010950C865CC890002'
    + '6D1A7414FD402F5092C7787E7A74238F866EBB623A5DF76B2A5BF916328B6C612CE53694263C7DEFFC8B3245771C22C585C3FFA9932875A439CF2E2ECE68CD24DFDB2CC40813F348411AF7026F662AFCEE1'
    + '3EB53418FB69257FF807691FA896E6486D54FD991E927C492D15C0C9B01D905FAD6FFA294C484DFA6B74400CBDD414A85D458DBFFC366C2AFACCEC7E4EA8D7AB75F52FAAD995ED9CB45D'
    + 'C69A8D906E1C09A60DEF1447A3D724F54CCE6';
end;

procedure TTestBlake2XS.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  inherited;
end;

procedure TTestBlake2XS.TestCheckTestVectors;
var
  LIdx: Int32;
  LVector: THashLibStringArray;
  LInput, LKey, LOutput, LOutputClone: TBytes;
  LHash, LHashClone: IHash;
begin

  for LIdx := 0 to System.Pred
    (System.Length(TBlake2STestVectors.FBlake2XS_XofTestVectors)) do
  begin
    LVector := TBlake2STestVectors.FBlake2XS_XofTestVectors[LIdx];
    LInput := TConverters.ConvertHexStringToBytes
      (TBlake2STestVectors.FBlake2XS_XofTestInput);
    LKey := TConverters.ConvertHexStringToBytes(LVector[0]);

    LHash := THashFactory.TXOF.CreateBlake2XS(LKey,
      (System.Length(LVector[1]) shr 1) * 8);
    LHash.Initialize;
    LHash.TransformBytes(LInput);
    LOutput := LHash.TransformFinal().GetBytes();

    if not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1]))
    then
    begin
      Fail(Format
        ('BLAKE2XS mismatch on test vector, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    System.SetLength(LOutput, System.Length(LVector[1]) shr 1);

    LHash.TransformBytes(LInput);
    LHashClone := LHash.Clone();

    (LHash as IXOF).DoOutput(LOutput, 0, System.Length(LOutput));
    if (not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1])))
    then
    begin
      Fail(Format
        ('BLAKE2XS mismatch on test vector after a reset, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    LOutputClone := LHashClone.TransformFinal().GetBytes();

    if (not AreEqual(LOutput, LOutputClone)) then
    begin
      Fail(Format
        ('BLAKE2XS mismatch on test vector test vector against a clone, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutputClone,
        False)]));
    end;
  end;
end;

{ TTestBlake2XB }

procedure TTestBlake2XB.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateBlake2XB(Nil, 512);
  XofInstance := THashFactory.TXOF.CreateBlake2XB(Nil, 8000) as IXOF;
  HashOfEmptyData :=
    'C5EF3D8845B9B2BA8EA28E9326C9E46E7A5843AD42BACAF927798BEAF554A43CA0830CCF8BB4A24CE1B1D82BD2DA971AFB2BE73919CC5FFF8E7C6A20F87284FA';
  HashOfDefaultData :=
    '9A4C47E816EF6A06F9708B8AE2FEE224F18565CE1F08B848945B73A961BB5E83D79B3A71BE6E324243483C265007A2CD67DE3150C26DC799CE7FC201981AC80A';
  HashOfOnetoNine :=
    '3FD021E013DF681EE479A6E3CE7D36E53971946C586147D59EECF1634C31C318F03BBCE3CDB0B1EC5CD4BD4EDF8ED1441A37754899BB3D8850FCA5EBE0639ABB';
  HashOfABCDE :=
    '81B9FF044391492C89822F8A96279128E876FC5326B0C5C83552B503409F1A6A6CA66DAECE711FE4FCC5DBD92D8560172A64472FAF845CAA7F4297E17ECA1283';
  XofOfEmptyData :=
    '85DDB224AFA3113F145AC1AA3618BD7496FDC79AF14372734A2CDCE9E8DA30029454BAF1C2D78D528F011B3F3FE824CF05B28C4CF34791B3595AC30AB7B348F'
    + '23084628A4315036BE75EDCBE93E217B922E7D8E8CD5EBC35580BC2909432E74506C0080718198A87F44BF22B83DE6FCBE6AC98965D9D8B83F37AACB75064FD6205762BA7CDFFF6F4B83'
    + '672D5296D8D550FDE5B8D16E465D95C26DE2819DA44130EAA3698EC5F2F892133E8F20948523CEE89F01723078FA2E4BE0395638CFAF7F05265C43FF7C08A03EDA0516476CD6C9D14B560E'
    + '7B1FE6E7D59BD658B434755CC58F1780ADE865EA9D365949BF7D260C46452FFF6CBFA9AB54EED5725E9A4E747F4C8C40F1BBAFCE1EEDDE87476924B78B8F7D61ABC93087327CD3220A'
    + '088C757B6E5E8C3A2530B08F7710D4E79E7EBA9C1B839A32E941D934D8B675B5029FE5AC6F00E64F5432DB9E40DFFD9C85A28D2D1786C51026F5AFCB06FD58414E12FF94A50D3F583885'
    + 'F5547605C11BF0C3F9CA71AC9EE9B4D5499A92FE4D765F48F9AE48441E65B384B14946F9A639B53CECB91636A9C14246B769FE7A3E6AAFD131110F3ABF157887A18EFFA5CA80887C358F5F'
    + '7292A09F3AB997D3FD4D08E2178F358F46B8862F220E495940BD60BF96FA219B0B90383E5FBF4DF496E922354DE70363583932F440E839093E3DB3615A3A38A3EF79BEFCA3C8B10FA55'
    + 'FB997E6B25EB68DF7AD4A69FF2B9D20CB3EC981143CEC641732C4FFB899E1496CF8920167097BE4AD3448385FB25C5BE411027798E89ADC79F8225DE42E292C02D24BD2356F9C9D'
    + 'CA502C0A1671BB7D25D91A038A6634670C9E9E668B18124C56CBC3FC7E56A01E8BAF23463DC2ACFEDF572070BD3EAD179CD4008A198EE0A544A975D401A5CED306A861FF23D17D91F67F'
    + 'F2F7CF453F9C444DDFCA81761C482299E098FEA53CD8C809B5E3F5AFEF857BFE918833EBF7B7B272DC014967F5610E39CD09EB8E7AB662F4DFD0CEF98DEC5F95307AA900EF27DF36373FE31'
    + '6DCB951C623729B26F61723B73AD442250F8C2EC7033447795860232B9012B4C837EA47E0F69A9C4A0489AD7BC48BC58BB8EB948BBAC2A638549EDE38B215ABFC30FBEB29F255A9C710A2'
    + '29B4070A5B09D894E1460DD577173892779BBA4257B60FCC9253BE3E6350221CE615438A04C86E3D6FAB218DE5947459B93D02D00C771F8F3820BABCAE18ADF599649F7716C7CECE86866B'
    + 'E1B03FC5390199A7607CA7E45CDAD99411A850125C90AD526C2008293185C1B5B008A458F8F885C8614F317ED52DBAF3E82D0A4B0E47E41C63F145FB17B994B5E9829D8138876A3ADA'
    + '872FD00914654D504245150B178B919D9F9A7219DB86595D3AACA009798FB52DD0D28F8FFBE4D75063EFD98E655CDEE16';
end;

procedure TTestBlake2XB.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  inherited;
end;

procedure TTestBlake2XB.TestCheckTestVectors;
var
  LIdx: Int32;
  LVector: THashLibStringArray;
  LInput, LKey, LOutput, LOutputClone: TBytes;
  LHash, LHashClone: IHash;
begin

  for LIdx := 0 to System.Pred
    (System.Length(TBlake2BTestVectors.FBlake2XB_XofTestVectors)) do
  begin
    LVector := TBlake2BTestVectors.FBlake2XB_XofTestVectors[LIdx];
    LInput := TConverters.ConvertHexStringToBytes
      (TBlake2BTestVectors.FBlake2XB_XofTestInput);
    LKey := TConverters.ConvertHexStringToBytes(LVector[0]);

    LHash := THashFactory.TXOF.CreateBlake2XB(LKey,
      (System.Length(LVector[1]) shr 1) * 8);
    LHash.Initialize;
    LHash.TransformBytes(LInput);
    LOutput := LHash.TransformFinal().GetBytes();

    if not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1]))
    then
    begin
      Fail(Format
        ('BLAKE2XB mismatch on test vector, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    System.SetLength(LOutput, System.Length(LVector[1]) shr 1);

    LHash.TransformBytes(LInput);
    LHashClone := LHash.Clone();

    (LHash as IXOF).DoOutput(LOutput, 0, System.Length(LOutput));
    if (not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1])))
    then
    begin
      Fail(Format
        ('BLAKE2XB mismatch on test vector after a reset, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    LOutputClone := LHashClone.TransformFinal().GetBytes();

    if (not AreEqual(LOutput, LOutputClone)) then
    begin
      Fail(Format
        ('BLAKE2XB mismatch on test vector test vector against a clone, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutputClone,
        False)]));
    end;
  end;
end;

{ TTestBlake3 }

procedure TTestBlake3.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateBlake3_256(Nil);
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);

  HashOfEmptyData :=
    'AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262';
  HashOfDefaultData :=
    'BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F';
  HashOfOnetoNine :=
    'B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED1';
  HashOfABCDE :=
    '0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2';
  HashOfDefaultDataHMACWithShortKey :=
    'D4DE3C2DE89625AF7076FEC6CFD7B0D318665514D1F88CF68F567AC4971B6681';
  HashOfDefaultDataHMACWithLongKey :=
    'A7F72F6A236F4572079427B0FD44516705B3322FB3A8D85ACFCB759804529E96';
end;

procedure TTestBlake3.TearDown;
begin
  HashInstance := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestBlake3XOF }

procedure TTestBlake3XOF.SetUp;
begin
  inherited;
  HashInstance := THashFactory.TXOF.CreateBlake3XOF(Nil, 512);
  XofInstance := THashFactory.TXOF.CreateBlake3XOF(Nil, 8000) as IXOF;
  HashOfEmptyData :=
    'AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A';
  HashOfDefaultData :=
    'BB8DB7E4155BFDB254AD49D8D3105C57B6AC3E783E6D316A75E8B8F8911EB41F800B6ACB7F3593E1787BF62433D016B800B75C14C4E3E395FC5571ADEB1A7143';
  HashOfOnetoNine :=
    'B7D65B48420D1033CB2595293263B6F72EABEE20D55E699D0DF1973B3C9DEED15042F0A21EE5D17C59E507AE27E48A7CD85F69DCD816C5F421883F36E513D9FE';
  HashOfABCDE :=
    '0648C03B5AD9BB6DDF8306EEF6A33EBAE8F89CB4741150C1AE9CD662FDCC1EE2AB9CED8A57741468B7C3163AF41767186CE877C7AE21260064FD4EAD6004D549';
  XofOfEmptyData :=
    'AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262E00F03E7B69AF26B7FAAF09FCD333050338DDFE085B8CC869CA98B206C08243A26F5'
    + '487789E8F660AFE6C99EF9E0C52B92E7393024A80459CF91F476F9FFDBDA7001C22E159B402631F277CA96F2DEFDF1078282314E763699A31C5363165421CCE14D30F'
    + '8A03E49EE25D2EA3CD48A568957B378A65AF65FC35FB3E9E12B81CA2D82CDEE16C68908A6772F827564336933C89E6908B2F9C7D1811C0EB795CBD5898FE6F5E8AF7633'
    + '19CA863718A59AFF3D99660EF642483E217EF0C8785827284FEA90D42225E3CDD6A179BEE852FD24E7D45B38C27B9C2F9469EA8DBDB893F00E28534C7D15B59BADD5A5BDE'
    + 'B090E98EB93C5B2F42101394ACB7C72E9B60094D5442096754600DB8C0FA6DBDFEA154C324C07BF17B7AB0D1488AE5EF76CB7611BAEF17087D84C08B4F950D3D85E00E7001'
    + '813FE029A10722BB003531D5AE406386E78CCA4CA7CACE8A41D294F6EE3B1C645832109B5B19304360B8AB79581E351C518849EAA7C7E14F37BA5B769D2CAF191F9DDEE2D49'
    + '82B6213947A7D047A03F5E456F2588F56E4075C756A319299FBA4001C4B6FB89FBFD93B0739DC684424A439CEFB447D5E191919C4581BC153BD2F2FAE39758F1322AE52EA8B2'
    + 'D859887A71F70C03E28765709711950C2C06BF5C7D1BB6C235F722CE6DB047FE97CF74B87ADBD6531CB14A1193A8974F939DD2EB21335793880279905402DBDA8B5EC0A7C82A'
    + '69151BB42F7126E4157A510C6123139815BA3DF3FD1D810795D1F4F49CB8B0D63D8D07833CE95FCFF2B8B8677D1F6C3EE3CF2A00CE72A32E93F5E225A065A0726DC5C9AD5C26F'
    + '2C3560E401BA5079C3D63A8B29175BC9597B09A2BE664E6641F2D2EBFAFE58D5C025EE367396B4C0E31F9D761B779FF27DBAB678CFBB3C62460CC68A4C3187E9788E045EC92437'
    + '1C3027903A42059D1ED659406706C5E4381C931886A034E20689FFA78221E39B42326A9725C5D669D5E2ABAA1C4640AFC7E4D3A5FF5C5513F1B13BF865F4F02EC09453DBD0BCD1D0'
    + 'AC3444141CC78B662F00811F095D1A1614EDCB516C70FB3BBF4C9ED58F8FBBDDE8CB1B5497585C53FB33EB7A98810780056C9952848F129D5A87DD36774C1B91E135C1ACEF799E6E4'
    + '320FB862C3619F6874CE0D7550D260308D7E309EEEA5026A534D37DFA4F703BF185C015D99D88A1E350639634D1C7F1DE79FAEBC0DFECAC66089E6F44C916DEBC12965DD0ECFDDF8A'
    + 'D4CAFB5ABC45FC9FCA9780C26F457EA9DDCF5370A4D042BC5B9BFA87FAC10F88B170CD22CB9AB2255B251529272BADDF757AD471C4935363495B8E626421859FF304F6D5D527AAE2AF'
    + '7444F3E14C8CD41F9BB1E19A1418E08A5B535C79554';
end;

procedure TTestBlake3XOF.TearDown;
begin
  HashInstance := Nil;
  XofInstance := Nil;
  inherited;
end;

procedure TTestBlake3XOF.TestCheckTestVectors;
var
  LIdx: Int32;
  LKeyAsString, LCtxAsString: String;
  LVector: THashLibStringArray;
  LFullInput, LChunkedInput, LNilKey, LKey, LOutput, LOutputClone, LKeyedOutput,
    LKeyedOutputClone, LCtx, LSubKey: TBytes;
  LHash, LHashClone, LKeyedHash, LKeyedHashClone: IHash;
begin
  System.SetLength(LFullInput, 1 shl 15);
  for LIdx := 0 to System.High(LFullInput) do
  begin
    LFullInput[LIdx] := Byte(LIdx mod 251);
  end;

  LKeyAsString := 'whats the Elvish word for friend';
  LCtxAsString := 'BLAKE3 2019-12-27 16:29:52 test vectors context';

  LKey := TConverters.ConvertStringToBytes(LKeyAsString, TEncoding.UTF8);
  LNilKey := Nil;
  LCtx := TConverters.ConvertStringToBytes(LCtxAsString, TEncoding.UTF8);

  for LIdx := 0 to System.Pred
    (System.Length(TBlake3TestVectors.FBlake3_XofTestVectors)) do
  begin
    LVector := TBlake3TestVectors.FBlake3_XofTestVectors[LIdx];
    LChunkedInput := System.Copy(LFullInput, 0, StrToInt(LVector[0]));

    LHash := THashFactory.TXOF.CreateBlake3XOF(LNilKey,
      (System.Length(LVector[1]) shr 1) * 8);

    LKeyedHash := THashFactory.TXOF.CreateBlake3XOF(LKey,
      (System.Length(LVector[2]) shr 1) * 8);

    LHash.Initialize;
    LKeyedHash.Initialize;

    LHash.TransformBytes(LChunkedInput);
    LKeyedHash.TransformBytes(LChunkedInput);
    LOutput := LHash.TransformFinal().GetBytes();
    LKeyedOutput := LKeyedHash.TransformFinal().GetBytes();

    if not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1]))
    then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on test vector, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    if not AreEqual(LKeyedOutput, TConverters.ConvertHexStringToBytes
      (LVector[2])) then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on keyed test vector, Expected "%s" but got "%s"',
        [LVector[2], TConverters.ConvertBytesToHexString(LKeyedOutput,
        False)]));
    end;

    System.SetLength(LOutput, System.Length(LVector[1]) shr 1);
    System.SetLength(LKeyedOutput, System.Length(LVector[2]) shr 1);

    LHash.TransformBytes(LChunkedInput);
    LKeyedHash.TransformBytes(LChunkedInput);
    LHashClone := LHash.Clone();
    LKeyedHashClone := LKeyedHash.Clone();

    (LHash as IXOF).DoOutput(LOutput, 0, System.Length(LOutput));
    (LKeyedHash as IXOF).DoOutput(LKeyedOutput, 0, System.Length(LKeyedOutput));
    if (not AreEqual(LOutput, TConverters.ConvertHexStringToBytes(LVector[1])))
    then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on test vector after a reset, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutput, False)]));
    end;

    if (not AreEqual(LKeyedOutput, TConverters.ConvertHexStringToBytes(LVector
      [2]))) then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on keyed test vector after a reset, Expected "%s" but got "%s"',
        [LVector[2], TConverters.ConvertBytesToHexString(LKeyedOutput,
        False)]));
    end;

    LOutputClone := LHashClone.TransformFinal().GetBytes();
    LKeyedOutputClone := LKeyedHashClone.TransformFinal().GetBytes();

    if (not AreEqual(LOutput, LOutputClone)) then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on test vector test vector against a clone, Expected "%s" but got "%s"',
        [LVector[1], TConverters.ConvertBytesToHexString(LOutputClone,
        False)]));
    end;

    if (not AreEqual(LKeyedOutput, LKeyedOutputClone)) then
    begin
      Fail(Format
        ('BLAKE3XOF mismatch on keyed test vector test vector against a clone, Expected "%s" but got "%s"',
        [LVector[2], TConverters.ConvertBytesToHexString(LKeyedOutputClone,
        False)]));
    end;

    System.SetLength(LSubKey, System.Length(LVector[3]) shr 1);
    TBlake3.DeriveKey(LChunkedInput, LCtx, LSubKey);

    if (not AreEqual(LSubKey, TConverters.ConvertHexStringToBytes(LVector[3])))
    then
    begin
      Fail(Format
        ('Blake3DeriveKey mismatch on test vector, Expected "%s" but got "%s"',
        [LVector[3], TConverters.ConvertBytesToHexString(LSubKey, False)]));
    end;
  end;
end;

{ TTestKMAC128 }

procedure TTestKMAC128.DoComputeKMAC128(const AKey, ACustomization, AData,
  AExpectedResult: String; AOutputSizeInBits: UInt64; IsXOF: Boolean);
var
  LHash, LClone: IHash;
  LIdx: Int32;
  LActualResult, LActualResultClone, LKey, LCustomization, LData: TBytes;
  Suffix: String;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LCustomization := TConverters.ConvertStringToBytes(ACustomization,
    TEncoding.UTF8);
  LData := TConverters.ConvertHexStringToBytes(AData);

  if IsXOF then
  begin
    LHash := THashFactory.TXOF.CreateKMAC128XOF(LKey, LCustomization,
      AOutputSizeInBits);
    Suffix := 'XOF';
  end
  else
  begin
    LHash := THashFactory.TKMAC.CreateKMAC128(LKey, LCustomization,
      AOutputSizeInBits);
    Suffix := '';
  end;

  LHash.Initialize;

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    LHash.TransformBytes(TBytes.Create(LData[LIdx]));
    // do incremental hashing
  end;

  LClone := LHash.Clone();

  LActualResult := Nil;
  LActualResultClone := Nil;

  if IsXOF then
  begin
    System.SetLength(LActualResult, AOutputSizeInBits shr 3);
    System.SetLength(LActualResultClone, AOutputSizeInBits shr 3);

    ((LHash as IKMAC) as IXOF).DoOutput(LActualResult, 0,
      AOutputSizeInBits shr 3);

    ((LClone as IKMAC) as IXOF).DoOutput(LActualResultClone, 0,
      AOutputSizeInBits shr 3);

    LHash.Initialize();
    LClone.Initialize();
  end
  else
  begin
    LActualResult := LHash.TransformFinal().GetBytes();
    LActualResultClone := LClone.TransformFinal().GetBytes();
  end;

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

  if (not AreEqual(LActualResult, LActualResultClone)) then
  begin
    Fail(Format
      ('KMAC128%s mismatch on test vector against a clone, Expected "%s" but got "%s"',
      [Suffix, AExpectedResult, TConverters.ConvertBytesToHexString
      (LActualResultClone, False)]));
  end;

end;

procedure TTestKMAC128.SetUp;
var
  LIdx: Int32;
  LTemp: TBytes;
begin
  inherited;
  LTemp := Nil;
  System.SetLength(LTemp, 200);
  for LIdx := 0 to 199 do
  begin
    LTemp[LIdx] := LIdx;
  end;

  FData := TConverters.ConvertBytesToHexString(LTemp, False);
end;

procedure TTestKMAC128.TearDown;
begin
  inherited;

end;

procedure TTestKMAC128.TestKMAC128NISTSample1;
begin
  DoComputeKMAC128(RawKeyInHex, '', ZeroToThreeInHex,
    'E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E',
    OutputSizeInBits, False);
end;

procedure TTestKMAC128.TestKMAC128NISTSample2;
begin
  DoComputeKMAC128(RawKeyInHex, CustomizationMessage, ZeroToThreeInHex,
    '3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5',
    OutputSizeInBits, False);
end;

procedure TTestKMAC128.TestKMAC128NISTSample3;
begin
  DoComputeKMAC128(RawKeyInHex, CustomizationMessage, FData,
    '1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230',
    OutputSizeInBits, False);
end;

procedure TTestKMAC128.TestKMAC128XOFNISTSample1;
begin
  DoComputeKMAC128(RawKeyInHex, '', ZeroToThreeInHex,
    'CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35',
    OutputSizeInBits, True);
end;

procedure TTestKMAC128.TestKMAC128XOFNISTSample2;
begin
  DoComputeKMAC128(RawKeyInHex, CustomizationMessage, ZeroToThreeInHex,
    '31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C',
    OutputSizeInBits, True);
end;

procedure TTestKMAC128.TestKMAC128XOFNISTSample3;
begin
  DoComputeKMAC128(RawKeyInHex, CustomizationMessage, FData,
    '47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F',
    OutputSizeInBits, True);
end;

{ TTestKMAC256 }

procedure TTestKMAC256.DoComputeKMAC256(const AKey, ACustomization, AData,
  AExpectedResult: String; AOutputSizeInBits: UInt64; IsXOF: Boolean);
var
  LHash, LClone: IHash;
  LIdx: Int32;
  LActualResult, LActualResultClone, LKey, LCustomization, LData: TBytes;
  Suffix: String;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LCustomization := TConverters.ConvertStringToBytes(ACustomization,
    TEncoding.UTF8);
  LData := TConverters.ConvertHexStringToBytes(AData);

  if IsXOF then
  begin
    LHash := THashFactory.TXOF.CreateKMAC256XOF(LKey, LCustomization,
      AOutputSizeInBits);
    Suffix := 'XOF';
  end
  else
  begin
    LHash := THashFactory.TKMAC.CreateKMAC256(LKey, LCustomization,
      AOutputSizeInBits);
    Suffix := '';
  end;

  LHash.Initialize;

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    LHash.TransformBytes(TBytes.Create(LData[LIdx]));
    // do incremental hashing
  end;

  LClone := LHash.Clone();

  LActualResult := Nil;
  LActualResultClone := Nil;

  if IsXOF then
  begin
    System.SetLength(LActualResult, AOutputSizeInBits shr 3);
    System.SetLength(LActualResultClone, AOutputSizeInBits shr 3);

    ((LHash as IKMAC) as IXOF).DoOutput(LActualResult, 0,
      AOutputSizeInBits shr 3);

    ((LClone as IKMAC) as IXOF).DoOutput(LActualResultClone, 0,
      AOutputSizeInBits shr 3);

    LHash.Initialize();
    LClone.Initialize();
  end
  else
  begin
    LActualResult := LHash.TransformFinal().GetBytes();
    LActualResultClone := LClone.TransformFinal().GetBytes();
  end;

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

  if (not AreEqual(LActualResult, LActualResultClone)) then
  begin
    Fail(Format
      ('KMAC256%s mismatch on test vector against a clone, Expected "%s" but got "%s"',
      [Suffix, AExpectedResult, TConverters.ConvertBytesToHexString
      (LActualResultClone, False)]));
  end;

end;

procedure TTestKMAC256.SetUp;
var
  LIdx: Int32;
  LTemp: TBytes;
begin
  inherited;
  LTemp := Nil;
  System.SetLength(LTemp, 200);
  for LIdx := 0 to 199 do
  begin
    LTemp[LIdx] := LIdx;
  end;

  FData := TConverters.ConvertBytesToHexString(LTemp, False);
end;

procedure TTestKMAC256.TearDown;
begin
  inherited;

end;

procedure TTestKMAC256.TestKMAC256NISTSample1;
begin
  DoComputeKMAC256(RawKeyInHex, CustomizationMessage, ZeroToThreeInHex,
    '20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD',
    OutputSizeInBits, False);
end;

procedure TTestKMAC256.TestKMAC256NISTSample2;
begin
  DoComputeKMAC256(RawKeyInHex, '', FData,
    '75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69',
    OutputSizeInBits, False);
end;

procedure TTestKMAC256.TestKMAC256NISTSample3;
begin
  DoComputeKMAC256(RawKeyInHex, CustomizationMessage, FData,
    'B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965',
    OutputSizeInBits, False);
end;

procedure TTestKMAC256.TestKMAC256XOFNISTSample1;
begin
  DoComputeKMAC256(RawKeyInHex, CustomizationMessage, ZeroToThreeInHex,
    '1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B',
    OutputSizeInBits, True);
end;

procedure TTestKMAC256.TestKMAC256XOFNISTSample2;
begin
  DoComputeKMAC256(RawKeyInHex, '', FData,
    'FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B',
    OutputSizeInBits, True);
end;

procedure TTestKMAC256.TestKMAC256XOFNISTSample3;
begin
  DoComputeKMAC256(RawKeyInHex, CustomizationMessage, FData,
    'D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D',
    OutputSizeInBits, True);
end;

{ TTestBlake2BMAC }

procedure TTestBlake2BMAC.DoComputeBlake2BMAC(const AKey, APersonalisation,
  ASalt, AData, AExpectedResult: String; AOutputSizeInBits: Int32);
var
  LHash, LClone: IHash;
  LIdx: Int32;
  LActualResult, LActualResultClone, LKey, LPersonalisation, LSalt,
    LData: TBytes;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LPersonalisation := TConverters.ConvertStringToBytes(APersonalisation,
    TEncoding.UTF8);

  // if personalisation length <> 16, resize to 16, padding with zeros if necessary
  if System.Length(LPersonalisation) <> 16 then
  begin
    System.SetLength(LPersonalisation, 16);
  end;

  LSalt := TConverters.ConvertHexStringToBytes(ASalt);
  LData := TConverters.ConvertStringToBytes(AData, TEncoding.UTF8);

  LHash := THashFactory.TBlake2BMAC.CreateBlake2BMAC(LKey, LSalt,
    LPersonalisation, AOutputSizeInBits);

  LHash.Initialize;

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    LHash.TransformBytes(TBytes.Create(LData[LIdx]));
    // do incremental hashing
  end;

  LClone := LHash.Clone();

  LActualResult := LHash.TransformFinal().GetBytes();
  LActualResultClone := LClone.TransformFinal().GetBytes();

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

  if (not AreEqual(LActualResult, LActualResultClone)) then
  begin
    Fail(Format
      ('Blake2BMAC mismatch on test vector against a clone, Expected "%s" but got "%s"',
      [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResultClone,
      False)]));
  end;

end;

procedure TTestBlake2BMAC.SetUp;
begin
  inherited;

end;

procedure TTestBlake2BMAC.TearDown;
begin
  inherited;

end;

procedure TTestBlake2BMAC.TestBlake2BMACSample1;
begin
  DoComputeBlake2BMAC
    ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '', '',
    'Sample input for outlen<digest_length', '2A', 1 * 8);
end;

procedure TTestBlake2BMAC.TestBlake2BMACSample2;
begin
  DoComputeBlake2BMAC
    ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    'application', '000102030405060708090A0B0C0D0E0F',
    'Combo input with outlen, custom and salt',
    '51742FC491171EAF6B9459C8B93A44BBF8F44A0B4869A17FA178C8209918AD96', 32 * 8);
end;

procedure TTestBlake2BMAC.TestBlake2BMACSample3;
begin
  DoComputeBlake2BMAC
    ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    'application', '000102030405060708090A0B0C0D0E0F',
    'Sample input for keylen<blocklen, salt and custom',
    '233A6C732212F4813EC4C9F357E35297E59A652FD24155205F00363F7C54734EE1E8C7329D92116CBEC62DB35EBB5D51F9E5C2BA41789B84AC9EBC266918E524',
    64 * 8);
end;

{ TTestBlake2SMAC }

procedure TTestBlake2SMAC.DoComputeBlake2SMAC(const AKey, APersonalisation,
  ASalt, AData, AExpectedResult: String; AOutputSizeInBits: Int32);
var
  LHash, LClone: IHash;
  LIdx: Int32;
  LActualResult, LActualResultClone, LKey, LPersonalisation, LSalt,
    LData: TBytes;
begin
  LKey := TConverters.ConvertHexStringToBytes(AKey);
  LPersonalisation := TConverters.ConvertStringToBytes(APersonalisation,
    TEncoding.UTF8);

  // if personalisation length <> 8, resize to 8, padding with zeros if necessary
  if System.Length(LPersonalisation) <> 8 then
  begin
    System.SetLength(LPersonalisation, 8);
  end;

  LSalt := TConverters.ConvertHexStringToBytes(ASalt);
  LData := TConverters.ConvertStringToBytes(AData, TEncoding.UTF8);

  LHash := THashFactory.TBlake2SMAC.CreateBlake2SMAC(LKey, LSalt,
    LPersonalisation, AOutputSizeInBits);

  LHash.Initialize;

  for LIdx := System.Low(LData) to System.High(LData) do
  begin
    LHash.TransformBytes(TBytes.Create(LData[LIdx]));
    // do incremental hashing
  end;

  LClone := LHash.Clone();

  LActualResult := LHash.TransformFinal().GetBytes();
  LActualResultClone := LClone.TransformFinal().GetBytes();

  CheckEquals(AExpectedResult, TConverters.ConvertBytesToHexString
    (LActualResult, False), Format('Expected %s But got %s',
    [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResult,
    False)]));

  if (not AreEqual(LActualResult, LActualResultClone)) then
  begin
    Fail(Format
      ('Blake2SMAC mismatch on test vector against a clone, Expected "%s" but got "%s"',
      [AExpectedResult, TConverters.ConvertBytesToHexString(LActualResultClone,
      False)]));
  end;

end;

procedure TTestBlake2SMAC.SetUp;
begin
  inherited;

end;

procedure TTestBlake2SMAC.TearDown;
begin
  inherited;

end;

procedure TTestBlake2SMAC.TestBlake2SMACSample1;
begin
  DoComputeBlake2SMAC
    ('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F', '', '',
    'Sample input for outlen<digest_length', '07', 1 * 8);
end;

procedure TTestBlake2SMAC.TestBlake2SMACSample2;
begin
  DoComputeBlake2SMAC('000102030405060708090A0B0C0D0E0F', 'app',
    '0001020304050607', 'Combo input with outlen, custom and salt',
    '6808D8DAAE537A16BF00E837010969A4', 16 * 8);
end;

procedure TTestBlake2SMAC.TestBlake2SMACSample3;
begin
  DoComputeBlake2SMAC('000102030405060708090A0B0C0D0E0F', 'app',
    'A205819E78D6D762', 'Sample input for keylen<blocklen, salt and custom',
    'E9F7704DFE5080A4AAFE62A806F53EA7F98FFC24175164158F18EC5497B961F5', 32 * 8);
end;

{ TTestBlake2BP }

procedure TTestBlake2BP.SetUp;
var
  LIdx: Int32;
  LKey: TBytes;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateBlake2BP(64, Nil);
  LKey := Nil;
  System.SetLength(LKey, 64);

  for LIdx := 0 to 63 do
  begin
    LKey[LIdx] := LIdx;
  end;

  HashInstanceWithKey := THashFactory.TCrypto.CreateBlake2BP(64, LKey);
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'B5EF811A8038F70B628FA8B294DAAE7492B1EBE343A80EAABBF1F6AE664DD67B9D90B0120791EAB81DC96985F28849F6A305186A85501B405114BFA678DF9380';
  HashOfDefaultData :=
    '6F02764BDBA4184E50CAA52539BC392239D31E1BC76CEACBCA42630BCB7B48B527F65AA2F50363C0E26A287B758C87BC77C7175AB7A12B33104330F5A1C6E171';
  HashOfOnetoNine :=
    'E70843E71EF73EF84D991990687CB72E272E590F7E86F491935E9904F0582A165A388F956D691101C5D2B035634E4415C3CB21D7F721702CC64791D53AEDB9E2';
  HashOfABCDE :=
    'C96CA7B60257D18A67EC6DAF4E06A6A0F882ECEE22605DBE64DFAD2D7AA2FF939726385C7E60F00A2A38CF302E460C33EAE769CA5652FA8456EA6A75DC6AAC39';
  HashOfDefaultDataHMACWithShortKey :=
    '671A8EE18AD7BCC940CF4B35B47D0AAA89077AA8503E4E374A5BC2803758BBF04C6C80F97E5B71CD79A1E6DCD6585EB82A5F5482DB268B462D651530CE5CB177';
  HashOfDefaultDataHMACWithLongKey :=
    '62B264D5D5DFC01350B69C083B239426EC8A8F971FAC8DCB0B6A4825DD664CB992413AA1F7E5D2950BFFB9C207A9B084591633A96F3F590A861B27C3B827D3BC';

  UnkeyedTestVectors := TBlake2BPTestVectors.FUnkeyedBlake2BP;
  KeyedTestVectors := TBlake2BPTestVectors.FKeyedBlake2BP;
end;

procedure TTestBlake2BP.TearDown;
begin
  HashInstance := Nil;
  HashInstanceWithKey := Nil;
  HMACInstance := Nil;
  inherited;
end;

{ TTestBlake2SP }

procedure TTestBlake2SP.SetUp;
var
  LIdx: Int32;
  LKey: TBytes;
begin
  inherited;
  HashInstance := THashFactory.TCrypto.CreateBlake2SP(32, Nil);
  LKey := Nil;
  System.SetLength(LKey, 32);

  for LIdx := 0 to 31 do
  begin
    LKey[LIdx] := LIdx;
  end;

  HashInstanceWithKey := THashFactory.TCrypto.CreateBlake2SP(32, LKey);
  HMACInstance := THashFactory.THMAC.CreateHMAC(HashInstance);
  HashOfEmptyData :=
    'DD0E891776933F43C7D032B08A917E25741F8AA9A12C12E1CAC8801500F2CA4F';
  HashOfDefaultData :=
    'F1617895134C203ED0A9C8CC72938161EBC9AB6F233BBD3CCFC4D4BCA08A5ED0';
  HashOfOnetoNine :=
    'D6D3157BD4E809982E0EEA22C5AF5CDDF05473F6ECBE353119591E6CDCB7127E';
  HashOfABCDE :=
    '107EEF69D795B14C8411EEBEFA897429682108397680377C78E5D214F014916F';
  HashOfDefaultDataHMACWithShortKey :=
    'D818A87A70949BDA7DE9765650D665C49B1B5CF11B05A1780901C46A91FFD786';
  HashOfDefaultDataHMACWithLongKey :=
    '7E061EC8E97D200F21BD7DB59FF4ED7BB1F7327D9E75EB3D922B926A76FEFE3F';

  UnkeyedTestVectors := TBlake2SPTestVectors.FUnkeyedBlake2SP;
  KeyedTestVectors := TBlake2SPTestVectors.FKeyedBlake2SP;
end;

procedure TTestBlake2SP.TearDown;
begin
  HashInstance := Nil;
  HashInstanceWithKey := Nil;
  HMACInstance := Nil;
  inherited;
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
RegisterTest(TTestCShake_128);
RegisterTest(TTestCShake_256);
RegisterTest(TTestKeccak_224);
RegisterTest(TTestKeccak_256);
RegisterTest(TTestKeccak_288);
RegisterTest(TTestKeccak_384);
RegisterTest(TTestKeccak_512);
RegisterTest(TTestBlake2B);
RegisterTest(TTestBlake2S);
RegisterTest(TTestBlake2XS);
RegisterTest(TTestBlake2XB);
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
RegisterTest(TTestKMAC128);
RegisterTest(TTestKMAC256);
RegisterTest(TTestBlake2BMAC);
RegisterTest(TTestBlake2SMAC);
RegisterTest(TTestBlake2BP);
RegisterTest(TTestBlake2SP);
RegisterTest(TTestBlake3);
RegisterTest(TTestBlake3XOF);
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
RegisterTest(TTestCShake_128.Suite);
RegisterTest(TTestCShake_256.Suite);
RegisterTest(TTestKeccak_224.Suite);
RegisterTest(TTestKeccak_256.Suite);
RegisterTest(TTestKeccak_288.Suite);
RegisterTest(TTestKeccak_384.Suite);
RegisterTest(TTestKeccak_512.Suite);
RegisterTest(TTestBlake2B.Suite);
RegisterTest(TTestBlake2S.Suite);
RegisterTest(TTestBlake2XS.Suite);
RegisterTest(TTestBlake2XB.Suite);
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
RegisterTest(TTestKMAC128.Suite);
RegisterTest(TTestKMAC256.Suite);
RegisterTest(TTestBlake2BMAC.Suite);
RegisterTest(TTestBlake2SMAC.Suite);
RegisterTest(TTestBlake2BP.Suite);
RegisterTest(TTestBlake2SP.Suite);
RegisterTest(TTestBlake3.Suite);
RegisterTest(TTestBlake3XOF.Suite);
{$ENDIF FPC}

end.
