unit HashLibTests;

interface

{$IFDEF FPC}
{$WARNINGS OFF }
{$NOTES OFF }
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
  HlpCRC,
  HlpICRC,
  HlpIHashInfo,
  HlpHashFactory,
  HlpIHash,
  HlpIHashResult,
  HlpConverters,
  HlpBlake2BConfig,
  HlpIBlake2BConfig,
  Blake2BTestVectors,
  HlpBlake2SConfig,
  HlpIBlake2SConfig,
  HlpHashLibTypes,
  Blake2STestVectors;

type

  THashLibTestCase = class abstract(TTestCase)

  end;

type

  THashLibAlgorithmTestCase = class abstract(THashLibTestCase)
  protected
    FHash: IHash;
    FHashResult: IHashResult;
    FActualString, FExpectedString: String;

  const
    FEmptyData: String = '';
    FDefaultData: String = 'HashLib4Pascal';
    FShortMessage: String = 'A short message';
    FZerotoFour: String = '01234';
    FOnetoNine: String = '123456789';
    FRandomStringRecord
      : String = 'I will not buy this record, it is scratched.';
    FRandomStringTobacco
      : String = 'I will not buy this tobacconist''s, it is scratched.';
    FQuickBrownDog: String = 'The quick brown fox jumps over the lazy dog';
    FBytesabcde: array [0 .. 4] of Byte = ($61, $62, $63, $64, $65);
    FHexStringAsKey: String = '000102030405060708090A0B0C0D0E0F';
    FHMACLongStringKey: String = 'I need an Angel';
    FHMACShortStringKey: String = 'Hash';

  end;

  // NullDigest

type
  TTestNullDigest = class(THashLibAlgorithmTestCase)

  private
    FNullDigest: IHash;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyBytes;
    procedure TestBytesabcde;
    procedure TestIncrementalHash;

  end;


  // CheckSum

type

  TTestCRCModel = class(THashLibAlgorithmTestCase)
  private

    FCRC: IHash;

  protected
    procedure TearDown; override;
  published
    procedure TestCheckValue;
    procedure TestCheckValueWithIncrementalHash;

  end;

type

  TTestAlder32 = class(THashLibAlgorithmTestCase)

  private

    FAdler32: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000001';
    FExpectedHashOfDefaultData: String = '25D40524';
    FExpectedHashOfOnetoNine: String = '091E01DE';
    FExpectedHashOfabcde: String = '05C801F0';

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

  end;

  // Hash32

type

  TTestAP = class(THashLibAlgorithmTestCase)

  private

    FAP: IHash;

  const
    FExpectedHashOfEmptyData: String = 'AAAAAAAA';
    FExpectedHashOfDefaultData: String = '7F14EFED';
    FExpectedHashOfOnetoNine: String = 'C0E86BE5';
    FExpectedHashOfabcde: String = '7F6A697A';

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

  end;

type

  TTestBernstein = class(THashLibAlgorithmTestCase)

  private

    FBernstein: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = 'C4635F48';
    FExpectedHashOfOnetoNine: String = '35CDBB82';
    FExpectedHashOfabcde: String = '0F11B894';

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

  end;

type

  TTestBernstein1 = class(THashLibAlgorithmTestCase)

  private

    FBernstein1: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = '2D122E48';
    FExpectedHashOfOnetoNine: String = '3BABEA14';
    FExpectedHashOfabcde: String = '0A1DEB04';

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

  end;

type

  TTestBKDR = class(THashLibAlgorithmTestCase)

  private

    FBKDR: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '29E11B15';
    FExpectedHashOfOnetoNine: String = 'DE43D6D5';
    FExpectedHashOfabcde: String = 'B3EDEA13';

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

  end;

type

  TTestDEK = class(THashLibAlgorithmTestCase)

  private

    FDEK: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '8E01E947';
    FExpectedHashOfOnetoNine: String = 'AB4ACBA5';
    FExpectedHashOfabcde: String = '0C2080E5';

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

  end;

type

  TTestDJB = class(THashLibAlgorithmTestCase)

  private

    FDJB: IHash;

  const
    FExpectedHashOfEmptyData: String = '00001505';
    FExpectedHashOfDefaultData: String = 'C4635F48';
    FExpectedHashOfOnetoNine: String = '35CDBB82';
    FExpectedHashOfabcde: String = '0F11B894';

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

  end;

type

  TTestELF = class(THashLibAlgorithmTestCase)

  private

    FELF: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '01F5B2CC';
    FExpectedHashOfOnetoNine: String = '0678AEE9';
    FExpectedHashOfabcde: String = '006789A5';

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

  end;

type

  TTestFNV = class(THashLibAlgorithmTestCase)

  private

    FFNV: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'BE611EA3';
    FExpectedHashOfOnetoNine: String = 'D8D70BF1';
    FExpectedHashOfabcde: String = 'B2B39969';

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

  end;

type

  TTestFNV1a = class(THashLibAlgorithmTestCase)

  private

    FFNV1a: IHash;

  const
    FExpectedHashOfEmptyData: String = '811C9DC5';
    FExpectedHashOfDefaultData: String = '1892F1F8';
    FExpectedHashOfOnetoNine: String = 'BB86B11C';
    FExpectedHashOfabcde: String = '749BCF08';

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

  end;

type

  TTestJenkins3 = class(THashLibAlgorithmTestCase)

  private

    FJenkins3: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'F0F69CEF';
    FExpectedHashOfOnetoNine: String = '845D9A96';
    FExpectedHashOfabcde: String = '026D72DE';

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

  end;

type

  TTestJS = class(THashLibAlgorithmTestCase)

  private

    FJS: IHash;

  const
    FExpectedHashOfEmptyData: String = '4E67C6A7';
    FExpectedHashOfDefaultData: String = '683AFCFE';
    FExpectedHashOfOnetoNine: String = '90A4224B';
    FExpectedHashOfabcde: String = '62E8C8B5';

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

  end;

type

  TTestMurmur2 = class(THashLibAlgorithmTestCase)

  private

    FMurmur2: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '30512DE6';
    FExpectedHashOfOnetoNine: String = 'DCCB0167';
    FExpectedHashOfabcde: String = '5F09A8DE';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = 'B15D52F0';

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
    procedure TestWithDifferentKey;

  end;

type

  TTestMurmurHash3_x86_32 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x86_32: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '3D97B9EB';
    FExpectedHashOfRandomString: String = 'A8D02B9A';
    FExpectedHashOfZerotoFour: String = '19D02170';
    FExpectedHashOfEmptyDataWithOneAsKey: String = '514E28B7';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = 'B05606FE';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;

  end;

type

  TTestOneAtTime = class(THashLibAlgorithmTestCase)

  private

    FOneAtTime: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '4E379A4F';
    FExpectedHashOfOnetoNine: String = 'C66B58C5';
    FExpectedHashOfabcde: String = 'B98559FC';

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

  end;

type

  TTestPJW = class(THashLibAlgorithmTestCase)

  private

    FPJW: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '01F5B2CC';
    FExpectedHashOfOnetoNine: String = '0678AEE9';
    FExpectedHashOfabcde: String = '006789A5';

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

  end;

type

  TTestRotating = class(THashLibAlgorithmTestCase)

  private

    FRotating: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '158009D3';
    FExpectedHashOfOnetoNine: String = '1076548B';
    FExpectedHashOfabcde: String = '00674525';

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

  end;

type

  TTestRS = class(THashLibAlgorithmTestCase)

  private

    FRS: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '9EF98E63';
    FExpectedHashOfOnetoNine: String = '704952E9';
    FExpectedHashOfabcde: String = 'A4A13F5D';

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

  end;

type

  TTestSDBM = class(THashLibAlgorithmTestCase)

  private

    FSDBM: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = '3001A5C9';
    FExpectedHashOfOnetoNine: String = '68A07035';
    FExpectedHashOfabcde: String = 'BD500063';

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

  end;

type

  TTestShiftAndXor = class(THashLibAlgorithmTestCase)

  private

    FShiftAndXor: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'BD0A7DA4';
    FExpectedHashOfOnetoNine: String = 'E164F745';
    FExpectedHashOfabcde: String = '0731B823';

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

  end;

type

  TTestSuperFast = class(THashLibAlgorithmTestCase)

  private

    FSuperFast: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000';
    FExpectedHashOfDefaultData: String = 'F00EB3C0';
    FExpectedHashOfOnetoNine: String = '9575A2E9';
    FExpectedHashOfabcde: String = '51ED072E';

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

  end;

type

  TTestXXHash32 = class(THashLibAlgorithmTestCase)

  private

    FXXHash32: IHash;

  const
    FExpectedHashOfEmptyData: String = '02CC5D05';
    FExpectedHashOfDefaultData: String = '6A1C7A99';
    FExpectedHashOfRandomString: String = 'CE8CF448';
    FExpectedHashOfZerotoFour: String = '8AA3B71C';
    FExpectedHashOfEmptyDataWithOneAsKey: String = '0B2CB792';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = '728C6772';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;

  end;

  // Hash64

type

  TTestFNV64 = class(THashLibAlgorithmTestCase)

  private

    FFNV64: IHash;

  const
    FExpectedHashOfEmptyData: String = '0000000000000000';
    FExpectedHashOfDefaultData: String = '061A6856F5925B83';
    FExpectedHashOfOnetoNine: String = 'B8FB573C21FE68F1';
    FExpectedHashOfabcde: String = '77018B280326F529';

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

  end;

type

  TTestFNV1a64 = class(THashLibAlgorithmTestCase)

  private

    FFNV1a64: IHash;

  const
    FExpectedHashOfEmptyData: String = 'CBF29CE484222325';
    FExpectedHashOfDefaultData: String = '5997E22BF92B0598';
    FExpectedHashOfOnetoNine: String = '06D5573923C6CDFC';
    FExpectedHashOfabcde: String = '6348C52D762364A8';

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

  end;

type

  TTestMurmur2_64 = class(THashLibAlgorithmTestCase)

  private

    FMurmur2_64: IHash;

  const
    FExpectedHashOfEmptyData: String = '0000000000000000';
    FExpectedHashOfDefaultData: String = 'F78F3AF068158F5A';
    FExpectedHashOfOnetoNine: String = 'F22BE622518FAF39';
    FExpectedHashOfabcde: String = 'AF7BA284707E90C2';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey: String = '49F2E215E924B552';

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
    procedure TestWithDifferentKey;

  end;

type
  TTestSipHash2_4 = class(THashLibAlgorithmTestCase)

  private

    FSipHash2_4: IHash;

  const
    FExpectedHashOfEmptyData: String = '726FDB47DD0E0E31';
    FExpectedHashOfDefaultData: String = 'AA43C4288619D24E';
    FExpectedHashOfShortMessage: String = 'AE43DFAED1AB1C00';
    FExpectedHashOfOnetoNine: String = 'CA60FC96020EFEFD';
    FExpectedHashOfabcde: String = 'A74563E1EA79B873';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestShortMessage;
    procedure TestOnetoNine;
    procedure TestBytesabcde;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithOutsideKey;

  end;

type

  TTestXXHash64 = class(THashLibAlgorithmTestCase)

  private

    FXXHash64: IHash;

  const
    FExpectedHashOfEmptyData: String = 'EF46DB3751D8E999';
    FExpectedHashOfDefaultData: String = '0F1FADEDD0B77861';
    FExpectedHashOfRandomString: String = 'C9C17BCD07584404';
    FExpectedHashOfZerotoFour: String = '34CB4C2EE6166F65';
    FExpectedHashOfEmptyDataWithOneAsKey: String = 'D5AFBA1336A3BE4B';
    FExpectedHashOfDefaultDataWithMaxUInt64AsKey: String = '68DCC1056096A94F';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt64DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;

  end;

  // Hash128

type

  TTestMurmurHash3_x86_128 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x86_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000000000000000000000000000';
    FExpectedHashOfDefaultData: String = 'B35E1058738E067BF637B17075F14B8B';
    FExpectedHashOfRandomString: String = '9B5B7BA2EF3F7866889ADEAF00F3F98E';
    FExpectedHashOfZerotoFour: String = '35C5B3EE7B3B211600AE108800AE1088';
    FExpectedHashOfEmptyDataWithOneAsKey
      : String = '88C4ADEC54D201B954D201B954D201B9';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey
      : String = '55315FA9E8129C7390C080B8FDB1C972';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;

  end;

type

  TTestMurmurHash3_x64_128 = class(THashLibAlgorithmTestCase)

  private

    FMurmurHash3_x64_128: IHash;

  const
    FExpectedHashOfEmptyData: String = '00000000000000000000000000000000';
    FExpectedHashOfDefaultData: String = '705BD3C954B94BE056F06B68662E6364';
    FExpectedHashOfRandomString: String = 'D30654ABBD8227E367D73523F0079673';
    FExpectedHashOfZerotoFour: String = '0F04E459497F3FC1ECCC6223A28DD613';
    FExpectedHashOfEmptyDataWithOneAsKey
      : String = '4610ABE56EFF5CB551622DAA78F83583';
    FExpectedHashOfDefaultDataWithMaxUInt32AsKey
      : String = 'ADFD14988FB1F8582A1B67C1BBACC218';

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestRandomString;
    procedure TestZerotoFour;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestWithDifferentKeyMaxUInt32DefaultData;
    procedure TestWithDifferentKeyOneEmptyString;

  end;

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

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCheckTestVectors();
    procedure TestCheckKeyedTestVectors();
    procedure TestSplits();
    procedure TestEmpty();
    procedure TestQuickBrownDog();

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
    procedure TestQuickBrownDog();

  end;

  type

    TTestRandomHash = class(THashLibAlgorithmTestCase)

    private

      FMurmurHash3_x86_32 : IHash;
      FHashAlg : array[0..17] of IHash;

    const
      InputHeader : String = '4f550200ca022000bb718b4b00d6f74478c332f5fb310507e55a9ef9b38551f63858e3f7c86dbd00200006f69afae8a6b0735b6acfcc58b7865fc8418897c530211f19140c9f95f24532102700000000000003000300a297fd17506f6c796d696e65722e506f6c796d696e65722e506f6c796d6939303030303030302184d63666eb166619e925cef2a306549bbc4d6f4da3bdf28b4393d5c1856f0ee3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855000000006d68295b00000000';
      InputLength : array[1..16] of Integer = (17 , 31, 32, 33, 34, 63, 64, 65, 100, 117, 127, 128, 129, 178, 199, 200);
      ExpactedValues : array[1..16, 1..19] of string =
        (
         (
          {SHA2_256          count  17}
          ('0fd3f87ae8963c1ac8aabc0706d2ad5a66c2d88b50f57821b864b093263a7a05'),
          {SHA2_384          count  17}
          ('86b2d0189776966214f3469254c4a2e9d4fadbb81aab5d9ef8d67f085301a5128758c8f3b9b89d8d4460c684fe181a58'),
          {SHA2_512          count  17}
          ('f729f844e23dadbfcb53c046407f03e790a7a9ec6004c570feea461f76b066353dfc5cca95629360d5ea310719bf6f0251a56e9c515b62b863206d6ff64b6784'),
          {SHA3_256          count  17}
          ('84b6a1cf6df74b3a54da73cf2ae3bca8426fba94908199bba45ba1ccc8f680d8'),
          {SHA3_384          count  17}
          ('ee2621cc2dc6f234c8976a1ac76a1eb8724213c67af5a704ba56a7bc92f09e146e1a1d7d0a5a4ae5405e8b9295fdf216'),
          {SHA3_512          count  17}
          ('36b8e099d4afb54a9aadb5c76154be673a96967a73e462fb401c21282a2c4554b832f323415c047156e3452e77070a085d14543b123b473ed93d03248514898c'),
          {RIPEMD160         count  17}
          ('734191cffedbbe96f14865d2eebe3650e54c6de6'),
          {RIPEMD256         count  17}
          ('b242099231d61f0d6c83044d360524b499a434d0ff12407296d1061e017bd023'),
          {RIPEMD320         count  17}
          ('3d9cd1561f939f3aa80ee5339fa11140e68f3dbcfdd928d4d31f6932a268bba329595cc1e347d06e'),
          {blake2b           count  17}
          ('8f8a1cf77aad3d0421db8ae7b2a4752b811059d3a3a5cc3b00454ecd918f39936e2f8e23c5a96c6f4519f76e73981da24d2f8c4d3ef4e7002a17eef80e2a9514'),
          {blake2s           count  17}
          ('c6d5f10d213cfa97b3317f115f6eae29419051524f14f29b39c4f620a6e4758d'),
          {Tiger2_5_192      count  17}
          ('31f8163acae71a73f662828258b8506f2d8d65062b550d71'),
          {Snefru_8_256      count  17}
          ('93fdb3c044cf11b551b7527a59c9eb9cfb1716adc8fc0e1926b246038677968c'),
          {Grindahl512       count  17}
          ('0b25b53c3812cb38fee71eae043331d5486154d4277d63f571ed7621ba1f38816163c16e6445568cde5dd4926249a2293b4c96f1e99d7f0697e9b0be24987fd9'),
          {Haval_5_256       count  17}
          ('1c3afb53f06ade5399c4797800b44abc301d9faaf698fe66ca36b18a26da5153'),
          {MD5               count  17}
          ('990d2e3e54e0d540e17e28bf089cbc8f'),
          {RadioGatun32      count  17}
          ('65024d09e2b8a46d8b6a2aa87af2445a9d640a74081e5d7a33062307a1c47b0d'),
          {WhirlPool         count  17}
          ('eb986421c1650306056d522a52f2ab6aec30a7fbd930dff6927e9ca6db63501c999102e1fc594a476ac7ec3b6dffb1bd5f3e69ed0f175216d923798e32cb8096'),
          {MurmurHash3_32    count  17}
          ('ea99253f')
         ),
         (
          {SHA2_256          count  31}
          ('209ef563d4ac7d51968cced180be0145dbd4d4c9688bdbdd8fcdb171029bff35'),
          {SHA2_384          count  31}
          ('f19c9457db4e320f0a795dd911f46e4def8e57f567b0e058eba7ea7de7277e0e0cf9467d567f3913af7bd3812a999901'),
          {SHA2_512          count  31}
          ('526be8f0afbc7ffe77f62456f8d47b2e60bdad5ff1955841d9bcf82d9a2c71a9a2bdf4288d025154ff43ba65b4d4adb97ac24f47c27a28af7af0b2d831c9c7a2'),
          {SHA3_256          count  31}
          ('49128a80ce9b14b46c310adcdfc0be99266ecd0728b4a12a7fdaa000d49c4106'),
          {SHA3_384          count  31}
          ('cac5638f7c264b72d01942b8109667b44142293cd1ad7bae06bcca65d82a5f72daf27070b17702415e9c3d501658ce57'),
          {SHA3_512          count  31}
          ('dfc10d8ec28d43efe3cbba1c1e1edcb6f71c14d9057941afc590469350402e8fe1298de2ba20eaa8280dea009668d5dde5f7001b65fb9237284c8b60e6bf4e8f'),
          {RIPEMD160         count  31}
          ('f5c19350c4a7a79f1597b7172ff52205864c92e7'),
          {RIPEMD256         count  31}
          ('e71778fbcc7b32156c66e244a6a07d10e463bb20cc35ed98c8cf35191ec013d3'),
          {RIPEMD320         count  31}
          ('62dabb157501ee8aee1e7364942774f5741ed806f87f31d3754e956cda45c3423d31d5675cd7fcdd'),
          {blake2b           count  31}
          ('4e074ec035707651726210950e241346aec8f6c6aaa504f416cd0ec92fa4c08340cca3827fb990d74b8f837c0bbafccb2d5739f2b59ff49cce5cfa4f285e083f'),
          {blake2s           count  31}
          ('2c82e8af7b3db4a4737546616f34026c0acdf0c2037ba138861af29e34b2eaff'),
          {Tiger2_5_192      count  31}
          ('4c3a22c2d96ab29ad12100b1f2cf6c52b0f75f4c75f049d3'),
          {Snefru_8_256      count  31}
          ('fb7c3d09e37f3388d9a90ca09c87cea58c6efbb8462562f7a4572a3eea194ed8'),
          {Grindahl512       count  31}
          ('9c8b6c9737348ea89adf7d3742344c416ca80e70d0c1a574b66d03c3a51fc363645a09b07e6804705726cbb0fda30ad755713f10b1dcd4bbc71d8d975401766b'),
          {Haval_5_256       count  31}
          ('4cccbbaf8e991a805626c96f3d2850862ae7e77e970a6e7b818444a7c92c8cf9'),
          {MD5               count  31}
          ('5120a7106123521029896a89890decbb'),
          {RadioGatun32      count  31}
          ('32b17be7c6fedb037515313b5604e1661ca1f34e282107e20d3e907864751421'),
          {WhirlPool         count  31}
          ('8ec8f6838a7f78f9a1104a15e6e51f690b8bfe69e412438a6591dd90ff1bdee732ee32b75eda9d679900081a17e10d1dec77fdaa109a6ede060bbf3fa7959a8b'),
          {MurmurHash3_32    count  31}
          ('1553afc2')
         ),
         (
          {SHA2_256          count  32}
          ('a910d364190b6aed1c0a4198688a1a5ac4b37205c542d665be0f5aa558ad483e'),
          {SHA2_384          count  32}
          ('60e13c214f9ecc37ab48c67beda727612a635d9e67114c83b34ed44753a65d00a424fbc812f1ec16f93079d7ae97a939'),
          {SHA2_512          count  32}
          ('3bbcc5f450e9b6708c22ed0ba40b5265d3b32130b9ffdcd06bfc61c49452aaabc8bf08df544f55935952c80d0e266f27f3f66ab4aa1b2f3e7b58ee0708200d79'),
          {SHA3_256          count  32}
          ('60c394688e6a2eba3d14edcebf6b13c95eea80a458bf3f557e55df0dd710bebe'),
          {SHA3_384          count  32}
          ('509a74fbecb9d7cb23838a31bcd8447d73ae0893d2a60c53d6327467a2861e07b39ce800c01329ae2e06d1b3ecc905e3'),
          {SHA3_512          count  32}
          ('e4290dafe0838e10c8752074731d7fdb76c4d5d632f75f2c508b357d344c622b8e5aa9ba1d58f4c859bb49b4b81a25c1faecbc08317ceafc00e1c3a9945295a4'),
          {RIPEMD160         count  32}
          ('29c74325055e81d14d7165c28599e311c9b63c6a'),
          {RIPEMD256         count  32}
          ('d538e7bdd392ee4ec094a2a50cb6edec45537a87fd8f4a72a7fc573cd5ce43c7'),
          {RIPEMD320         count  32}
          ('286cbc2d0bd027673fdb6165c0281f3beabeafa2936d0d2b651010b473faa68fbad54c663c9d0fa2'),
          {blake2b           count  32}
          ('cb2c167bbad4d529cbdc48645756cf61b3838d6c0af14a9596dd105a172053e198c22c3669a792949274ff1ed687e80e4ae3b85ec70154a6f62d2cf13231b083'),
          {blake2s           count  32}
          ('c661e40d5ef223343c2513b19b0ba5a69c91e076be875c854830345de2741517'),
          {Tiger2_5_192      count  32}
          ('5072d1575f95f75eb22169647a0f5b774bdc21dd8896528f'),
          {Snefru_8_256      count  32}
          ('c5c78eba6dae1f3c9aefbe8e6608c60889dd8c648efc7b02befccd8bab46c54f'),
          {Grindahl512       count  32}
          ('04790923e624227751ada31cb344e77ba8cfabea22b9d09fd2f0a867d679e8cbb70665be0fe81554d1a2add1b69bcfd59c8fa452dd7847461c688da80a22df5f'),
          {Haval_5_256       count  32}
          ('c5b81863a6c8c1ac6cc3f429a7fce6ff6ecb1f459856d241f5c5f1820f229927'),
          {MD5               count  32}
          ('49848dfebea23abc37872a22bb76e1ea'),
          {RadioGatun32      count  32}
          ('ff4d011327d8dfccde7901523cd044fdc8c89479a831a61a8179ccb1eb6b34e7'),
          {WhirlPool         count  32}
          ('5687a34495d2ebe57ee157fb0eb4c9674079d6ce97d70a091abfb92fb0096f2065197ea7379bbbfcb10a148beec4381bf2dd3662bcaeb9077a014d5d51acff7b'),
          {MurmurHash3_32    count  32}
          ('9146e5ee')
         ),
         (
          {SHA2_256          count  33}
          ('8f2d5d44ca1a2f534253a600c4e95f315133f775127a11bcb22db928efbd638d'),
          {SHA2_384          count  33}
          ('dcc50f12c899f09c44901c549aae1d3d7341b2c6b78f2e566c671631d8df1e74ebf5b74f5230b92401ba9b74e75a4e67'),
          {SHA2_512          count  33}
          ('10279e84bf5f4debae99ebb1c2186a3b5a510da642c99cb77ab981f39fbf55d20ef70fcb19880b86929dd7db3a4b2259b4b86d82a38b200933d550c42d729a57'),
          {SHA3_256          count  33}
          ('feb0146e6af5c99e7dc931f28fa2c965c1e16a9360bb7fc5eacbd6658115b114'),
          {SHA3_384          count  33}
          ('cd6c73588fce7db1f3d59bdef9f544b6f08b2c50ec0b01dd012700d4274b80f4d0ff20ca774b27f04b31ef9f19bf0cc9'),
          {SHA3_512          count  33}
          ('dde23aa602cca8efcfa9b026cf067ada1b8bc5487b4dc029b31621294d5be3954e402ddfb4e5f9a0401648e6e649a0f05f647e61457289f705ee167c86f6c3db'),
          {RIPEMD160         count  33}
          ('1f54c3702f8dff024a6fae7ceb017a64f71b15a6'),
          {RIPEMD256         count  33}
          ('7e1bbb5611223834cb1cee497b700c70cc27bbb042c2431fccd4ec67965567ee'),
          {RIPEMD320         count  33}
          ('921c28a7318df3bfca84091eb48ae54808fe79e9a24d716b641c61108272114a7c3e21614b316eb3'),
          {blake2b           count  33}
          ('9a8a4ea7bbaf058c07a62a9f13de219abb2bd99738a7997bfaa373d61ce54c6a0ede112cb652d40682ff804552f9db4247de5858c45ccb9a8ac064881f05b92c'),
          {blake2s           count  33}
          ('fae74bb4a48f325c4380ab694ed91ed6b0bb5d8eac825ae8ade73d4b7d7d1cb7'),
          {Tiger2_5_192      count  33}
          ('3fb8ab4e655028dbf2aab6ebeee5996a93fe0b4bb250fb6f'),
          {Snefru_8_256      count  33}
          ('448c94af0ceddab0a6c2d06eda05f3ad6484512cccc61fa32f902a8e9021b851'),
          {Grindahl512       count  33}
          ('d0af72a4c6ba8d8a690405f09c794030ae8c134df8ca60af5de4cc71458c0accba769abcb7d1c1b833921d52d44bec149d35110a98d03776ab9fc576f44044cf'),
          {Haval_5_256       count  33}
          ('6453387b3f0b6d6dd6a8343cab021ceeedef2f8fd852ab35a8aa5472f3653909'),
          {MD5               count  33}
          ('62b3040c9f11e5ef68f5b029beffb3ec'),
          {RadioGatun32      count  33}
          ('92dd5fbface846262b32ebca67a20fa571a87c435c11daacaca4cd96da4c9c2a'),
          {WhirlPool         count  33}
          ('017cf76d956e88528f0d1f48dbf895c645f0d9a7269ea21df15da6e24e15d711edbf88f0a6872c2074afb0f5c2905291395862b02e06019ffea960aa92ae7f98'),
          {MurmurHash3_32    count  33}
          ('9d9efa16')
         ),
         (
          {SHA2_256          count  34}
          ('da8f41e9f2ac0effa4815a50f599b0791f210cb85f056672404639c960f56fe8'),
          {SHA2_384          count  34}
          ('f8a0491ef325a3af1ed02eac4e9bfd7ef645a1312318e0b5189300850ead5016194c39af296643dd5230c3b5cfa15479'),
          {SHA2_512          count  34}
          ('b5c4f53ee9d151543fdb42640650e4ff930d2f145ce1986d6a8b3b1860a0136ec889e4f02675a99e0118430c9c8357f974ee99d0e52b62b92016ac2c6833af5b'),
          {SHA3_256          count  34}
          ('c247d6b3649e736004601810655ba1e7041c40a73ee5fd5d408e891a90f38dbb'),
          {SHA3_384          count  34}
          ('ad76006715dd48f0138420ae2c3bd7d5e64ba735a307323c00192acbe837cec5cbe04312a1602ea757de41f18d0fde7f'),
          {SHA3_512          count  34}
          ('a54f15ec275b53cb618ca462bb0de1776e1038f2cbc40df2da6a7e5e1333ba475fcead9e0c55e357547feca9a973f781bc9e601c7570a0f510414e27167be834'),
          {RIPEMD160         count  34}
          ('1068b29dd5bd6aec7cf04ffc1ef671cf83e7f239'),
          {RIPEMD256         count  34}
          ('a73d52f35585f3d4dd34850bf3e8de4697ad1f94cba71321d6784785f29ed905'),
          {RIPEMD320         count  34}
          ('d569a0217a6bbbbd99e6f54899f14078adccc06b56be014bf3f25493763c7f6ebdb76fb0d187d0ba'),
          {blake2b           count  34}
          ('a7651109edfa702d76471ad0c4ffaaed200f5ed783a4ad834ced1b37bf4038af8472d767a7b0d08e146e079c4467468df30d89f14ae59fc75ecf927717abecdc'),
          {blake2s           count  34}
          ('d6010f74459a82f459604a044fb2d21d93904427c44ebb22bd76694110fbf9df'),
          {Tiger2_5_192      count  34}
          ('026780bd79297995ef4b5e0d9cbdb1fdb4f6df4aa94abee6'),
          {Snefru_8_256      count  34}
          ('99bd6565cf0c34bb93b74c81e68c5c096731e927c04eb374032e5507ce20175f'),
          {Grindahl512       count  34}
          ('fcfd8e4226478060980bc67a6191f55e772f44327897ea518ed092277112de8e8df8780c630f712a4ee2b4387d945e20e9d1628c5d513ea5ae61f9f2ea476cba'),
          {Haval_5_256       count  34}
          ('71dd44d1eb0ced6208ac71360611b7ac50cbc49365c135fa253771814f8fd224'),
          {MD5               count  34}
          ('61c9c3ec798fdb6fc587065114a093b5'),
          {RadioGatun32      count  34}
          ('289590b6bbe0da22917b8d62b5752c4ea032de707e753d98771da87e7a6f68d9'),
          {WhirlPool         count  34}
          ('c5ef49c4ba2aadecadd8820034378e53174d66b6bee6583ea3d36dde0ebe652be2571f9c5713e38e98f433817b3cfd4d633e3cbf62e6091943ed241c0b8cae37'),
          {MurmurHash3_32    count  34}
          ('deffbebf')
         ),
         (
          {SHA2_256          count  63}
          ('b06a88f708c40510cc132a5108c6f26a9a3f7f6d42e0143baaacaf96aec16952'),
          {SHA2_384          count  63}
          ('2adbfe51413f5d3458581dc9b9ce713b6e96ff6208fa4716cd012710e6a2d834681d32b1915e661ebfcf8dedecc08c85'),
          {SHA2_512          count  63}
          ('a35de82665a3c12424e5a11acc356b329a56b15bee61c2332ec04fee142ad7699f9834800e127c0146827d8b84ad1ce0b57f2c5ed30afc0768e098a5d621dd97'),
          {SHA3_256          count  63}
          ('d3e6fd4abf153070e11446c6dd1cfe748064239a9f680437a4b1d51c5c64fa2c'),
          {SHA3_384          count  63}
          ('ddc1e64c8420ff5579eceac10844684d08cb769cf578925e59d98c79f5be736524ff44738a16543bba47d70b1ebcc36e'),
          {SHA3_512          count  63}
          ('6971211bc158034f3420850303953d8845f9657871af4d35d71f75eb086e69c07f4e63eb173962d53279400688ae3637d2fd742255b93e3ab6bbe1b203243586'),
          {RIPEMD160         count  63}
          ('5de126808d8b2656c8f91796eb2dd86a9fe65ad1'),
          {RIPEMD256         count  63}
          ('48d647a2e1dc581b675daf26f0d08a11fff402a42c47d132f52133bb8a6895f4'),
          {RIPEMD320         count  63}
          ('ffac8eacef53c8e9c9b9628ae080dbf8b50d9ccef6beaf0fc318f0921aeaa4624e478b48dff801fa'),
          {blake2b           count  63}
          ('e24f626b1a12d956231a7bf17d7f976925cc186776da91543eb9b244454bc0b71956bce4e514bf1095fc61097eb39d67dc78ec6c78e640bcfb18fd110adaecfd'),
          {blake2s           count  63}
          ('0707f52c9629e5d926d19aaac0e31f96273627ddfbb85519f4d2abdda8107459'),
          {Tiger2_5_192      count  63}
          ('c45fc6510ee3ff3503c4c8795d3d27da2fd4f81e5edef179'),
          {Snefru_8_256      count  63}
          ('81a91002867a3e930493d9c833655165c63062ea66d65c45f2b1b29fec0d245f'),
          {Grindahl512       count  63}
          ('24b3f7df2ac9e96aa9ce2245e77a3b96a5c1c3c9d070f6806340f65ea9478d4b92ad48b0289d2540a4dc62fa511243eb7ca9808b59425ecc12343b8aff83d4a2'),
          {Haval_5_256       count  63}
          ('09182c9035cd025d5cca7f2a9525bccdf8314d6c03419987a03a0bec59e76e38'),
          {MD5               count  63}
          ('89973c44bb3e207dc60d789e3b9b482b'),
          {RadioGatun32      count  63}
          ('da5cf1e7f0b880c419201aeb2f537fe27594d9e239b738f1bc677d59f2927923'),
          {WhirlPool         count  63}
          ('9d3afbcb5b7bb86e27378090dc4664abc46f87bd69dbdf2481a5a1c25ebc216eeae5bd9a900f996d1fe8749c7127986602bd1221b73ea7c3cebcfd2fcf529773'),
          {MurmurHash3_32    count  63}
          ('56311c1c')
         ),
         (
          {SHA2_256          count  64}
          ('3725408cbe6e81f8a05bd2f1b4618a356235b7262eb809608bc4e3dc38e4fa1f'),
          {SHA2_384          count  64}
          ('483f8d2065879e98c9640230d85cfffdcbf99543d7a2f24c045cf08ef8f53cb5472c93c1cd3655f35903ac91926ed2b8'),
          {SHA2_512          count  64}
          ('6dd15a36cb5ae97d7ba0c74e19adea2bb4c243839f58aeef83cd8527e87c43069d0a02804dbcb281636b8712f6e546f31946318a709019ed11f3816642eba77b'),
          {SHA3_256          count  64}
          ('c5d9eea9c7d04746dde6e94cee94105a5d1f173809849c2d2953e31b3af5d556'),
          {SHA3_384          count  64}
          ('f29ec08d00ae2072137288e31990f2858629e23d2365a84a079cc5986dbcff1b16a19216aceb079e240e89626644bb3e'),
          {SHA3_512          count  64}
          ('dec734f489aefcd5ad355134ef6fd1ebb18c8f741d16e0fedb201dd801905a7f39c2824b67b2b995679c8266530b527e2dd2af59f044cc5d034d93bc7c35efdd'),
          {RIPEMD160         count  64}
          ('bf4c1c78a8e75584c6697fc2f1706e0c41c9df59'),
          {RIPEMD256         count  64}
          ('2cefa11f6ea8dddd1d0c935b4f04f36c1631b1589eea6082ed53b3e9b54cfc72'),
          {RIPEMD320         count  64}
          ('47f9c63000e89707be545cdf37e3697128b6ca013ea59ce576437125a35b94a1fc12b4568c2b42f7'),
          {blake2b           count  64}
          ('55de09270df2b8f2b8c35f082ae45acd55fca556fb4c7614a61531888e7d5502a2015b0c936fbddf4f6ccfcdba4d4e69139be2062c42a6b1acc03638b035d55e'),
          {blake2s           count  64}
          ('c55f4dc5612258bd600c4b078128919dca82a4f98022b9762826d596356dda14'),
          {Tiger2_5_192      count  64}
          ('7e056bc56de5385d47eb3e3a218b5cab1894449b8e0b55fa'),
          {Snefru_8_256      count  64}
          ('565e627a7ac890df042565377b1413b30ff2fc1bafa861fa9070526375936299'),
          {Grindahl512       count  64}
          ('8830b562ce16b7afaf42dcb1af79624856cdea734b88f7b9f26b147f6e8c716aa0bb48b329ffee5ba8d0a37f205de2dcc0d9359e7e133aae14a201d22e82e60e'),
          {Haval_5_256       count  64}
          ('d6cc048cdd7c944ad99b1bb8ff9b48bf8f8ecfa783369e3d008902fedd98009f'),
          {MD5               count  64}
          ('e2ae3f3eeffb99c0b46f12254ad6eb4e'),
          {RadioGatun32      count  64}
          ('9b21fc33aa89b1a709c0af3b0305ee0ce491462ea34900d52f44682938f8b5ae'),
          {WhirlPool         count  64}
          ('0a2cf63dfda157514c4d9a54198265b7d09100922c8a6431d2b29b62c74f0ad7a0b0c661005aa686d5e2cbb5cab76563ee883bcbe52a4f4f32f2852ce3793b4c'),
          {MurmurHash3_32    count  64}
          ('4dd59c1e')
         ),
         (
          {SHA2_256          count  65}
          ('af29a07c4c9ca57aa087a3c6134573615ec8b54706c75361cfd23fba38d8a5d0'),
          {SHA2_384          count  65}
          ('c4397852b5944238dc167821e2f51e80ff736c0050b1abbd0400c8db1eeb4dc17e1fdc0ed9a0d61d2e2bc29ebbb583b9'),
          {SHA2_512          count  65}
          ('a2433136dc3bd4f0e2d4d14b6033e1002f675c4ce842d7baeee78b95193030c647af66f0e54ff94ae3b60e46a88314a4a145f30267f3fd0990c6ebc2970b9fbf'),
          {SHA3_256          count  65}
          ('81bd225df0d6dd4ed5347dbf688b4940b9a0f085db9a5efd8fa4dddf5bea2e9d'),
          {SHA3_384          count  65}
          ('9a0bd293ed9ea460387266b65773bd73cd8c5c6ccadc0d1b901f35d1e82571a10b63bb90beeac3e1a0fc29786da0beb1'),
          {SHA3_512          count  65}
          ('40b460c3f18d2c0aa076db67af63c3d22a6c3d29853ca642204d3ff5b0649b394f2e10beaf78be0929cb499b24323462ad7242a3e3e9c7b7a89a58da4358d1c5'),
          {RIPEMD160         count  65}
          ('79123df7d67e2a3c3cdf3f1529deac143d44ca8c'),
          {RIPEMD256         count  65}
          ('5a2a91bab4ca44664ef1d16fb8f8cde48ba2dca1cc0c0faa636812b86b98fe3f'),
          {RIPEMD320         count  65}
          ('0047b303eeff27dd6d3fd9ad838cb3eaac2d06b9f909729d449052bfb648c522e17f23beef18e14f'),
          {blake2b           count  65}
          ('51a424024d3eb88e2cf09e14e512a6ce27b1a95a087afe07c5138e191cbf8079fd740a262e47e6dffad44355548eebd2c1ebc24c8b7bbf266573b838a6b70ef8'),
          {blake2s           count  65}
          ('7ce4f4e9e7357f74f15903f273a285e02d7fa976e94ae900d9a14b131f397aec'),
          {Tiger2_5_192      count  65}
          ('6b6e1f82c0ea6b6a4b40678c8fd1d8ebdd49f3dc657ebc6a'),
          {Snefru_8_256      count  65}
          ('0116ec1a605e1c56137427e06599be0bfc243a191988a4ced8a5b461b6f9bf67'),
          {Grindahl512       count  65}
          ('cca9753de1a1a717c1dfb06a1b9fd3bc7bb01ef228d2b10ddbb8e36fcfd30ee2ce6fb4b63c091506cef5c5458f89dd11991b829a817870fa25253697d369265e'),
          {Haval_5_256       count  65}
          ('e7e1ead7bad22f210bfe98825022a71e9ebc8b85cf8710b2ef6fb9e457fb96db'),
          {MD5               count  65}
          ('3c2b0369b053d0df325c7343f0a5401a'),
          {RadioGatun32      count  65}
          ('c2856589442488830608c6d9669f1d93bdb39c83616294499b36dffba17d2bc0'),
          {WhirlPool         count  65}
          ('fe6b3567fbbb1f1490d263248ef4f8ee7136a0c7627abb229c98fb90bd91710a15f135dffe1ab84a31984b3cc4869e870e64168efead9b8921a6139cd84b387f'),
          {MurmurHash3_32    count  65}
          ('a96e7dea')
         ),
         (
          {SHA2_256          count 100}
          ('30cb592bdaf02c26fcba00c055059d9c3cf74f10a7eb49e2fcd4926c86c85e00'),
          {SHA2_384          count 100}
          ('5526d6e720647cc23e1ab86a51c8e8601579b6952e5d610c4b450e41292e6acb073439b91fcdd75041f475530c033323'),
          {SHA2_512          count 100}
          ('a55acfa8808e502b5f02e23f6f824b56fbf6e8bba3f032d7ffd5b254200de521299a4e8f593c453c1483773cc78332d54f1016af2cbddac68ae7fef7aa399219'),
          {SHA3_256          count 100}
          ('5746f720dab78746407d4c594fda4a2539949183a0208553c8aee1d578b72898'),
          {SHA3_384          count 100}
          ('addb1229b53c3a35d1f974cfe7a1c3a6f6803996d72cbc13bf50376b85105b86b1fdeacdbe51525928e39e38ff23b1fc'),
          {SHA3_512          count 100}
          ('480d6ea46a25eeb45a2eaa1a23304d68dba624635772d26a21fe8fe56376de8d298bcb5f5d48e59aa6193a55170ae5a1d15f4f8dfe7fdef7706c0686eb39862f'),
          {RIPEMD160         count 100}
          ('ef7cdf0a7ded768b4675a743ac7ab64c3bc5fad3'),
          {RIPEMD256         count 100}
          ('a5fbe1faca66cc5d5f5dcea2550811254f221fb8761c4b5a3caf31f2f0534ad0'),
          {RIPEMD320         count 100}
          ('d9eaaa5d3dbe16e6d2d06b1fdae8f5a6893303f82cf7ec838ee1b94a37ba2ecb8ccb008c149586bf'),
          {blake2b           count 100}
          ('03cab91f85e1ffc286a297538200b80b39681f5fe06108557c354264127db6aaa271399af25c2cb240554921b3d878675f875dd244a7af22187015945b105558'),
          {blake2s           count 100}
          ('4be6010f72c375b685dd57d66585b8c5f86eb1ac27b80ca20f041d44533a7005'),
          {Tiger2_5_192      count 100}
          ('cf38de0d363bb17ee67f510900a48f156fc9e8429097509f'),
          {Snefru_8_256      count 100}
          ('2d5fc09951112a362dc542262351087594e3643160cf87733ef6bc48d9cbe673'),
          {Grindahl512       count 100}
          ('ead32ea9bb5b7db55c19895cf6b9ea82bd17ee4a56ac508f3bbeb69a0e5f4df8cf492a02ea5db195f74e6101314ae4917758e0642e8981d947c1dfa16cf651b0'),
          {Haval_5_256       count 100}
          ('ef0ecb677bee8f32a0e234f9f1944528a17f2e148634d7ee99d490c21898b245'),
          {MD5               count 100}
          ('98e0bd2b4eb38f4d7e6d33d1cb5fbc1d'),
          {RadioGatun32      count 100}
          ('bbda668f9d7b3cb2729b4a6a840b48ce3f938864d41a37a8b6c1df0926923291'),
          {WhirlPool         count 100}
          ('c95fb60f44a4eeb27cab9718ec3e3e6bdcd4bc3e2e59124f64defceeb17acf90121b65bf4693ae094e76f0db8d6f309a8531a474b53f49d5c4a7686fb9261d4f'),
          {MurmurHash3_32    count 100}
          ('61afdbb2')
         ),
         (
          {SHA2_256          count 117}
          ('1e34859b3591e50f8522d707a554725591603b95725d8d16f9dc728f901091d4'),
          {SHA2_384          count 117}
          ('7ade74e0a89e7ad77e76e9a35c04f67c933d8f4cab485d1628b0ced9ccc17f447ba38f81ebac28a4618abc006af4e5b4'),
          {SHA2_512          count 117}
          ('b4647f67deb7347a18d43d87a4143853855fd81602baab1edd8a08b32a74268adb12fc03b6d1a05d81e67dc75fa93386749dc1d40d988a685ed1550a5849b527'),
          {SHA3_256          count 117}
          ('ade65df24b483b5d51e8620dd05966dd89b96c90b69322c19d67c3a968f5514d'),
          {SHA3_384          count 117}
          ('5c142da18a1e2b0f66f396e07cc102106227638a93d9cc5230b2c8ade550fab096049acb53fb5b357039983b77193460'),
          {SHA3_512          count 117}
          ('5b7e1c31bf4358a77f1afb7f2c181cde1bf87b3d9e94fed09d82a996364998ee3e46b9e7ab94337ad967878741475b2d11061de00d06e1db3026e2859ca2af32'),
          {RIPEMD160         count 117}
          ('fb82dbfbb359e2f5fd3bc0a00a9bb7e873bda70d'),
          {RIPEMD256         count 117}
          ('f8cace5bd4fc6711706e6c3cfe9713234d40e4fafeb37b5dbe97c13c37f6ebc9'),
          {RIPEMD320         count 117}
          ('deff952e2a54873158c0cb880eb8c813f03716649006b9026dd9ba1556b9be4058ac4091c36693ac'),
          {blake2b           count 117}
          ('e9ca855bf340229a4446f46cb0b0e3cffaf1942b8a8b6e296d5b35621be9e6c40217a76d1461380d062e9f0ac8cee8e15b70b7762a6de367463ac84c4d56b49a'),
          {blake2s           count 117}
          ('a37bc13f537b8800fc61170dd714cb938c0e62047a7c9d0061bd8a407fe29a13'),
          {Tiger2_5_192      count 117}
          ('c15eba0aa26d3668b97f9abfa4bfa0513057f35874f50ab0'),
          {Snefru_8_256      count 117}
          ('3278279bc38c7483c3c072a892702a9ba0ea909b8a3412a4b48f333c99735433'),
          {Grindahl512       count 117}
          ('4447132202fd4a94ae31af19bf454d2c46e4e8a1f82ab214f3eadd9d02eb9d7ebc72ddbf04bab2e0e3a553f4e6ec5b7c8724f20c887c8394b2f970524a3b845f'),
          {Haval_5_256       count 117}
          ('883de42fabd84a49dbc4a5cc6a71f6b8c8c2b2ce91eadce672a21b0df5d38683'),
          {MD5               count 117}
          ('135a0450af2b16e8529060246e402a27'),
          {RadioGatun32      count 117}
          ('4e99747c8623d579b13f1cc6593a83c7a363d70157ae3a83165d817e836a22d0'),
          {WhirlPool         count 117}
          ('dff715603eaff8b2cfd3e0aa49ee50b0afdfa445e4f4b4a2b148959c4b23c6594bf8e2c81228db3c57c147e3b8a2fb91763b9a7abc0bff48052c30a9117d6b04'),
          {MurmurHash3_32    count 117}
          ('04d45504')
         ),
         (
          {SHA2_256          count 127}
          ('6b3e56f2349c09aa0a814a0c5a9dfb72e13b79c57d3dd5bf802ab00c5040164b'),
          {SHA2_384          count 127}
          ('6e23e9d0dc3ee1ccb08f1f9568e8fc5d8d85b8b5a01afe63946894b39d68691330a63bbeaccc4fd6bac141c452feaa0e'),
          {SHA2_512          count 127}
          ('d33bc6775743bd1110f51b84c0ebbdc57c622890b20d53b754ad9a1937e2761a1747d9adcdc2ec685549e418eb6ec3943c1e88d8e4a698389542547256522fe7'),
          {SHA3_256          count 127}
          ('4230dbf66b2e324d321fcbd6ffbfeb0156e3070af672dc0c743b5001d6e530ac'),
          {SHA3_384          count 127}
          ('d3a0c04b1350044d29a099cb5d95175539e93e1144f471d27bbcae555864a3e7c87bbaf7107e8335206aebb2067c6e1d'),
          {SHA3_512          count 127}
          ('73b63d13c3e4e9dcd9fcce0adaeba4423ec201aa7e13e33faba2b6fbc35efd76302148fc964f7647b24d770ae897c9d5ca0211e4b1e27a81fb769ecbfefb1511'),
          {RIPEMD160         count 127}
          ('67073f8cb7f372f93bd57f289cf3829d801e78d6'),
          {RIPEMD256         count 127}
          ('d14265c897b77caa18c77c77c7f46f1a07faca209a16d997af794c15b145bb05'),
          {RIPEMD320         count 127}
          ('d5d5fbe5fb496f65ecc8f65b114bc498bad886b826e593fe0c66b0b03b868002be71c3219a992b61'),
          {blake2b           count 127}
          ('ab24840d31c5c19a8c5c0729e8bc327cb1b48088b135de8f04428985a0ef71d366388973625cb77d558f6dc4dcbe93c5d5327aedb83b0cbee34e656fde2962ee'),
          {blake2s           count 127}
          ('ef42bf26aeae6d85c8c1a0d4304da676444a7c57944efc0496c300b391048b01'),
          {Tiger2_5_192      count 127}
          ('24b3fec9a6235309ae17ee5a972503b60a3e8017b66cdf12'),
          {Snefru_8_256      count 127}
          ('b22280ba8e1c973424ddf5be20497e1191634f7c72f46cb0757eb46dac168839'),
          {Grindahl512       count 127}
          ('f924af50f7cdc77b9199d1af7f1f7fcd454b8b670df3a1d22ec634a502f509f47ff0d6ede8eb26afb94ee45ef819acdd522680a5a6394aee34704f9f08e1a37c'),
          {Haval_5_256       count 127}
          ('0c57f4b86511b060b39c9d7b101fc6282642654890fc9dfdd010025e632c9ce8'),
          {MD5               count 127}
          ('74f3b69ddcd9d6ce64530eeef42cec35'),
          {RadioGatun32      count 127}
          ('86517f426d2c55fd69d07a434f90bfee70539cde89f024dc1ba0e52d0ba5710a'),
          {WhirlPool         count 127}
          ('76a8e2c8f91308134eb2a6485f4c8b1ed186632f5d4a477d5e2bd591c1a5913f39c97baf4a89ec56d0b46de38e72df6d43a0e8101f65e1441b415e4200cbe313'),
          {MurmurHash3_32    count 127}
          ('22f573a2')
         ),
         (
          {SHA2_256          count 128}
          ('75b01600de565f4138151f345028a91a8471385509dfe27e2d07096b4c82136b'),
          {SHA2_384          count 128}
          ('3b9d1126768bc0e16c6484a0025f492893a92927eb42cc645c23c22a6a5252bcb7b82ac748f0a99a49ce2ccdaafa723a'),
          {SHA2_512          count 128}
          ('f03557fc390333279816513d69a4e389ab51df3bf1a06b666c816c18f98c8dedaf338eea98e3063cd728ebcafe7d59dd19eca2bef4327a3421eb1e921af5d223'),
          {SHA3_256          count 128}
          ('c19c584bb6969ba83731d2f21025d556b9cf08a9e598cc97cdc5f021675e7a90'),
          {SHA3_384          count 128}
          ('7538b4cc1d1fc9eb921f5bea8dda949b43e1f2e8fb7dbfd2f1e7b01f843dc5914fe7983cc29f53ea52c91da5e0e38a7c'),
          {SHA3_512          count 128}
          ('d5ec5de877ef0a39eefe294f6183b63adb91d2a0ba1ec1fd576db515ed78f8220442c2347bdeb8a0f77cdc46d97e5b96d4189fec1f5cd2e8b5de3d467684ad73'),
          {RIPEMD160         count 128}
          ('c923752f5fbb9721a48c5f1dbcfbc70865577869'),
          {RIPEMD256         count 128}
          ('b286ca27b0ae4f6c18886879f9713cd959fff512535bcd379943c95dcde7773f'),
          {RIPEMD320         count 128}
          ('39bb7f49c9be805d4ff51210d6e64fc5b48a87ad4795e1c17deef630d4ab5f93bcee15b999fd81de'),
          {blake2b           count 128}
          ('ef4618e9126f6c54931e8f2ab5e12737ed4722932e107d05768ba59f484e0858b6b189ce0b1db3e18eea5355eb60dec5826be26cac759b7f2eab3a97ec111f10'),
          {blake2s           count 128}
          ('54afb0c19b2fc2ed628d379f819a79ad940add19296099acabe26bdc67c9bd05'),
          {Tiger2_5_192      count 128}
          ('61485315bdca303a54a23b3fdf5ab410092824c0bd8b177a'),
          {Snefru_8_256      count 128}
          ('f456475f82364ff1c5b4d14509b2a06d5fc8512378ec4d909fa9c57c336d2bdb'),
          {Grindahl512       count 128}
          ('c86054fb58498874529532408a05101ad0d1753639716f96f56468c015880d7adfc2db4b94edcb50af6e66f87a0d595f7e29a5829edba17c2d039141aec90724'),
          {Haval_5_256       count 128}
          ('63829e28fce75643700ebe1e4750fc26001c81335401b19b5e86acf3866e4672'),
          {MD5               count 128}
          ('ed31bf5fd4dbc2d509ac4cb880ec685d'),
          {RadioGatun32      count 128}
          ('bb266e01e0ba48d3c8a5f465d41dde07c67396f05011b1eee0fc8c95e11b2525'),
          {WhirlPool         count 128}
          ('661dc7ddbc9cd25ce94dfba19b7941daf12ff9a0a9d1b151d691ace392ed9d6c8d8cd1c12b2f0fda9ea116291cf81f04aca12f40fa2c482976228eb703d64029'),
          {MurmurHash3_32    count 128}
          ('545ab5d7')
         ),
         (
          {SHA2_256          count 129}
          ('5536bf5cdf0739e4ff259eb79a4276a009717e371057a3b8afe4ba79a03a884a'),
          {SHA2_384          count 129}
          ('2703c12554db5b80ef25b7d2dc4f0233b7b7064e69d57eff39b12aa77ad3c8b2e5d8014506179fc76399da952b2ed985'),
          {SHA2_512          count 129}
          ('5af2f48f25c994054c624afd99c5c9a59e91c492facdb65068cc1a15497f65ba0f6c5d15dc2f176f10ea6130c2894339a02fb99696b39b6c634066acc590427c'),
          {SHA3_256          count 129}
          ('82ea34a1f09ebaf85ad11efa05f81e9e7a8d6fbb62e04cfed2e5f26c4d1f09b5'),
          {SHA3_384          count 129}
          ('699fc858bf267ab42444dc5888f53e55c8bd7f195cda1bee192d9471fced05a25370f98d1e8a20127e57422fb226e499'),
          {SHA3_512          count 129}
          ('461f2ef3ddb3101d2ae5b1edea9178bc431225a9e5bec7c04e446a70db25f2e8e9b24547733667f0794286a330297d11215f21da7b5eea03adf063193f5f49bf'),
          {RIPEMD160         count 129}
          ('6ada1e777ecaacc07922cf839e1259d1f2b8afce'),
          {RIPEMD256         count 129}
          ('ccfc63b15e2e810a36f3d26ed3b1bd49f456d1af97c3d46c0683833d37ce359f'),
          {RIPEMD320         count 129}
          ('1d18806ff98659458e4095e0acac282c1af2815cf5967402dad2c688afa4c10b16b6d1996415bf86'),
          {blake2b           count 129}
          ('ad7f01517787bfa75ceceab92d96f94f04600786a83cabe190e3b503af1d184d9db27577bdddb78fa052d8a086147add8ecc385b3f26c37180408311664bf9af'),
          {blake2s           count 129}
          ('31e1c3e9ce27f992329d933a02dafe206b856f90057803d1e537304e97f80885'),
          {Tiger2_5_192      count 129}
          ('742c2dc251630e13016a4f968e640156e44bf3c6fc307665'),
          {Snefru_8_256      count 129}
          ('c3b087f29c8237981b10227dbed68b203408df8aeb1805089a7a723f02b51992'),
          {Grindahl512       count 129}
          ('3db136d934e5c22fbbe614fb7420d9cd70d74d1e868e078bbab97939039124543b0909de500b72114a110b1a94a6dcab623b3f0ac9eb102176023719a8243561'),
          {Haval_5_256       count 129}
          ('a29f9c16a35abbcc06d5f3e77854008dea21c38093729ec347cd3cf24ab6fdc8'),
          {MD5               count 129}
          ('2cacdddc8999a30233627b929921202b'),
          {RadioGatun32      count 129}
          ('9935ccf10e79f6077845f4f6ad9a41df57a8ce7d854a0899090de8140ca38b67'),
          {WhirlPool         count 129}
          ('a9cf1d955a634da1f5b1068d1a0d631948ccd947c2e44eaf20584a79a810070bc3d30a208d63c023146d8bff79571ae6a9d10c90baf3e0031a733016f4473356'),
          {MurmurHash3_32    count 129}
          ('45d66366')
         ),
         (
          {SHA2_256          count 178}
          ('ad69c11f5d88dc4b047174218e843fdb29dbfb8dd2697f017bc8cd98a6a7b7fd'),
          {SHA2_384          count 178}
          ('c21fe026e7ba3c8e845512d39c592beddf903e6df81fb8ec0637464c279618b1f10a91b5291f1ab698d9354b61a3b2d6'),
          {SHA2_512          count 178}
          ('8dc7dbc6d4b1ccd92948804c6474e5f94acaf59f4d908f86603abd3c7d96f18dc1d1723a22cef7b6e0ef9a6c1c33f390c4c85a9e1fd4c4fd4db3c867564f1d81'),
          {SHA3_256          count 178}
          ('471ea99294ac57486166be9a3e3da3cbf588adc0c6606c290dddd513632931ac'),
          {SHA3_384          count 178}
          ('03c546e8f629538bdfe523e4776b9c4fce59b2c523a57482fcf212d617e63a7677b98ded0878b317e1514de278c58aec'),
          {SHA3_512          count 178}
          ('3f71cc9ed5acf47e4b994fb36bdc306c7e777a400532e0c0ec7e2ac1796c4471d39a09d7e32473e7bf804e4b342813a87f8f11c85da3b08f50cfe8af3f690d12'),
          {RIPEMD160         count 178}
          ('abc2c368a457d10bc300954a4036b3a33eae7128'),
          {RIPEMD256         count 178}
          ('e6178a33180fdcad7cc503f5ed90b66610db900dee7326696cb4e10d1234caa7'),
          {RIPEMD320         count 178}
          ('957de878669f2a162f50a2c8bb07ae835b857985ef68f6c77d590b89861358698ed10fe59503b454'),
          {blake2b           count 178}
          ('99ae6a63885847e5b45ff4d2d2b0eb43e9fd722a0c7254eb4bcf706a484df9e300c61e6aa7c6620ddf2dabcc9b51257715f396f713606dbcd09f14c833becdb6'),
          {blake2s           count 178}
          ('f95e620f0335c83afa8eda36b853a739158cd4f8910fa2aa30d0794352c65510'),
          {Tiger2_5_192      count 178}
          ('eac22e2e763c29b07346c531917a0fcb93fbc72daab36681'),
          {Snefru_8_256      count 178}
          ('0e13d6fc033f4de4e9db360292e7a8c02514534e2cdff6fd69cbdcb515c8760b'),
          {Grindahl512       count 178}
          ('be7c6b085ccfa21344e46415a3bb139ee2ac1b87ae569e3f751a563280e879cc7910c357416101495cca5442d6260bf993e11ba1d5aedccad75afd130d4346fa'),
          {Haval_5_256       count 178}
          ('f83274137a08ac4f8738587e643a85907716f2df0462d32673f5d79c5e301e6a'),
          {MD5               count 178}
          ('c6f6aae119ba216edf22c62ed898bc56'),
          {RadioGatun32      count 178}
          ('344442532a514e9dbb4b9c4232d45558e7e38510109ef62b17f54f402885cbde'),
          {WhirlPool         count 178}
          ('53ca52a4baa75c13ef909fb6f6ec680338902bda1269c6a7db456c187a40f5e9e0dfce6f3d151e3b533f1b18c0b35a955095b24c94bd75a69bca5c67720c8e24'),
          {MurmurHash3_32    count 178}
          ('eb1680c6')
         ),
         (
          {SHA2_256          count 199}
          ('cafebf56cdeaec6505b97a0f52369a79fa441d4d2e5a034d16ab0df00172b907'),
          {SHA2_384          count 199}
          ('83843225d4dbfd455676885ea3b923ba2e0fa536a53c713365b5335623897840588d30260a4ed4d392c18efb6c96d946'),
          {SHA2_512          count 199}
          ('f239e971dfa284808c7e95a9726e1f42942e431e2c942e84d020c580a7a4a8c1a7ca35af44f2efafee6d3d929c01c30f0588c01e8e6813649fb86b22f0369cb1'),
          {SHA3_256          count 199}
          ('af6df45fdc24388fba66baa4484ace35cdd01aa6a0f9a635f564c1ba5b1fefd3'),
          {SHA3_384          count 199}
          ('a2e0626bec9c34d571ec7079d0186b0235c45cc2faa165ca619c0ebd290f0292e7c565ee77fce106af58e0d30e7b673b'),
          {SHA3_512          count 199}
          ('e2e4d8eadf49edf7c0b81c97e0c115064a6788eda531df390b88d09586dd2f33f551c6fe4f930caaf3e6d24e7f3dce49c9ecfedb5ceeef796c1afa1776157736'),
          {RIPEMD160         count 199}
          ('31ed25a6a35ba860abc0804c6e8c3e3e6174099d'),
          {RIPEMD256         count 199}
          ('2a1c9d07ce2174a6a09a246c6edbdc4f0fd0514f0179984cb44c06b8b3c573b1'),
          {RIPEMD320         count 199}
          ('527b23083ca9c12fe6f3e9936310f7b71c594113efaaeb58c195b657406a45a70f6d918e714ba450'),
          {blake2b           count 199}
          ('33074a6aa23c6117037b426d16211bc41a29e38bf94bba4c2dce6659b0c4e5b63555a8b08a214905e1f795282a0a427cb90de7d3967d7ba975b58a7eb550eb3c'),
          {blake2s           count 199}
          ('bd881d0cac02bd2300d41dfd8936570ed940d8cef9632731f28ea472d43c4199'),
          {Tiger2_5_192      count 199}
          ('2b173dfd8256085aa6b8336b5ce6fbb3d383c59547e5547c'),
          {Snefru_8_256      count 199}
          ('72e8f1ef4c8425356593a9ce4be37181911bcff9d9f426c93aa1622348a2c6e7'),
          {Grindahl512       count 199}
          ('eeefc607804883a8e4e24d349297380a7be6789f877d6edfd017b054d6dff6a7fcb1386c5695b76ff9997332125a2e7aadb9533761a2d9fd960f6be4646fbaf3'),
          {Haval_5_256       count 199}
          ('9d08dcbcffe809a60e60fcad8b515ed73e339e73f885c5b50479d7ea2afb6e3b'),
          {MD5               count 199}
          ('c5fc302e8942cb54a37a7c46adeab3d0'),
          {RadioGatun32      count 199}
          ('b76be67d94ce6014e5a125c371c22abfce3bbccc86f92dac31c394226b0c7912'),
          {WhirlPool         count 199}
          ('26c9f7bed820bef29e35521bb6e89ccba04ad473eb7f8d9e51952ed4d414b71da10e57fc2d30ac8d6405722af51456bb515553a9fa9108cd022d270b9fda6ffe'),
          {MurmurHash3_32    count 199}
          ('33a16e6d')
         ),
         (
          {SHA2_256          count 200}
          ('d20e764994f9a21ca01a3e9247bc70618f39663773c3a7a839d8a2e1072f182d'),
          {SHA2_384          count 200}
          ('ccfe1529f08bad44c42cf6bb96497f3474fe69631a33b58b4a28833e30dc7a404d63f5573dd81654e0430d92034b2b8b'),
          {SHA2_512          count 200}
          ('5a9aee4aed39dd405980b29984dccc6b520b685c6beb6e42c3450b858e1cc45de9d235849fa743738a06514b30522180d06f98185a49919191e86374a79df3b9'),
          {SHA3_256          count 200}
          ('cd31079dc52963c7753ff9b8640ce60404fd44fe4464af475229aa704cb5de4f'),
          {SHA3_384          count 200}
          ('af0f60050d97927fa2becfd3b7938e31c20ff3576bc3adde5d51428e91de10102e3c49c24ae7e515838952e53709a67a'),
          {SHA3_512          count 200}
          ('d62ed867af9fee338bc1cc712fdbc0da15afa40b4a5dcc3e76d74f1770c5a7ca88638f0cc8bce685cae8d68a2aa8717c84bc3e146100aff25c3326355b1735aa'),
          {RIPEMD160         count 200}
          ('1105e599abaea1b0f8d51c3878729ad0ca619a4e'),
          {RIPEMD256         count 200}
          ('29a962414ab1f46a2013178f831d66559a46d709fd3604b4b435ec4d8b536619'),
          {RIPEMD320         count 200}
          ('c56063dd1fb318af5a0910ed3993c3ea3f746be8ef65661af0fb4c7451f44dfcabfe7e5db469d9b3'),
          {blake2b           count 200}
          ('6c5117105a9cf47347e5e59aeeacf833e503c3e537e75020c9363cdebafeab00dd478e96c3a0e11e4c2615284fddf47a079c2b49d650f0bbc167ba10f5bf25e8'),
          {blake2s           count 200}
          ('c83b8ea4503d8a8d470c0ba7f977c2ea773e844d36d9a9e866a953c1338259ee'),
          {Tiger2_5_192      count 200}
          ('c2eee732fdbcdc4b0c8f57187a69b7017f9ad8771fc5ae36'),
          {Snefru_8_256      count 200}
          ('8ba028b1ad51b06d8a92cf3541c817a22c483fb8aa9c4341345faddb8e166867'),
          {Grindahl512       count 200}
          ('13771dd2bd4e1d046acd57457b0cddd6c535d91923677315ad89f7bf2fd3573b31d5eff98eb88798a5383b90d36efabc5b4127eb6e592adceb6a0749bae01869'),
          {Haval_5_256       count 200}
          ('5e1e2503132805abbdd447a5428dc9ddf7071da09fc5bede1a2db78731177fee'),
          {MD5               count 200}
          ('9242480e2630061d3eccb16821e98d30'),
          {RadioGatun32      count 200}
          ('16696fe96e850fce272f90b59e9114e55098c03ee0d3e40e0d0616a1926a8ed8'),
          {WhirlPool         count 200}
          ('d88dceef0776780b8439dd8338cd972734d6e973b4dc43b6d298622d9ed0a1ab3e9a37664ecbd14d4155c65cde93dcfd70707ba4dd7eecbf15af2a5ffee48d1e'),
          {MurmurHash3_32    count 200}
          ('442b55fe')
         )
        );

    protected
      procedure SetUp; override;
      procedure TearDown; override;
    published
      procedure TestRandomHashSequence;

    end;


implementation

// CheckSum

{ TTestCRCModel }

procedure TTestCRCModel.TearDown;
begin
  FCRC := Nil;
  inherited;

end;

procedure TTestCRCModel.TestCheckValue;
var
  Idx: TCRCStandard;
  tmp: String;
begin
  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.CreateCRC(Idx);

    FExpectedString := IntToHex(((FCRC as ICRC).CheckValue), 16);

    tmp := FCRC.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.' + ' ' + (FCRC as ICRC).Names[0],
      [FExpectedString, FActualString]));

  end;

end;

procedure TTestCRCModel.TestCheckValueWithIncrementalHash;
var
  Idx: TCRCStandard;
  tmp: String;
begin
  for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
  begin
    FCRC := THashFactory.TChecksum.CreateCRC(Idx);

    FCRC.Initialize();

    FExpectedString := IntToHex(((FCRC as ICRC).CheckValue), 16);

    FCRC.TransformString(System.Copy(FOnetoNine, 1, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(FOnetoNine, 4, 3), TEncoding.UTF8);
    FCRC.TransformString(System.Copy(FOnetoNine, 7, 3), TEncoding.UTF8);

    FHashResult := FCRC.TransformFinal();

    tmp := FHashResult.ToString();

    FActualString := System.StringOfChar('0', 16 - System.Length(tmp)) + tmp;

    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.' + ' ' + (FCRC as ICRC).Names[0],
      [FExpectedString, FActualString]));

  end;

end;

{ TTestAlder32 }

procedure TTestAlder32.SetUp;
begin
  inherited;
  FAdler32 := THashFactory.TChecksum.CreateAdler32();
end;

procedure TTestAlder32.TearDown;
begin
  FAdler32 := Nil;
  inherited;
end;

procedure TTestAlder32.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FAdler32.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FAdler32.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FAdler32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestAlder32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FAdler32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAlder32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.TChecksum.CreateAdler32();

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

procedure TTestAlder32.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FAdler32.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

// Hash32

{ TTestAP }

procedure TTestAP.SetUp;
begin
  inherited;
  FAP := THashFactory.THash32.CreateAP();
end;

procedure TTestAP.TearDown;
begin
  FAP := Nil;
  inherited;
end;

procedure TTestAP.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FAP.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FAP.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FAP.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestAP.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FAP.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestAP.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateAP();

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

procedure TTestAP.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FAP.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBernstein }

procedure TTestBernstein.SetUp;
begin
  inherited;
  FBernstein := THashFactory.THash32.CreateBernstein();
end;

procedure TTestBernstein.TearDown;
begin
  FBernstein := Nil;
  inherited;
end;

procedure TTestBernstein.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBernstein.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBernstein.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBernstein.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBernstein.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBernstein.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBernstein();

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

procedure TTestBernstein.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBernstein.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBernstein1 }

procedure TTestBernstein1.SetUp;
begin
  inherited;
  FBernstein1 := THashFactory.THash32.CreateBernstein1();
end;

procedure TTestBernstein1.TearDown;
begin
  FBernstein1 := Nil;
  inherited;
end;

procedure TTestBernstein1.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBernstein1.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBernstein1.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBernstein1.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBernstein1.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBernstein1.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBernstein1.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBernstein1();

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

procedure TTestBernstein1.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBernstein1.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestBKDR }

procedure TTestBKDR.SetUp;
begin
  inherited;
  FBKDR := THashFactory.THash32.CreateBKDR();
end;

procedure TTestBKDR.TearDown;
begin
  FBKDR := Nil;
  inherited;
end;

procedure TTestBKDR.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FBKDR.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FBKDR.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FBKDR.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestBKDR.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FBKDR.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestBKDR.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateBKDR();

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

procedure TTestBKDR.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FBKDR.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestDEK }

procedure TTestDEK.SetUp;
begin
  inherited;
  FDEK := THashFactory.THash32.CreateDEK();
end;

procedure TTestDEK.TearDown;
begin
  FDEK := Nil;
  inherited;
end;

procedure TTestDEK.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FDEK.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FDEK.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FDEK.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestDEK.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FDEK.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDEK.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateDEK();

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

procedure TTestDEK.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FDEK.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestDJB }

procedure TTestDJB.SetUp;
begin
  inherited;
  FDJB := THashFactory.THash32.CreateDJB();
end;

procedure TTestDJB.TearDown;
begin
  FDJB := Nil;
  inherited;
end;

procedure TTestDJB.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FDJB.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FDJB.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FDJB.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestDJB.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FDJB.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestDJB.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateDJB();

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

procedure TTestDJB.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FDJB.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestELF }

procedure TTestELF.SetUp;
begin
  inherited;
  FELF := THashFactory.THash32.CreateELF();
end;

procedure TTestELF.TearDown;
begin
  FELF := Nil;
  inherited;
end;

procedure TTestELF.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FELF.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FELF.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FELF.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestELF.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FELF.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestELF.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateELF();

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

procedure TTestELF.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FELF.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV }

procedure TTestFNV.SetUp;
begin
  inherited;
  FFNV := THashFactory.THash32.CreateFNV();
end;

procedure TTestFNV.TearDown;
begin
  FFNV := Nil;
  inherited;
end;

procedure TTestFNV.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateFNV();

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

procedure TTestFNV.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV1a }

procedure TTestFNV1a.SetUp;
begin
  inherited;
  FFNV1a := THashFactory.THash32.CreateFNV1a();
end;

procedure TTestFNV1a.TearDown;
begin
  FFNV1a := Nil;
  inherited;
end;

procedure TTestFNV1a.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV1a.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV1a.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV1a.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV1a.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV1a.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateFNV1a();

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

procedure TTestFNV1a.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV1a.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestJenkins3 }

procedure TTestJenkins3.SetUp;
begin
  inherited;
  FJenkins3 := THashFactory.THash32.CreateJenkins3();
end;

procedure TTestJenkins3.TearDown;
begin
  FJenkins3 := Nil;
  inherited;
end;

procedure TTestJenkins3.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FJenkins3.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FJenkins3.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FJenkins3.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestJenkins3.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FJenkins3.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJenkins3.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateJenkins3();

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

procedure TTestJenkins3.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FJenkins3.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestJS }

procedure TTestJS.SetUp;
begin
  inherited;
  FJS := THashFactory.THash32.CreateJS();
end;

procedure TTestJS.TearDown;
begin
  FJS := Nil;
  inherited;
end;

procedure TTestJS.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FJS.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FJS.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FJS.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestJS.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FJS.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestJS.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateJS();

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

procedure TTestJS.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FJS.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmur2 }

procedure TTestMurmur2.SetUp;
begin
  inherited;
  FMurmur2 := THashFactory.THash32.CreateMurmur2();
end;

procedure TTestMurmur2.TearDown;
begin
  FMurmur2 := Nil;
  inherited;
end;

procedure TTestMurmur2.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMurmur2.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmur2.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmur2.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmur2.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmur2.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateMurmur2();

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

procedure TTestMurmur2.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMurmur2.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2.TestWithDifferentKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmur2 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmurHash3_x86_32 }

procedure TTestMurmurHash3_x86_32.SetUp;
begin
  inherited;
  FMurmurHash3_x86_32 := THashFactory.THash32.CreateMurmurHash3_x86_32();

end;

procedure TTestMurmurHash3_x86_32.TearDown;
begin
  FMurmurHash3_x86_32 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x86_32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x86_32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x86_32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x86_32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x86_32.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateMurmurHash3_x86_32();

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

procedure TTestMurmurHash3_x86_32.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x86_32.ComputeString(FRandomStringRecord,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x86_32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x86_32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_32.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x86_32.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestOneAtTime }

procedure TTestOneAtTime.SetUp;
begin
  inherited;
  FOneAtTime := THashFactory.THash32.CreateOneAtTime();
end;

procedure TTestOneAtTime.TearDown;
begin
  FOneAtTime := Nil;
  inherited;
end;

procedure TTestOneAtTime.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FOneAtTime.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FOneAtTime.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FOneAtTime.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestOneAtTime.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FOneAtTime.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestOneAtTime.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateOneAtTime();

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

procedure TTestOneAtTime.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FOneAtTime.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestPJW }

procedure TTestPJW.SetUp;
begin
  inherited;
  FPJW := THashFactory.THash32.CreatePJW();
end;

procedure TTestPJW.TearDown;
begin
  FPJW := Nil;
  inherited;
end;

procedure TTestPJW.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FPJW.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FPJW.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FPJW.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestPJW.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FPJW.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestPJW.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreatePJW();

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

procedure TTestPJW.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FPJW.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRotating }

procedure TTestRotating.SetUp;
begin
  inherited;
  FRotating := THashFactory.THash32.CreateRotating();
end;

procedure TTestRotating.TearDown;
begin
  FRotating := Nil;
  inherited;
end;

procedure TTestRotating.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRotating.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRotating.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRotating.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRotating.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRotating.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRotating.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateRotating();

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

procedure TTestRotating.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRotating.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestRS }

procedure TTestRS.SetUp;
begin
  inherited;
  FRS := THashFactory.THash32.CreateRS();
end;

procedure TTestRS.TearDown;
begin
  FRS := Nil;
  inherited;
end;

procedure TTestRS.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FRS.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FRS.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FRS.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestRS.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FRS.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestRS.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateRS();

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

procedure TTestRS.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FRS.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSDBM }

procedure TTestSDBM.SetUp;
begin
  inherited;
  FSDBM := THashFactory.THash32.CreateSDBM();
end;

procedure TTestSDBM.TearDown;
begin
  FSDBM := Nil;
  inherited;
end;

procedure TTestSDBM.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSDBM.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSDBM.ComputeString(FDefaultData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSDBM.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSDBM.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSDBM.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSDBM.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateSDBM();

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

procedure TTestSDBM.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSDBM.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestShiftAndXor }

procedure TTestShiftAndXor.SetUp;
begin
  inherited;
  FShiftAndXor := THashFactory.THash32.CreateShiftAndXor();
end;

procedure TTestShiftAndXor.TearDown;
begin
  FShiftAndXor := Nil;
  inherited;
end;

procedure TTestShiftAndXor.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FShiftAndXor.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FShiftAndXor.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FShiftAndXor.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestShiftAndXor.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FShiftAndXor.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestShiftAndXor.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateShiftAndXor();

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

procedure TTestShiftAndXor.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FShiftAndXor.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSuperFast }

procedure TTestSuperFast.SetUp;
begin
  inherited;
  FSuperFast := THashFactory.THash32.CreateSuperFast();
end;

procedure TTestSuperFast.TearDown;
begin
  FSuperFast := Nil;
  inherited;
end;

procedure TTestSuperFast.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSuperFast.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSuperFast.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSuperFast.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSuperFast.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSuperFast.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSuperFast.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateSuperFast();

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

procedure TTestSuperFast.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSuperFast.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestXXHash32 }

procedure TTestXXHash32.SetUp;
begin
  inherited;
  FXXHash32 := THashFactory.THash32.CreateXXHash32();

end;

procedure TTestXXHash32.TearDown;
begin
  FXXHash32 := Nil;
  inherited;
end;

procedure TTestXXHash32.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FXXHash32.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestXXHash32.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FXXHash32.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FXXHash32.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();

  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash32.CreateXXHash32();

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

procedure TTestXXHash32.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FXXHash32.ComputeString(FRandomStringTobacco, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FXXHash32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FXXHash32 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash32.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FXXHash32.ComputeString(FZerotoFour, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

// Hash64

{ TTestFNV64 }

procedure TTestFNV64.SetUp;
begin
  inherited;
  FFNV64 := THashFactory.THash64.CreateFNV();
end;

procedure TTestFNV64.TearDown;
begin
  FFNV64 := Nil;
  inherited;
end;

procedure TTestFNV64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV64.ComputeString(FEmptyData, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateFNV;

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

procedure TTestFNV64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV64.ComputeString(FOnetoNine, TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestFNV1a64 }

procedure TTestFNV1a64.SetUp;
begin
  inherited;
  FFNV1a64 := THashFactory.THash64.CreateFNV1a();
end;

procedure TTestFNV1a64.TearDown;
begin
  FFNV1a64 := Nil;
  inherited;
end;

procedure TTestFNV1a64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FFNV1a64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FFNV1a64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FFNV1a64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestFNV1a64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FFNV1a64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestFNV1a64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateFNV1a();

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

procedure TTestFNV1a64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FFNV1a64.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmur2_64 }

procedure TTestMurmur2_64.SetUp;
begin
  inherited;
  FMurmur2_64 := THashFactory.THash64.CreateMurmur2();
end;

procedure TTestMurmur2_64.TearDown;
begin
  FMurmur2_64 := Nil;
  inherited;
end;

procedure TTestMurmur2_64.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FMurmur2_64.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmur2_64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmur2_64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmur2_64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmur2_64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateMurmur2();

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

procedure TTestMurmur2_64.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FMurmur2_64.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmur2_64.TestWithDifferentKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmur2_64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestSipHash2_4 }

procedure TTestSipHash2_4.SetUp;
begin
  inherited;
  FSipHash2_4 := THashFactory.THash64.CreateSipHash2_4();
end;

procedure TTestSipHash2_4.TearDown;
begin
  FSipHash2_4 := Nil;
  inherited;
end;

procedure TTestSipHash2_4.TestBytesabcde;
var
  LBuffer: TBytes;
begin
  System.SetLength(LBuffer, System.SizeOf(FBytesabcde));
  System.Move(FBytesabcde, Pointer(LBuffer)^, System.SizeOf(FBytesabcde));
  FExpectedString := FExpectedHashOfabcde;
  FActualString := FSipHash2_4.ComputeBytes(LBuffer).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FSipHash2_4.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FSipHash2_4.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestSipHash2_4.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FSipHash2_4.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateSipHash2_4();

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

procedure TTestSipHash2_4.TestOnetoNine;
begin
  FExpectedString := FExpectedHashOfOnetoNine;
  FActualString := FSipHash2_4.ComputeString(FOnetoNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestShortMessage;
begin
  FExpectedString := FExpectedHashOfShortMessage;
  FActualString := FSipHash2_4.ComputeString(FShortMessage, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestSipHash2_4.TestWithOutsideKey;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  LIHashWithKey := (FSipHash2_4 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ConvertHexStringToBytes(FHexStringAsKey);
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestXXHash64 }

procedure TTestXXHash64.SetUp;
begin
  inherited;
  FXXHash64 := THashFactory.THash64.CreateXXHash64();

end;

procedure TTestXXHash64.TearDown;
begin
  FXXHash64 := Nil;
  inherited;
end;

procedure TTestXXHash64.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FXXHash64.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestXXHash64.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FXXHash64.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FXXHash64.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash64.CreateXXHash64();

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

procedure TTestXXHash64.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FXXHash64.ComputeString(FRandomStringTobacco, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestWithDifferentKeyMaxUInt64DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt64AsKey;
  LIHashWithKey := (FXXHash64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt64AsBytesLE(System.High(UInt64));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FXXHash64 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt64AsBytesLE(UInt64(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestXXHash64.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FXXHash64.ComputeString(FZerotoFour, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;


// Hash128

{ TTestMurmurHash3_x86_128 }

procedure TTestMurmurHash3_x86_128.SetUp;
begin
  inherited;
  FMurmurHash3_x86_128 := THashFactory.THash128.CreateMurmurHash3_x86_128();

end;

procedure TTestMurmurHash3_x86_128.TearDown;
begin
  FMurmurHash3_x86_128 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x86_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x86_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x86_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x86_128.ComputeString(FEmptyData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x86_128.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash128.CreateMurmurHash3_x86_128();

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

procedure TTestMurmurHash3_x86_128.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x86_128.ComputeString(FRandomStringTobacco,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x86_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x86_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x86_128.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x86_128.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

{ TTestMurmurHash3_x64_128 }

procedure TTestMurmurHash3_x64_128.SetUp;
begin
  inherited;
  FMurmurHash3_x64_128 := THashFactory.THash128.CreateMurmurHash3_x64_128();

end;

procedure TTestMurmurHash3_x64_128.TearDown;
begin
  FMurmurHash3_x64_128 := Nil;
  inherited;
end;

procedure TTestMurmurHash3_x64_128.TestEmptyStream;
var
  stream: TStream;
begin
  stream := TMemoryStream.Create;
  try
    FExpectedString := FExpectedHashOfEmptyData;
    FActualString := FMurmurHash3_x64_128.ComputeStream(stream).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  finally
    stream.Free;
  end;
end;

procedure TTestMurmurHash3_x64_128.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FMurmurHash3_x64_128.ComputeString(FEmptyData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestDefaultData;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FActualString := FMurmurHash3_x64_128.ComputeString(FDefaultData,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestIncrementalHash;
begin
  FExpectedString := FExpectedHashOfDefaultData;
  FHash := THashFactory.THash128.CreateMurmurHash3_x64_128();

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

procedure TTestMurmurHash3_x64_128.TestRandomString;
begin
  FExpectedString := FExpectedHashOfRandomString;
  FActualString := FMurmurHash3_x64_128.ComputeString(FRandomStringTobacco,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestWithDifferentKeyMaxUInt32DefaultData;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (FMurmurHash3_x64_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  FActualString := LIHashWithKey.ComputeString(FDefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestWithDifferentKeyOneEmptyString;
var
  LIHashWithKey: IHashWithKey;
begin
  FExpectedString := FExpectedHashOfEmptyDataWithOneAsKey;
  LIHashWithKey := (FMurmurHash3_x64_128 as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(UInt32(1));
  FActualString := LIHashWithKey.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

procedure TTestMurmurHash3_x64_128.TestZerotoFour;
begin
  FExpectedString := FExpectedHashOfZerotoFour;
  FActualString := FMurmurHash3_x64_128.ComputeString(FZerotoFour,
    TEncoding.UTF8).ToString();
  CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s.',
    [FExpectedString, FActualString]));
end;

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
  Fconfig.HashSize := 18;
  Fconfig.Salt := FSalt;
  Fconfig.Personalisation := FPersonalisation;

  FBlake2SWithConfig := THashFactory.TCrypto.CreateBlake2S(Fconfig);

  FActualString := FBlake2SWithConfig.ComputeBytes(FValue).ToString();
  FExpectedString := '23F1CAE542785205164E8356D1F622038679';

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

{ TTestNullDigest }

procedure TTestNullDigest.SetUp;
begin
  inherited;
  FNullDigest := THashFactory.TNullDigestFactory.CreateNullDigest();
end;

procedure TTestNullDigest.TearDown;
begin
  inherited;
  FNullDigest := Nil;
end;

procedure TTestNullDigest.TestBytesabcde;
var
  BytesABCDE, result: TBytes;
begin
  BytesABCDE := TEncoding.UTF8.GetBytes('abcde');
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(BytesABCDE);

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(System.Length(BytesABCDE), FNullDigest.HashSize);

  result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(CompareMem(PByte(BytesABCDE), PByte(result),
    System.Length(BytesABCDE) * System.SizeOf(Byte)));

end;

procedure TTestNullDigest.TestEmptyBytes;
var
  BytesEmpty, result: TBytes;
begin
  BytesEmpty := TEncoding.UTF8.GetBytes('');
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(BytesEmpty);

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(System.Length(BytesEmpty), FNullDigest.HashSize);

  result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(CompareMem(PByte(BytesEmpty), PByte(result),
    System.Length(BytesEmpty) * System.SizeOf(Byte)));

end;

procedure TTestNullDigest.TestIncrementalHash;
var
  BytesZeroToNine, result: TBytes;
begin
  BytesZeroToNine := TEncoding.UTF8.GetBytes('0123456789');
  CheckEquals(-1, FNullDigest.BlockSize);
  CheckEquals(-1, FNullDigest.HashSize);

  FNullDigest.Initialize;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 0, 4));

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(4, FNullDigest.HashSize);

  FNullDigest.TransformBytes(System.Copy(BytesZeroToNine, 4, 6));

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(10, FNullDigest.HashSize);

  result := FNullDigest.TransformFinal.GetBytes;

  CheckEquals(0, FNullDigest.BlockSize);
  CheckEquals(0, FNullDigest.HashSize);

  CheckTrue(CompareMem(PByte(BytesZeroToNine), PByte(result),
    System.Length(BytesZeroToNine) * System.SizeOf(Byte)));

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

procedure TTestGOST3411_2012_256.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGOST3411_2012_256.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
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

procedure TTestGOST3411_2012_512.TestEmptyString;
begin
  FExpectedString := FExpectedHashOfEmptyData;
  FActualString := FGOST3411_2012_512.ComputeString(FEmptyData, TEncoding.UTF8)
    .ToString();
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

{TTestRandomHash}
procedure TTestRandomHash.SetUp;
begin
  inherited;
  FMurmurHash3_x86_32 := THashFactory.THash32.CreateMurmurHash3_x86_32();
  FHashAlg[0] := THashFactory.TCrypto.CreateSHA2_256();
  FHashAlg[1] := THashFactory.TCrypto.CreateSHA2_384();
  FHashAlg[2] := THashFactory.TCrypto.CreateSHA2_512();
  FHashAlg[3] := THashFactory.TCrypto.CreateSHA3_256();
  FHashAlg[4] := THashFactory.TCrypto.CreateSHA3_384();
  FHashAlg[5] := THashFactory.TCrypto.CreateSHA3_512();
  FHashAlg[6] := THashFactory.TCrypto.CreateRIPEMD160();
  FHashAlg[7] := THashFactory.TCrypto.CreateRIPEMD256();
  FHashAlg[8] := THashFactory.TCrypto.CreateRIPEMD320();
  FHashAlg[9] := THashFactory.TCrypto.CreateBlake2B_512();
  FHashAlg[10] := THashFactory.TCrypto.CreateBlake2S_256();
  FHashAlg[11] := THashFactory.TCrypto.CreateTiger2_5_192();
  FHashAlg[12] := THashFactory.TCrypto.CreateSnefru_8_256();
  FHashAlg[13] := THashFactory.TCrypto.CreateGrindahl512();
  FHashAlg[14] := THashFactory.TCrypto.CreateHaval_5_256();
  FHashAlg[15] := THashFactory.TCrypto.CreateMD5();
  FHashAlg[16] := THashFactory.TCrypto.CreateRadioGatun32();
  FHashAlg[17] := THashFactory.TCrypto.CreateWhirlPool();

end;

procedure TTestRandomHash.TearDown;
begin
  FMurmurHash3_x86_32 := Nil;
  FHashAlg[1] := nil;
  FHashAlg[2] := nil;
  FHashAlg[3] := nil;
  FHashAlg[4] := nil;
  FHashAlg[5] := nil;
  FHashAlg[6] := nil;
  FHashAlg[7] := nil;
  FHashAlg[8] := nil;
  FHashAlg[9] := nil;
  FHashAlg[10] := nil;
  FHashAlg[11] := nil;
  FHashAlg[12] := nil;
  FHashAlg[13] := nil;
  FHashAlg[14] := nil;
  FHashAlg[15] := nil;
  FHashAlg[16] := nil;
  FHashAlg[17] := nil;

  inherited;
end;

procedure TTestRandomHash.TestRandomHashSequence;
var
  HeaderBytes: TBytes;
  InputHeaderBytes: TBytes;
  HashResultStr : string;
  HashResult    : THashLibByteArray;
  ExpectedStr : string;
  i, k, tlen: integer;
begin
  InputHeaderBytes := TConverters.ConvertHexStringToBytes(InputHeader);
  for i := 1 to 16 do
  begin
    tlen := InputLength[i];
    System.SetLength(HeaderBytes, tlen);

    for k := 0 to 17 do
    begin
      ExpectedStr := UpperCase(ExpactedValues[i][k+1]);
      System.Move(InputHeaderBytes[0], HeaderBytes[0], tlen);

      HashResult := FHashAlg[k].ComputeBytes(HeaderBytes).GetBytes();
      HashResultStr := TConverters.ConvertBytesToHexString(HashResult, False);

      CheckEquals(ExpectedStr, HashResultStr, Format('Expected %s but got %s.', [ExpectedStr, HashResultStr]));
    end;

    //murmur3 test
    ExpectedStr := UpperCase(ExpactedValues[i][19]);
    System.Move(InputHeaderBytes[0], HeaderBytes[0], tlen);

    //HashResult := FMurmurHash3_x86_32.ComputeBytes(HeaderBytes).GetBytes();
    //HashResultStr := TConverters.ConvertBytesToHexString(HashResult, False);
    HashResultStr := FMurmurHash3_x86_32.ComputeBytes(HeaderBytes).ToString();

    CheckEquals(ExpectedStr, HashResultStr, Format('Expected %s but got %s.', [ExpectedStr, HashResultStr]));

  end
end;


initialization

// Register any test cases with the test runner

{$IFDEF FPC}
//RandomHash
RegisterTest(TTestRandomHash);
// NullDigest
RegisterTest(TTestNullDigest);
// CheckSum
RegisterTest(TTestCRCModel);
RegisterTest(TTestAlder32);
// Hash32
RegisterTest(TTestAP);
RegisterTest(TTestBernstein);
RegisterTest(TTestBernstein1);
RegisterTest(TTestBKDR);
RegisterTest(TTestDEK);
RegisterTest(TTestDJB);
RegisterTest(TTestELF);
RegisterTest(TTestFNV);
RegisterTest(TTestFNV1a);
RegisterTest(TTestJenkins3);
RegisterTest(TTestJS);
RegisterTest(TTestMurmur2);
RegisterTest(TTestMurmurHash3_x86_32);
RegisterTest(TTestOneAtTime);
RegisterTest(TTestPJW);
RegisterTest(TTestRotating);
RegisterTest(TTestRS);
RegisterTest(TTestSDBM);
RegisterTest(TTestShiftAndXor);
RegisterTest(TTestSuperFast);
RegisterTest(TTestXXHash32);
// Hash64
RegisterTest(TTestFNV64);
RegisterTest(TTestFNV1a64);
RegisterTest(TTestMurmur2_64);
RegisterTest(TTestSipHash2_4);
RegisterTest(TTestXXHash64);
// Hash128
RegisterTest(TTestMurmurHash3_x86_128);
RegisterTest(TTestMurmurHash3_x64_128);
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
//RandomHash
RegisterTest(TTestRandomHash.Suite);
// NullDigest
RegisterTest(TTestNullDigest.Suite);
// CheckSum
RegisterTest(TTestCRCModel.Suite);
RegisterTest(TTestAlder32.Suite);
// Hash32
RegisterTest(TTestAP.Suite);
RegisterTest(TTestBernstein.Suite);
RegisterTest(TTestBernstein1.Suite);
RegisterTest(TTestBKDR.Suite);
RegisterTest(TTestDEK.Suite);
RegisterTest(TTestDJB.Suite);
RegisterTest(TTestELF.Suite);
RegisterTest(TTestFNV.Suite);
RegisterTest(TTestFNV1a.Suite);
RegisterTest(TTestJenkins3.Suite);
RegisterTest(TTestJS.Suite);
RegisterTest(TTestMurmur2.Suite);
RegisterTest(TTestMurmurHash3_x86_32.Suite);
RegisterTest(TTestOneAtTime.Suite);
RegisterTest(TTestPJW.Suite);
RegisterTest(TTestRotating.Suite);
RegisterTest(TTestRS.Suite);
RegisterTest(TTestSDBM.Suite);
RegisterTest(TTestShiftAndXor.Suite);
RegisterTest(TTestSuperFast.Suite);
RegisterTest(TTestXXHash32.Suite);
// Hash64
RegisterTest(TTestFNV64.Suite);
RegisterTest(TTestFNV1a64.Suite);
RegisterTest(TTestMurmur2_64.Suite);
RegisterTest(TTestSipHash2_4.Suite);
RegisterTest(TTestXXHash64.Suite);
// Hash128
RegisterTest(TTestMurmurHash3_x86_128.Suite);
RegisterTest(TTestMurmurHash3_x64_128.Suite);
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
