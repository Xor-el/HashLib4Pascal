unit HashLibTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
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
  HlpIHash,
  HlpIHashInfo,
  HlpIHashResult,
  HlpConverters,
  HlpArrayUtils,
  HlpHashLibTypes;

{$IFDEF FPC}

type
  TTestMethod = TRunMethod;
{$ENDIF}

type
  THashLibTestCase = class abstract(TTestCase)

  strict private
  var
    FActualString, FExpectedString: String;

    function GetActualString: String; inline;
    procedure SetActualString(const AValue: String); inline;
    function GetExpectedString: String; inline;
    procedure SetExpectedString(const AValue: String); inline;

  strict protected
    property ActualString: String read GetActualString write SetActualString;
    property ExpectedString: String read GetExpectedString
      write SetExpectedString;
  end;

type
  TPBKDF2_HMACTestCase = class abstract(THashLibTestCase)

  strict private
  var
    FByteCount: Int32;
    FPBKDF2_HMACInstance: IPBKDF2_HMAC;

    function GetByteCount: Int32; inline;
    procedure SetByteCount(const AValue: Int32); inline;
    function GetPBKDF2_HMACInstance: IPBKDF2_HMAC; inline;
    procedure SetPBKDF2_HMACInstance(const AValue: IPBKDF2_HMAC); inline;

  strict protected
    property ByteCount: Int32 read GetByteCount write SetByteCount;
    property PBKDF2_HMACInstance: IPBKDF2_HMAC read GetPBKDF2_HMACInstance
      write SetPBKDF2_HMACInstance;

  published
    procedure TestPBKDF2_HMAC;

  end;

type
  THashLibAlgorithmTestCase = class abstract(THashLibTestCase)

  strict private
  var
    FHashInstance: IHash;

    function GetHashInstance: IHash; inline;
    procedure SetHashInstance(const AValue: IHash); inline;

  strict protected

  const
    ChunkSizes: array [0 .. 259] of Int32 = (1,
      // Test many chunk of < sizeof(int)
      2, // Test many chunk of < sizeof(int)
      3, // Test many chunk of < sizeof(int)
      4, // Test many chunk of = sizeof(int)
      5, // Test many chunk of > sizeof(int)
      6, // Test many chunk of > sizeof(int)
      7, // Test many chunk of > sizeof(int)
      8, // Test many chunk of > 2*sizeof(int)
      9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
      28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
      46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
      64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
      82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
      100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
      115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
      130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
      145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
      160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
      175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189,
      190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204,
      205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
      220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234,
      235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249,
      250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260);
    // , 261, 262, 263, 264,
    // 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279,
    // 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294,
    // 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309,
    // 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324,
    // 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 337, 338, 339,
    // 340, 341, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 352, 353, 354,
    // 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369,
    // 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 381, 382, 383, 384,
    // 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399,
    // 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414,
    // 415, 416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429,
    // 430, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444,
    // 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458, 459,
    // 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474,
    // 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489,
    // 490, 491, 492, 493, 494, 495, 496, 497, 498, 499, 500, 501, 502, 503, 504,
    // 505, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519,
    // 520, 521, 522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534,
    // 535, 536, 537, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549,
    // 550, 551, 552, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564,
    // 565, 566, 567, 568, 569, 570, 571, 572, 573, 574, 575, 576, 577, 578, 579,
    // 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594,
    // 595, 596, 597, 598, 599, 600, 601, 602, 603, 604, 605, 606, 607, 608, 609,
    // 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624,
    // 625, 626, 627, 628, 629, 630, 631, 632, 633, 634, 635, 636, 637, 638, 639,
    // 640, 641, 642, 643, 644, 645, 646, 647, 648, 649, 650, 651, 652, 653, 654,
    // 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669,
    // 670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684,
    // 685, 686, 687, 688, 689, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699,
    // 700, 701, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714,
    // 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729,
    // 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743, 744,
    // 745, 746, 747, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759,
    // 760, 761, 762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774,
    // 775, 776, 777, 778, 779, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789,
    // 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 802, 803, 804,
    // 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 819,
    // 820, 821, 822, 823, 824, 825, 826, 827, 828, 829, 830, 831, 832, 833, 834,
    // 835, 836, 837, 838, 839, 840, 841, 842, 843, 844, 845, 846, 847, 848, 849,
    // 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864,
    // 865, 866, 867, 868, 869, 870, 871, 872, 873, 874, 875, 876, 877, 878, 879,
    // 880, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893, 894,
    // 895, 896, 897, 898, 899, 900, 901, 902, 903, 904, 905, 906, 907, 908, 909,
    // 910, 911, 912, 913, 914, 915, 916, 917, 918, 919, 920, 921, 922, 923, 924,
    // 925, 926, 927, 928, 929, 930, 931, 932, 933, 934, 935, 936, 937, 938, 939,
    // 940, 941, 942, 943, 944, 945, 946, 947, 948, 949, 950, 951, 952, 953, 954,
    // 955, 956, 957, 958, 959, 960, 961, 962, 963, 964, 965, 966, 967, 968, 969,
    // 970, 971, 972, 973, 974, 975, 976, 977, 978, 979, 980, 981, 982, 983, 984,
    // 985, 986, 987, 988, 989, 990, 991, 992, 993, 994, 995, 996, 997, 998, 999,
    // 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011,
    // 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022,
    // 1023, 1024);

    BytesABCDE: array [0 .. 4] of Byte = ($61, $62, $63, $64, $65);
    EmptyData: String = '';
    DefaultData = 'HashLib4Pascal';
    OneToNine = '123456789';
    ChunkedData =
      'HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678';
    EEAABEEF = 'EEAABEEF';
    ZeroToThreeInHex = '00010203';
    ZeroToFifteenInHex = '000102030405060708090A0B0C0D0E0F';
    ZeroToOneHundredAndNinetyNineInHex = '000102030405060708090A0B0C0D0E0F' +
      '101112131415161718191A1B1C1D1E1F' + '202122232425262728292A2B2C2D2E2F' +
      '303132333435363738393A3B3C3D3E3F' + '404142434445464748494A4B4C4D4E4F' +
      '505152535455565758595A5B5C5D5E5F' + '606162636465666768696A6B6C6D6E6F' +
      '707172737475767778797A7B7C7D7E7F' + '808182838485868788898A8B8C8D8E8F' +
      '909192939495969798999A9B9C9D9E9F' + 'A0A1A2A3A4A5A6A7A8A9AAABACADAEAF' +
      'B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF' + 'C0C1C2C3C4C5C6C7';

    HMACLongStringKey = 'I need an Angel';
    HMACShortStringKey = 'Hash';

    function AreEqual(const A, B: TBytes): Boolean;

    property HashInstance: IHash read GetHashInstance write SetHashInstance;

  end;

type
  TCloneAlgorithmTestCase = class abstract(THashLibAlgorithmTestCase)
  published
    procedure TestHashCloneIsCorrect;
    procedure TestHashCloneMatchesMainHash;
    procedure TestHashCloneIsUnique;
  end;

type
  TNullDigestAlgorithmTestCase = class abstract(TCloneAlgorithmTestCase)
  strict protected
  var
    FBlockSizeMethod, FHashSizeMethod: TTestMethod;

    procedure CallGetBlockSize();
    procedure CallGetHashSize();
  published
    procedure TestEmptyBytes;
    procedure TestBytesABCDE;
  end;

type
  THashAlgorithmTestCase = class abstract(TCloneAlgorithmTestCase)
  strict private
  var
    FHashOfEmptyData, FHashOfDefaultData, FHashOfOnetoNine,
      FHashOfABCDE: String;

    function GetHashOfEmptyData: String; inline;
    function GetHashOfDefaultData: String; inline;
    function GetHashOfOnetoNine: String; inline;
    function GetHashOfABCDE: String; inline;

    procedure SetHashOfEmptyData(const AValue: String); inline;
    procedure SetHashOfDefaultData(const AValue: String); inline;
    procedure SetHashOfOnetoNine(const AValue: String); inline;
    procedure SetHashOfABCDE(const AValue: String); inline;

  strict protected
    property HashOfEmptyData: String read GetHashOfEmptyData
      write SetHashOfEmptyData;
    property HashOfDefaultData: String read GetHashOfDefaultData
      write SetHashOfDefaultData;
    property HashOfOnetoNine: String read GetHashOfOnetoNine
      write SetHashOfOnetoNine;
    property HashOfABCDE: String read GetHashOfABCDE write SetHashOfABCDE;
  published
    procedure TestEmptyString;
    procedure TestDefaultData;
    procedure TestOnetoNine;
    procedure TestBytesABCDE;
    procedure TestEmptyStream;
    procedure TestIncrementalHash;
    procedure TestIndexChunkedDataIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestUntypedInterface;
    procedure TestInitializeWorks;

  end;

type
  THashWithUInt32AsKeyAlgorithmTestCase = class abstract(THashAlgorithmTestCase)
  strict private
  var
    FHashOfDefaultDataWithMaxUInt32AsKey: String;

    function GetHashOfDefaultDataWithMaxUInt32AsKey: String; inline;

    procedure SetHashOfDefaultDataWithMaxUInt32AsKey(const AValue
      : String); inline;

  strict protected
    property HashOfDefaultDataWithMaxUInt32AsKey: String
      read GetHashOfDefaultDataWithMaxUInt32AsKey
      write SetHashOfDefaultDataWithMaxUInt32AsKey;
  published
    procedure TestWithMaxUInt32AsKey;

  end;

type
  THashWithUInt64AsKeyAlgorithmTestCase = class abstract(THashAlgorithmTestCase)
  strict private
  var
    FHashOfDefaultDataWithMaxUInt64AsKey: String;

    function GetHashOfDefaultDataWithMaxUInt64AsKey: String; inline;

    procedure SetHashOfDefaultDataWithMaxUInt64AsKey(const AValue
      : String); inline;

  strict protected
    property HashOfDefaultDataWithMaxUInt64AsKey: String
      read GetHashOfDefaultDataWithMaxUInt64AsKey
      write SetHashOfDefaultDataWithMaxUInt64AsKey;
  published
    procedure TestWithMaxUInt64AsKey;

  end;

type
  THashWithExternalKeyAlgorithmTestCase = class abstract(THashAlgorithmTestCase)
  strict private
  var
    FHashOfDefaultDataWithExternalKey: String;

    function GetHashOfDefaultDataWithExternalKey: String; inline;

    procedure SetHashOfDefaultDataWithExternalKey(const AValue: String); inline;

  strict protected
    property HashOfDefaultDataWithExternalKey: String
      read GetHashOfDefaultDataWithExternalKey
      write SetHashOfDefaultDataWithExternalKey;
  published
    procedure TestWithExternalKey;

  end;

type
  TCryptoAlgorithmTestCase = class abstract(THashAlgorithmTestCase)
  strict private
  var
    FHMACInstance: IHMAC;
    FHashOfDefaultDataHMACWithShortKey,
      FHashOfDefaultDataHMACWithLongKey: String;

    function GetHashOfDefaultDataHMACWithShortKey: String; inline;
    function GetHashOfDefaultDataHMACWithLongKey: String; inline;
    procedure SetHashOfDefaultDataHMACWithShortKey(const AValue
      : String); inline;
    procedure SetHashOfDefaultDataHMACWithLongKey(const AValue: String); inline;

    function GetHMACInstance: IHMAC; inline;
    procedure SetHMACInstance(const AValue: IHMAC); inline;

  strict protected
    property HashOfDefaultDataHMACWithShortKey: String
      read GetHashOfDefaultDataHMACWithShortKey
      write SetHashOfDefaultDataHMACWithShortKey;

    property HashOfDefaultDataHMACWithLongKey: String
      read GetHashOfDefaultDataHMACWithLongKey
      write SetHashOfDefaultDataHMACWithLongKey;

    property HMACInstance: IHMAC read GetHMACInstance write SetHMACInstance;
  published
    procedure TestSplits();
    procedure TestHMACWithDefaultDataShortKey;
    procedure TestHMACWithDefaultDataLongKey;
    procedure TestHMACCloneWorks;

  end;

type
  TKeyedCryptoAlgorithmTestCase = class abstract(TCryptoAlgorithmTestCase)

  strict private
  var
    FHashInstanceWithKey: IHash;

    function GetHashInstanceWithKey: IHash; inline;
    procedure SetHashInstanceWithKey(const AValue: IHash); inline;

  strict protected

    property HashInstanceWithKey: IHash read GetHashInstanceWithKey
      write SetHashInstanceWithKey;

  end;

type
  TBlakeCryptoAlgorithmTestCase = class abstract(TKeyedCryptoAlgorithmTestCase)

  strict private
  var
    FUnkeyedTestVectors, FKeyedTestVectors: THashLibStringArray;

    function GetUnkeyedTestVectors: THashLibStringArray; inline;
    procedure SetUnkeyedTestVectors(const AValue: THashLibStringArray); inline;

    function GetKeyedTestVectors: THashLibStringArray; inline;
    procedure SetKeyedTestVectors(const AValue: THashLibStringArray); inline;

  strict protected
    property UnkeyedTestVectors: THashLibStringArray read GetUnkeyedTestVectors
      write SetUnkeyedTestVectors;
    property KeyedTestVectors: THashLibStringArray read GetKeyedTestVectors
      write SetKeyedTestVectors;

  published
    procedure TestCheckKeyedTestVectors();
    procedure TestCheckUnkeyedTestVectors();

  end;

type
  TXofAlgorithmTestCase = class abstract(THashAlgorithmTestCase)

  strict private
  var
    FXofInstance: IXOF;
    FXofOfEmptyData: String;

    procedure CallShouldRaiseException();
    function GetXofOfEmptyData: String; inline;
    procedure SetXofOfEmptyData(const AValue: String); inline;

    function GetXofInstance: IXOF; inline;
    procedure SetXofInstance(const AValue: IXOF); inline;

  strict protected
    property XofOfEmptyData: String read GetXofOfEmptyData
      write SetXofOfEmptyData;

    property XofInstance: IXOF read GetXofInstance write SetXofInstance;
  published
    procedure TestOutputOverflow;
    procedure TestOutputBufferTooShort;
    procedure TestVeryLongXofOfEmptyString;
    procedure TestVeryLongXofOfEmptyStringWithStreamingOutput;
    procedure TestXofShouldRaiseExceptionOnWriteAfterRead;

  end;

type
  TShakeAlgorithmTestCase = class abstract(TXofAlgorithmTestCase)

  end;

type
  TCShakeAlgorithmTestCase = class abstract(TXofAlgorithmTestCase)
  strict private
  var
    FXofInstanceShake, FXofInstanceTestVector: IXOF;
    FXofOfZeroToOneHundredAndNinetyNineInHex: String;

    function GetXofOfZeroToOneHundredAndNinetyNineInHex: String; inline;
    procedure SetXofOfZeroToOneHundredAndNinetyNineInHex
      (const AValue: String); inline;

    function GetXofInstanceShake: IXOF; inline;
    procedure SetXofInstanceShake(const AValue: IXOF); inline;

    function GetXofInstanceTestVector: IXOF; inline;
    procedure SetXofInstanceTestVector(const AValue: IXOF); inline;

    function ComputeCShake(const ACShake: IHash; const AMsg: TBytes): String;

  strict protected
    property XofOfZeroToOneHundredAndNinetyNineInHex: String
      read GetXofOfZeroToOneHundredAndNinetyNineInHex
      write SetXofOfZeroToOneHundredAndNinetyNineInHex;

    property XofInstanceShake: IXOF read GetXofInstanceShake
      write SetXofInstanceShake;

    property XofInstanceTestVector: IXOF read GetXofInstanceTestVector
      write SetXofInstanceTestVector;
  published
    procedure TestCShakeAndShakeAreSameWhenNAndSAreEmpty;
    procedure TestCShake_Vectors;

  end;

implementation

{ THashLibTestCase }

function THashLibTestCase.GetActualString: String;
begin
  Result := FActualString;
end;

function THashLibTestCase.GetExpectedString: String;
begin
  Result := FExpectedString;
end;

procedure THashLibTestCase.SetActualString(const AValue: String);
begin
  FActualString := AValue;
end;

procedure THashLibTestCase.SetExpectedString(const AValue: String);
begin
  FExpectedString := AValue;
end;

{ TPBKDF2_HMACTestCase }

function TPBKDF2_HMACTestCase.GetByteCount: Int32;
begin
  Result := FByteCount;
end;

function TPBKDF2_HMACTestCase.GetPBKDF2_HMACInstance: IPBKDF2_HMAC;
begin
  Result := FPBKDF2_HMACInstance;
end;

procedure TPBKDF2_HMACTestCase.SetByteCount(const AValue: Int32);
begin
  FByteCount := AValue;
end;

procedure TPBKDF2_HMACTestCase.SetPBKDF2_HMACInstance
  (const AValue: IPBKDF2_HMAC);
begin
  FPBKDF2_HMACInstance := AValue;
end;

procedure TPBKDF2_HMACTestCase.TestPBKDF2_HMAC;
begin
  ActualString := TConverters.ConvertBytesToHexString
    (PBKDF2_HMACInstance.GetBytes(ByteCount), False);
  PBKDF2_HMACInstance.Clear();

  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ THashLibAlgorithmTestCase }

function THashLibAlgorithmTestCase.GetHashInstance: IHash;
begin
  Result := FHashInstance;
end;

procedure THashLibAlgorithmTestCase.SetHashInstance(const AValue: IHash);
begin
  FHashInstance := AValue;
end;

function THashLibAlgorithmTestCase.AreEqual(const A, B: TBytes): Boolean;
begin
  Result := TArrayUtils.AreEqual(A, B);
end;

{ TCloneAlgorithmTestCase }

procedure TCloneAlgorithmTestCase.TestHashCloneIsCorrect;
var
  LOriginal, LCopy: IHash;
  LMainData, LChunkOne, LChunkTwo: TBytes;
  LCount: Int32;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  LCount := System.Length(LMainData) - 3;
  LChunkOne := System.Copy(LMainData, 0, LCount);
  LChunkTwo := System.Copy(LMainData, LCount, System.Length(LMainData)
    - LCount);
  LOriginal := HashInstance;
  LOriginal.Initialize;

  LOriginal.TransformBytes(LChunkOne);
  // Make Copy Of Current State
  LCopy := LOriginal.Clone();
  LOriginal.TransformBytes(LChunkTwo);
  ExpectedString := LOriginal.TransformFinal().ToString();
  LCopy.TransformBytes(LChunkTwo);
  ActualString := LCopy.TransformFinal().ToString();

  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TCloneAlgorithmTestCase.TestHashCloneIsUnique;
var
  LOriginal, LCopy: IHash;
begin
  LOriginal := HashInstance;
  LOriginal.Initialize;
  LOriginal.BufferSize := (64 * 1024); // 64Kb
  // Make Copy Of Current State
  LCopy := LOriginal.Clone();
  LCopy.BufferSize := (128 * 1024); // 128Kb

  CheckNotEquals(LOriginal.BufferSize, LCopy.BufferSize,
    Format('Expected %d but got %d.', [LOriginal.BufferSize,
    LCopy.BufferSize]));
end;

procedure TCloneAlgorithmTestCase.TestHashCloneMatchesMainHash;
var
  LClone: IHash;
  LIdx: Int32;
  LActualResult, LActualResultClone: TBytes;
begin
  HashInstance.Initialize;

  for LIdx := System.Low(BytesABCDE) to System.High(BytesABCDE) do
  begin
    // do incremental hashing
    HashInstance.TransformBytes(TBytes.Create(BytesABCDE[LIdx]));
  end;

  LClone := HashInstance.Clone();

  LActualResult := HashInstance.TransformFinal().GetBytes();
  LActualResultClone := LClone.TransformFinal().GetBytes();

  if (not AreEqual(LActualResult, LActualResultClone)) then
  begin
    Fail(Format('%s Mismatch on test against a Clone', [HashInstance.Name]));
  end;

end;

{ TNullDigestAlgorithmTestCase }

procedure TNullDigestAlgorithmTestCase.CallGetBlockSize;
begin
  HashInstance.BlockSize;
end;

procedure TNullDigestAlgorithmTestCase.CallGetHashSize;
begin
  HashInstance.HashSize;
end;

procedure TNullDigestAlgorithmTestCase.TestEmptyBytes;
var
  BytesEmpty, Result: TBytes;
begin
  BytesEmpty := TConverters.ConvertStringToBytes('', TEncoding.UTF8);

  HashInstance.Initialize;

  HashInstance.TransformBytes(BytesEmpty);

  Result := HashInstance.TransformFinal.GetBytes;

  CheckTrue(AreEqual(BytesEmpty, Result));
  CheckException(FBlockSizeMethod, ENotImplementedHashLibException);
  CheckException(FHashSizeMethod, ENotImplementedHashLibException);
end;

procedure TNullDigestAlgorithmTestCase.TestBytesABCDE;
var
  LBytesABCDE, LResult: TBytes;
  LIdx: Int32;
begin
  LBytesABCDE := TConverters.ConvertStringToBytes('ABCDE', TEncoding.UTF8);

  HashInstance.Initialize;

  for LIdx := System.Low(LBytesABCDE) to System.High(LBytesABCDE) do
  begin
    // do incremental hashing
    HashInstance.TransformBytes(TBytes.Create(LBytesABCDE[LIdx]));
  end;

  LResult := HashInstance.TransformFinal.GetBytes;

  CheckTrue(AreEqual(LBytesABCDE, LResult));
  CheckException(FBlockSizeMethod, ENotImplementedHashLibException);
  CheckException(FHashSizeMethod, ENotImplementedHashLibException);
end;

{ THashAlgorithmTestCase }

function THashAlgorithmTestCase.GetHashOfABCDE: String;
begin
  Result := FHashOfABCDE;
end;

function THashAlgorithmTestCase.GetHashOfDefaultData: String;
begin
  Result := FHashOfDefaultData;
end;

function THashAlgorithmTestCase.GetHashOfEmptyData: String;
begin
  Result := FHashOfEmptyData;
end;

function THashAlgorithmTestCase.GetHashOfOnetoNine: String;
begin
  Result := FHashOfOnetoNine;
end;

procedure THashAlgorithmTestCase.SetHashOfABCDE(const AValue: String);
begin
  FHashOfABCDE := AValue;
end;

procedure THashAlgorithmTestCase.SetHashOfDefaultData(const AValue: String);
begin
  FHashOfDefaultData := AValue;
end;

procedure THashAlgorithmTestCase.SetHashOfEmptyData(const AValue: String);
begin
  FHashOfEmptyData := AValue;
end;

procedure THashAlgorithmTestCase.SetHashOfOnetoNine(const AValue: String);
begin
  FHashOfOnetoNine := AValue;
end;

procedure THashAlgorithmTestCase.TestIndexChunkedDataIncrementalHash;
var
  LCount, LIdx: Int32;
  LChunkedDataBytes, LTemp: TBytes;
  LHashInstanceCopy: IHash;
begin
  LHashInstanceCopy := HashInstance.Clone();
  LChunkedDataBytes := TConverters.ConvertStringToBytes(ChunkedData,
    TEncoding.UTF8);
  for LIdx := System.Low(LChunkedDataBytes) to System.High(LChunkedDataBytes) do
  begin
    LCount := System.Length(LChunkedDataBytes) - LIdx;
    LTemp := System.Copy(LChunkedDataBytes, LIdx, LCount);
    HashInstance.Initialize();

    HashInstance.TransformBytes(LChunkedDataBytes, LIdx, LCount);

    ActualString := HashInstance.TransformFinal().ToString();
    ExpectedString := LHashInstanceCopy.ComputeBytes(LTemp).ToString();

    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  end;
end;

procedure THashAlgorithmTestCase.TestInitializeWorks;
var
  LMainData, LResultOne, LResultTwo: TBytes;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  HashInstance.Initialize;
  HashInstance.TransformBytes(LMainData);
  LResultOne := HashInstance.TransformFinal().GetBytes();

  HashInstance.Initialize;
  HashInstance.TransformBytes(LMainData);
  LResultTwo := HashInstance.TransformFinal().GetBytes();

  CheckTrue(AreEqual(LResultOne, LResultTwo));
end;

procedure THashAlgorithmTestCase.TestAnotherChunkedDataIncrementalHash;
var
  LIdx, LSize, LJIdx: Int32;
  LTemp: String;
  LHashInstanceCopy: IHash;
begin
  LHashInstanceCopy := HashInstance.Clone();
  for LIdx := 0 to System.Pred(System.SizeOf(ChunkSizes)
    div System.SizeOf(Int32)) do
  begin
    LSize := ChunkSizes[LIdx];
    HashInstance.Initialize();
    LJIdx := LSize;
    while LJIdx < System.Length(ChunkedData) do
    begin
      LTemp := System.Copy(ChunkedData, (LJIdx - LSize) + 1, LSize);
      HashInstance.TransformString(LTemp, TEncoding.UTF8);

      System.Inc(LJIdx, LSize);
    end;
    LTemp := System.Copy(ChunkedData, (LJIdx - LSize) + 1,
      System.Length(ChunkedData) - ((LJIdx - LSize)));
    HashInstance.TransformString(LTemp, TEncoding.UTF8);

    ActualString := HashInstance.TransformFinal().ToString();
    ExpectedString := LHashInstanceCopy.ComputeString(ChunkedData,
      TEncoding.UTF8).ToString();
    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  end;
end;

procedure THashAlgorithmTestCase.TestBytesABCDE;
var
  LBuffer: TBytes;
begin
  LBuffer := Nil;
  System.SetLength(LBuffer, System.SizeOf(BytesABCDE));
  System.Move(BytesABCDE, Pointer(LBuffer)^, System.SizeOf(BytesABCDE));
  ExpectedString := HashOfABCDE;
  ActualString := HashInstance.ComputeBytes(LBuffer).ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure THashAlgorithmTestCase.TestDefaultData;
begin
  ExpectedString := HashOfDefaultData;
  ActualString := HashInstance.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure THashAlgorithmTestCase.TestEmptyStream;
var
  LStream: TStream;
begin
  LStream := TMemoryStream.Create;
  try
    ExpectedString := HashOfEmptyData;
    ActualString := HashInstance.ComputeStream(LStream).ToString();
    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  finally
    LStream.Free;
  end;
end;

procedure THashAlgorithmTestCase.TestEmptyString;
begin
  ExpectedString := HashOfEmptyData;
  ActualString := HashInstance.ComputeString(EmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure THashAlgorithmTestCase.TestIncrementalHash;
begin
  ExpectedString := HashOfDefaultData;

  HashInstance.Initialize();
  HashInstance.TransformString(System.Copy(DefaultData, 1, 3), TEncoding.UTF8);
  HashInstance.TransformString(System.Copy(DefaultData, 4, 3), TEncoding.UTF8);
  HashInstance.TransformString(System.Copy(DefaultData, 7, 3), TEncoding.UTF8);
  HashInstance.TransformString(System.Copy(DefaultData, 10, 3), TEncoding.UTF8);
  HashInstance.TransformString(System.Copy(DefaultData, 13, 2), TEncoding.UTF8);
  ActualString := HashInstance.TransformFinal().ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure THashAlgorithmTestCase.TestOnetoNine;
begin
  ExpectedString := HashOfOnetoNine;
  ActualString := HashInstance.ComputeString(OneToNine, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure THashAlgorithmTestCase.TestUntypedInterface;
var
  LBuffer, LResultA, LResultB: TBytes;
begin
  LBuffer := Nil;
  System.SetLength(LBuffer, System.SizeOf(BytesABCDE));
  System.Move(BytesABCDE, Pointer(LBuffer)^, System.SizeOf(BytesABCDE));
  LResultA := HashInstance.ComputeBytes(LBuffer).GetBytes();
  LResultB := HashInstance.ComputeUntyped(BytesABCDE, System.SizeOf(BytesABCDE))
    .GetBytes();
  CheckTrue(AreEqual(LResultA, LResultB),
    'Computation Mismatch In Untyped Interface');
end;

{ THashWithUInt32AsKeyAlgorithmTestCase }

function THashWithUInt32AsKeyAlgorithmTestCase.
  GetHashOfDefaultDataWithMaxUInt32AsKey: String;
begin
  Result := FHashOfDefaultDataWithMaxUInt32AsKey;
end;

procedure THashWithUInt32AsKeyAlgorithmTestCase.
  SetHashOfDefaultDataWithMaxUInt32AsKey(const AValue: String);
begin
  FHashOfDefaultDataWithMaxUInt32AsKey := AValue;
end;

procedure THashWithUInt32AsKeyAlgorithmTestCase.TestWithMaxUInt32AsKey;
var
  LIHashWithKey: IHashWithKey;
begin
  ExpectedString := HashOfDefaultDataWithMaxUInt32AsKey;
  LIHashWithKey := (HashInstance as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt32AsBytesLE(System.High(UInt32));
  ActualString := LIHashWithKey.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ THashWithUInt64AsKeyAlgorithmTestCase }

function THashWithUInt64AsKeyAlgorithmTestCase.
  GetHashOfDefaultDataWithMaxUInt64AsKey: String;
begin
  Result := FHashOfDefaultDataWithMaxUInt64AsKey;
end;

procedure THashWithUInt64AsKeyAlgorithmTestCase.
  SetHashOfDefaultDataWithMaxUInt64AsKey(const AValue: String);
begin
  FHashOfDefaultDataWithMaxUInt64AsKey := AValue;
end;

procedure THashWithUInt64AsKeyAlgorithmTestCase.TestWithMaxUInt64AsKey;
var
  LIHashWithKey: IHashWithKey;
begin
  ExpectedString := HashOfDefaultDataWithMaxUInt64AsKey;
  LIHashWithKey := (HashInstance as IHashWithKey);
  LIHashWithKey.Key := TConverters.ReadUInt64AsBytesLE(System.High(UInt64));
  ActualString := LIHashWithKey.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ THashWithExternalKeyAlgorithmTestCase }

function THashWithExternalKeyAlgorithmTestCase.
  GetHashOfDefaultDataWithExternalKey: String;
begin
  Result := FHashOfDefaultDataWithExternalKey;
end;

procedure THashWithExternalKeyAlgorithmTestCase.
  SetHashOfDefaultDataWithExternalKey(const AValue: String);
begin
  FHashOfDefaultDataWithExternalKey := AValue;
end;

procedure THashWithExternalKeyAlgorithmTestCase.TestWithExternalKey;
var
  LIHashWithKey: IHashWithKey;
begin
  ExpectedString := HashOfDefaultDataWithExternalKey;
  LIHashWithKey := (HashInstance as IHashWithKey);
  LIHashWithKey.Key := TConverters.ConvertHexStringToBytes(ZeroToFifteenInHex);
  ActualString := LIHashWithKey.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

{ TCryptoAlgorithmTestCase }

function TCryptoAlgorithmTestCase.GetHashOfDefaultDataHMACWithLongKey: String;
begin
  Result := FHashOfDefaultDataHMACWithLongKey;
end;

function TCryptoAlgorithmTestCase.GetHashOfDefaultDataHMACWithShortKey: String;
begin
  Result := FHashOfDefaultDataHMACWithShortKey;
end;

procedure TCryptoAlgorithmTestCase.SetHashOfDefaultDataHMACWithLongKey
  (const AValue: String);
begin
  FHashOfDefaultDataHMACWithLongKey := AValue;
end;

procedure TCryptoAlgorithmTestCase.SetHashOfDefaultDataHMACWithShortKey
  (const AValue: String);
begin
  FHashOfDefaultDataHMACWithShortKey := AValue;
end;

function TCryptoAlgorithmTestCase.GetHMACInstance: IHMAC;
begin
  Result := FHMACInstance;
end;

procedure TCryptoAlgorithmTestCase.SetHMACInstance(const AValue: IHMAC);
begin
  FHMACInstance := AValue;
end;

procedure TCryptoAlgorithmTestCase.TestHMACWithDefaultDataShortKey;
begin
  ExpectedString := HashOfDefaultDataHMACWithShortKey;
  HMACInstance.Key := TConverters.ConvertStringToBytes(HMACShortStringKey,
    TEncoding.UTF8);
  ActualString := HMACInstance.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TCryptoAlgorithmTestCase.TestHMACWithDefaultDataLongKey;
begin
  ExpectedString := HashOfDefaultDataHMACWithLongKey;
  HMACInstance.Key := TConverters.ConvertStringToBytes(HMACLongStringKey,
    TEncoding.UTF8);
  ActualString := HMACInstance.ComputeString(DefaultData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TCryptoAlgorithmTestCase.TestHMACCloneWorks;
var
  LOriginal, LCopy: IHMAC;
  LMainData, LChunkOne, LChunkTwo: TBytes;
  LCount: Int32;
begin
  LMainData := TConverters.ConvertStringToBytes(DefaultData, TEncoding.UTF8);
  LCount := System.Length(LMainData) - 3;
  LChunkOne := System.Copy(LMainData, 0, LCount);
  LChunkTwo := System.Copy(LMainData, LCount, System.Length(LMainData)
    - LCount);
  LOriginal := HMACInstance;
  (LOriginal as IHMAC).Key := TConverters.ConvertStringToBytes
    (HMACLongStringKey, TEncoding.UTF8);
  LOriginal.Initialize;

  LOriginal.TransformBytes(LChunkOne);
  // Make Copy Of Current State
  LCopy := LOriginal.Clone() as IHMAC;
  LOriginal.TransformBytes(LChunkTwo);
  ExpectedString := LOriginal.TransformFinal().ToString();
  LCopy.TransformBytes(LChunkTwo);
  ActualString := LCopy.TransformFinal().ToString();

  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TCryptoAlgorithmTestCase.TestSplits;
var
  LLen, LSplit1, LSplit2, LIdx: Int32;
  LHash0, LHash1: String;
  LInput: TBytes;
begin
  LInput := Nil;
  System.SetLength(LInput, 20);
  for LIdx := System.Low(LInput) to System.High(LInput) do
  begin
    LInput[LIdx] := LIdx;
  end;

  for LLen := System.Low(LInput) to System.High(LInput) do
  begin
    HashInstance.Initialize();
    HashInstance.TransformBytes(LInput, 0, LLen);
    LHash0 := HashInstance.TransformFinal.ToString();

    for LSplit1 := 0 to LLen do
    begin
      for LSplit2 := LSplit1 to LLen do
      begin
        HashInstance.Initialize();
        HashInstance.TransformBytes(LInput, 0, LSplit1);
        HashInstance.TransformBytes(LInput, LSplit1, LSplit2 - LSplit1);
        HashInstance.TransformBytes(LInput, LSplit2, LLen - LSplit2);
        LHash1 := HashInstance.TransformFinal.ToString();
        CheckEquals(LHash0, LHash1, Format('Expected %s but got %s.',
          [LHash0, LHash1]));
      end;
    end;

  end;

end;

{ TKeyedCryptoAlgorithmTestCase }

function TKeyedCryptoAlgorithmTestCase.GetHashInstanceWithKey: IHash;
begin
  Result := FHashInstanceWithKey;
end;

procedure TKeyedCryptoAlgorithmTestCase.SetHashInstanceWithKey
  (const AValue: IHash);
begin
  FHashInstanceWithKey := AValue;
end;

{ TBlakeCryptoAlgorithmTestCase }

function TBlakeCryptoAlgorithmTestCase.GetKeyedTestVectors: THashLibStringArray;
begin
  Result := FKeyedTestVectors;
end;

function TBlakeCryptoAlgorithmTestCase.GetUnkeyedTestVectors
  : THashLibStringArray;
begin
  Result := FUnkeyedTestVectors;
end;

procedure TBlakeCryptoAlgorithmTestCase.SetKeyedTestVectors
  (const AValue: THashLibStringArray);
begin
  FKeyedTestVectors := AValue;
end;

procedure TBlakeCryptoAlgorithmTestCase.SetUnkeyedTestVectors
  (const AValue: THashLibStringArray);
begin
  FUnkeyedTestVectors := AValue;
end;

procedure TBlakeCryptoAlgorithmTestCase.TestCheckKeyedTestVectors;
var
  LLen, LIdx: Int32;
  LData: TBytes;
begin
  for LLen := System.Low(KeyedTestVectors) to System.High(KeyedTestVectors) do
  begin

    if LLen = 0 then
    begin
      LData := Nil;
    end
    else
    begin
      System.SetLength(LData, LLen);
      for LIdx := System.Low(LData) to System.High(LData) do
      begin
        LData[LIdx] := LIdx;
      end;
    end;

    ActualString := HashInstanceWithKey.ComputeBytes(LData).ToString();
    ExpectedString := KeyedTestVectors[LLen];

    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  end;
end;

procedure TBlakeCryptoAlgorithmTestCase.TestCheckUnkeyedTestVectors;
var
  LIdx, LJdx: Int32;
  LInput: TBytes;
begin
  for LIdx := System.Low(UnkeyedTestVectors)
    to System.High(UnkeyedTestVectors) do
  begin

    if LIdx = 0 then
    begin
      LInput := Nil;
    end
    else
    begin
      System.SetLength(LInput, LIdx);
      for LJdx := System.Low(LInput) to System.High(LInput) do
      begin
        LInput[LJdx] := LJdx;
      end;
    end;

    ActualString := HashInstance.ComputeBytes(LInput).ToString();
    ExpectedString := UnkeyedTestVectors[LIdx];

    CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
      [ExpectedString, ActualString]));
  end;

end;

{ TXofAlgorithmTestCase }

function TXofAlgorithmTestCase.GetXofInstance: IXOF;
begin
  Result := FXofInstance;
end;

function TXofAlgorithmTestCase.GetXofOfEmptyData: String;
begin
  Result := FXofOfEmptyData;
end;

procedure TXofAlgorithmTestCase.SetXofInstance(const AValue: IXOF);
begin
  FXofInstance := AValue;
end;

procedure TXofAlgorithmTestCase.SetXofOfEmptyData(const AValue: String);
begin
  FXofOfEmptyData := AValue;
end;

procedure TXofAlgorithmTestCase.CallShouldRaiseException;
var
  LOutput: TBytes;
begin
  XofInstance.Initialize;
  LOutput := Nil;
  System.SetLength(LOutput, (XofInstance.XOFSizeInBits shr 3));
  XofInstance.TransformUntyped(BytesABCDE, System.SizeOf(BytesABCDE));
  XofInstance.DoOutput(LOutput, 0, System.Length(LOutput));
  // this call below should raise exception since we have already read from the Xof
  XofInstance.TransformUntyped(BytesABCDE, System.SizeOf(BytesABCDE));
end;

procedure TXofAlgorithmTestCase.TestOutputBufferTooShort;
var
  LOutput: TBytes;
begin
  XofInstance.Initialize;
  LOutput := Nil;
  System.SetLength(LOutput, (XofInstance.XOFSizeInBits shr 3));

  try
    XofInstance.DoOutput(LOutput, 1, System.Length(LOutput));
    Fail('no exception');
  except
    on e: EArgumentOutOfRangeHashLibException do
    begin
      CheckEquals('Output Buffer Too Short', e.Message);
    end;
  end;

  LOutput := XofInstance.TransformFinal().GetBytes();
end;

procedure TXofAlgorithmTestCase.TestOutputOverflow;
var
  LOutput: TBytes;
begin
  XofInstance.Initialize;
  LOutput := Nil;
  System.SetLength(LOutput, (XofInstance.XOFSizeInBits shr 3) + 1);

  try
    XofInstance.DoOutput(LOutput, 0, System.Length(LOutput));
    Fail('no exception');
  except
    on e: EArgumentOutOfRangeHashLibException do
    begin
      CheckEquals('Output Length is above the Digest Length', e.Message);
    end;
  end;

  LOutput := XofInstance.TransformFinal().GetBytes();
end;

procedure TXofAlgorithmTestCase.TestVeryLongXofOfEmptyString;
begin
  ActualString := XofInstance.ComputeString(EmptyData, TEncoding.UTF8)
    .ToString();
  ExpectedString := XofOfEmptyData;
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TXofAlgorithmTestCase.TestVeryLongXofOfEmptyStringWithStreamingOutput;
var
  LTempResult, LExpectedChunk, LActualChunk: TBytes;
begin
  LTempResult := Nil;
  System.SetLength(LTempResult, 1000);
  XofInstance.Initialize;
  XofInstance.TransformString(EmptyData, TEncoding.UTF8);

  XofInstance.DoOutput(LTempResult, 0, 250);

  LActualChunk := System.Copy(LTempResult, 0, 250);
  LExpectedChunk := System.Copy(TConverters.ConvertHexStringToBytes
    (XofOfEmptyData), 0, 250);

  CheckTrue(AreEqual(LActualChunk, LExpectedChunk),
    Format('%s Streaming Test 1 Mismatch', [XofInstance.Name]));

  XofInstance.DoOutput(LTempResult, 250, 250);

  LActualChunk := System.Copy(LTempResult, 250, 250);
  LExpectedChunk := System.Copy(TConverters.ConvertHexStringToBytes
    (XofOfEmptyData), 250, 250);

  CheckTrue(AreEqual(LActualChunk, LExpectedChunk),
    Format('%s Streaming Test 2 Mismatch', [XofInstance.Name]));

  XofInstance.DoOutput(LTempResult, 500, 250);

  LActualChunk := System.Copy(LTempResult, 500, 250);
  LExpectedChunk := System.Copy(TConverters.ConvertHexStringToBytes
    (XofOfEmptyData), 500, 250);

  CheckTrue(AreEqual(LActualChunk, LExpectedChunk),
    Format('%s Streaming Test 3 Mismatch', [XofInstance.Name]));

  XofInstance.DoOutput(LTempResult, 750, 250);

  LActualChunk := System.Copy(LTempResult, 750, 250);
  LExpectedChunk := System.Copy(TConverters.ConvertHexStringToBytes
    (XofOfEmptyData), 750, 250);

  CheckTrue(AreEqual(LActualChunk, LExpectedChunk),
    Format('%s Streaming Test 4 Mismatch', [XofInstance.Name]));

  ActualString := TConverters.ConvertBytesToHexString(LTempResult, False);
  ExpectedString := XofOfEmptyData;
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));

  // Verify that Initialization Works
  XofInstance.Initialize;

  XofInstance.DoOutput(LTempResult, 0, 250);

  LActualChunk := System.Copy(LTempResult, 0, 250);
  LExpectedChunk := System.Copy(TConverters.ConvertHexStringToBytes
    (XofOfEmptyData), 0, 250);

  CheckTrue(AreEqual(LActualChunk, LExpectedChunk),
    Format('%s Streaming Initialization Test Fail', [XofInstance.Name]));
end;

procedure TXofAlgorithmTestCase.TestXofShouldRaiseExceptionOnWriteAfterRead;
var
  LTestMethod: TTestMethod;
begin
  LTestMethod := CallShouldRaiseException;
  CheckException(LTestMethod, EInvalidOperationHashLibException);
end;

{ TCShakeAlgorithmTestCase }

function TCShakeAlgorithmTestCase.GetXofInstanceTestVector: IXOF;
begin
  Result := FXofInstanceTestVector;
end;

function TCShakeAlgorithmTestCase.GetXofInstanceShake: IXOF;
begin
  Result := FXofInstanceShake;
end;

function TCShakeAlgorithmTestCase.
  GetXofOfZeroToOneHundredAndNinetyNineInHex: String;
begin
  Result := FXofOfZeroToOneHundredAndNinetyNineInHex;
end;

procedure TCShakeAlgorithmTestCase.SetXofInstanceTestVector(const AValue: IXOF);
begin
  FXofInstanceTestVector := AValue;
end;

procedure TCShakeAlgorithmTestCase.SetXofInstanceShake(const AValue: IXOF);
begin
  FXofInstanceShake := AValue;
end;

procedure TCShakeAlgorithmTestCase.SetXofOfZeroToOneHundredAndNinetyNineInHex
  (const AValue: String);
begin
  FXofOfZeroToOneHundredAndNinetyNineInHex := AValue;
end;

function TCShakeAlgorithmTestCase.ComputeCShake(const ACShake: IHash;
  const AMsg: TBytes): String;
begin
  ACShake.Initialize;
  ACShake.TransformBytes(AMsg);
  Result := ACShake.TransformFinal().ToString();
end;

procedure TCShakeAlgorithmTestCase.TestCShakeAndShakeAreSameWhenNAndSAreEmpty;
var
  LData: TBytes;
begin
  ExpectedString := XofInstance.ComputeString(EmptyData, TEncoding.UTF8)
    .ToString();
  ActualString := XofInstanceShake.ComputeString(EmptyData, TEncoding.UTF8)
    .ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));

  LData := TConverters.ConvertHexStringToBytes(EEAABEEF);
  ExpectedString := XofInstance.ComputeBytes(LData).ToString();
  ActualString := XofInstanceShake.ComputeBytes(LData).ToString();
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

procedure TCShakeAlgorithmTestCase.TestCShake_Vectors;
begin
  ActualString := ComputeCShake(XofInstanceTestVector,
    TConverters.ConvertHexStringToBytes(ZeroToOneHundredAndNinetyNineInHex));
  ExpectedString := XofOfZeroToOneHundredAndNinetyNineInHex;
  CheckEquals(ExpectedString, ActualString, Format('Expected %s but got %s.',
    [ExpectedString, ActualString]));
end;

end.
