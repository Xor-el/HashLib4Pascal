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
    Fc_chunkSize: array [0 .. 259] of Int32 = (1,
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
    FChunkedData
      : String =
      'HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678HashLib4Pascal012345678';
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

    FCRC, FCRCComplete: IHash;

  protected
    procedure TearDown; override;
  published
    procedure TestCheckValue;
    procedure TestCheckValueWithIncrementalHash;
    procedure TestAnotherChunkedDataIncrementalHash;

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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;

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
    procedure TestAnotherChunkedDataIncrementalHash;
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
    procedure TestAnotherChunkedDataIncrementalHash;
    procedure TestQuickBrownDog();

  end;

implementation

// CheckSum

{ TTestCRCModel }

procedure TTestCRCModel.TearDown;
begin
  FCRC := Nil;
  inherited;

end;

procedure TTestCRCModel.TestAnotherChunkedDataIncrementalHash;
var
  Idx: TCRCStandard;
  temp: String;
  x, size, i: Int32;
begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    for Idx := System.Low(TCRCStandard) to System.High(TCRCStandard) do
    begin
      FCRC := THashFactory.TChecksum.CreateCRC(Idx);
      FCRC.Initialize;
      FCRCComplete := THashFactory.TChecksum.CreateCRC(Idx);

      i := size;
      while i < System.Length(FChunkedData) do
      begin
        temp := System.Copy(FChunkedData, (i - size) + 1, size);
        FCRC.TransformString(temp, TEncoding.UTF8);

        System.Inc(i, size);
      end;
      temp := System.Copy(FChunkedData, (i - size) + 1,
        System.Length(FChunkedData) - ((i - size)));
      FCRC.TransformString(temp, TEncoding.UTF8);

      FActualString := FCRC.TransformFinal().ToString();

      FExpectedString := FCRCComplete.ComputeString(FChunkedData,
        TEncoding.UTF8).ToString();

      CheckEquals(FExpectedString, FActualString,
        Format('Expected %s but got %s.' + ' ' + (FCRC as ICRC).Names[0],
        [FExpectedString, FActualString]));

    end;
  end;

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

procedure TTestMurmurHash3_x86_32.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x86_32.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x86_32.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x86_32.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x86_32.TransformFinal().ToString();
    FExpectedString := THashFactory.THash32.CreateMurmurHash3_x86_32.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

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

procedure TTestXXHash32.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FXXHash32.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FXXHash32.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FXXHash32.TransformString(temp, TEncoding.UTF8);

    FActualString := FXXHash32.TransformFinal().ToString();
    FExpectedString := THashFactory.THash32.CreateXXHash32.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

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

procedure TTestSipHash2_4.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FSipHash2_4.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FSipHash2_4.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FSipHash2_4.TransformString(temp, TEncoding.UTF8);

    FActualString := FSipHash2_4.TransformFinal().ToString();
    FExpectedString := THashFactory.THash64.CreateSipHash2_4.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s',
      [FExpectedString, FActualString]));
  end;

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

procedure TTestXXHash64.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FXXHash64.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FXXHash64.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FXXHash64.TransformString(temp, TEncoding.UTF8);

    FActualString := FXXHash64.TransformFinal().ToString();
    FExpectedString := THashFactory.THash64.CreateXXHash64.ComputeString
      (FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

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

procedure TTestMurmurHash3_x86_128.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x86_128.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x86_128.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x86_128.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x86_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x86_128.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString, Format('Expected %s but got %s',
      [FExpectedString, FActualString]));
  end;

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

procedure TTestMurmurHash3_x64_128.TestAnotherChunkedDataIncrementalHash;
var
  x, size, i: Int32;
  temp: string;

begin

  for x := 0 to System.Pred(System.SizeOf(Fc_chunkSize)
    div System.SizeOf(Int32)) do
  begin
    size := Fc_chunkSize[x];
    FMurmurHash3_x64_128.Initialize();
    i := size;
    while i < System.Length(FChunkedData) do
    begin
      temp := System.Copy(FChunkedData, (i - size) + 1, size);
      FMurmurHash3_x64_128.TransformString(temp, TEncoding.UTF8);

      System.Inc(i, size);
    end;
    temp := System.Copy(FChunkedData, (i - size) + 1,
      System.Length(FChunkedData) - ((i - size)));
    FMurmurHash3_x64_128.TransformString(temp, TEncoding.UTF8);

    FActualString := FMurmurHash3_x64_128.TransformFinal().ToString();
    FExpectedString := THashFactory.THash128.CreateMurmurHash3_x64_128.
      ComputeString(FChunkedData, TEncoding.UTF8).ToString();
    CheckEquals(FExpectedString, FActualString,
      Format('Expected %s but got %s.', [FExpectedString, FActualString]));
  end;

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

  CheckEquals(System.Length(BytesABCDE), System.Length(result));
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

  CheckEquals(System.Length(BytesEmpty), System.Length(result));
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

  CheckEquals(System.Length(BytesZeroToNine), System.Length(result));
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
