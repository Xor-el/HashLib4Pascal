unit HlpCRC;

{
  Generic CRC engine for any width 3..64 and any polynomial, plus the catalogue
  of named standards (parameters from http://reveng.sourceforge.net/crc-catalogue/).

  One engine path serves every width: a slicing-by-16 table plus the SIMD /
  scalar fold selected in HlpCRCCore. Widths below 8 with MSB-first input are
  computed in a left-aligned domain (polynomial and state shifted up by
  8 - Width, un-shifted at finalization); LSB-first (reflected) CRCs are
  width-agnostic and run as-is.
}

{$I ..\Include\HashLib.inc}

interface

uses
  SysUtils,
  SyncObjs,
  Generics.Collections,
  HlpHashLibTypes,
  HlpHash,
  HlpIHash,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpICRC,
  HlpCRCCore;

resourcestring
  SWidthOutOfRange = 'Width Must be Between 3 and 64. "%d"';

type
  /// <summary>
  /// All defined and implemented CRC standards.
  /// </summary>
  TCRCStandard = (CRC3_GSM, CRC3_ROHC, CRC4_INTERLAKEN, CRC4_ITU, CRC5_EPC,
    CRC5_ITU, CRC5_USB, CRC6_CDMA2000A, CRC6_CDMA2000B, CRC6_DARC, CRC6_GSM,
    CRC6_ITU, CRC7, CRC7_ROHC, CRC7_UMTS, CRC8, CRC8_AUTOSAR, CRC8_BLUETOOTH,
    CRC8_CDMA2000, CRC8_DARC, CRC8_DVBS2, CRC8_EBU, CRC8_GSMA, CRC8_GSMB,
    CRC8_ICODE, CRC8_ITU, CRC8_LTE, CRC8_MAXIM, CRC8_OPENSAFETY, CRC8_ROHC,
    CRC8_SAEJ1850, CRC8_WCDMA, CRC8_MIFAREMAD, CRC8_NRSC5, CRC10,
    CRC10_CDMA2000, CRC10_GSM, CRC11, CRC11_UMTS, CRC12_CDMA2000, CRC12_DECT,
    CRC12_GSM, CRC12_UMTS, CRC13_BBC, CRC14_DARC, CRC14_GSM, CRC15,
    CRC15_MPT1327, ARC, CRC16_AUGCCITT, CRC16_BUYPASS, CRC16_CCITTFALSE,
    CRC16_CDMA2000, CRC16_CMS, CRC16_DDS110, CRC16_DECTR, CRC16_DECTX,
    CRC16_DNP, CRC16_EN13757, CRC16_GENIBUS, CRC16_GSM, CRC16_LJ1200,
    CRC16_MAXIM, CRC16_MCRF4XX, CRC16_OPENSAFETYA, CRC16_OPENSAFETYB,
    CRC16_PROFIBUS, CRC16_RIELLO, CRC16_T10DIF, CRC16_TELEDISK, CRC16_TMS37157,
    CRC16_USB, CRCA, KERMIT, MODBUS, X25, XMODEM, CRC16_NRSC5, CRC17_CANFD,
    CRC21_CANFD, CRC24, CRC24_BLE, CRC24_FLEXRAYA, CRC24_FLEXRAYB,
    CRC24_INTERLAKEN, CRC24_LTEA, CRC24_LTEB, CRC24_OS9, CRC30_CDMA,
    CRC31_PHILIPS, CRC32, CRC32_AUTOSAR, CRC32_BZIP2, CRC32C, CRC32D,
    CRC32_MPEG2, CRC32_POSIX, CRC32Q, JAMCRC, XFER, CRC32_CDROMEDC, CRC40_GSM,
    CRC64, CRC64_GOISO, CRC64_WE, CRC64_XZ, CRC64_1B, CRC64_Jones);

type
  TCRC = class sealed(THash, IChecksum, ICRC, ITransformBlock)

  strict private
  class var
    FCache: TDictionary<String, TCRCCacheValue>;
    FCacheLock: TCriticalSection;

  var
    FNames: THashLibStringArray;
    FWidth, FEngineWidth, FEngineShift: Int32;
    FPolynomial, FInitialValue, FOutputXor, FCheckValue, FCRCMask,
      FHash: UInt64;
    FIsInputReflected, FIsOutputReflected: Boolean;

    FCacheEntry: TCRCCacheValue;

    class constructor CreateCRCCache;
    class destructor DestroyCRCCache;

    class function GenerateCRCTable(APoly: UInt64; AWidth: Int32;
      AReflected: Boolean): THashLibMatrixUInt64Array; static;
    class function GetOrCreateCacheEntry(APoly: UInt64; AWidth: Int32;
      AReflected: Boolean): TCRCCacheValue; static;

    function GetNames: THashLibStringArray;
    function GetWidth: Int32;
    function GetPolynomial: UInt64;
    function GetInitialValue: UInt64;
    function GetIsInputReflected: Boolean;
    function GetIsOutputReflected: Boolean;
    function GetOutputXor: UInt64;
    function GetCheckValue: UInt64;

    // Table-driven byte path: length < MinSimdBytes or tail after fold.
    procedure UpdateCRCViaByteTable(AData: PByte; ADataLength, AIndex: Int32);

  strict protected
    function GetName: String; override;

  public

    constructor Create(AWidth: Int32; APolynomial, AInitial: UInt64;
      AIsInputReflected, AIsOutputReflected: Boolean;
      AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);

    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;

    function Clone(): IHash; override;

    class function CreateCRCObject(AValue: TCRCStandard): ICRC; static;

  end;

implementation

type
  TCRCStandardDef = record
    Width: Int32;
    Poly, Init: UInt64;
    RefIn, RefOut: Boolean;
    XorOut, Check: UInt64;
    Names: String; // comma-separated aliases; first one is the primary name
  end;

const
  CRCStandardDefs: array [TCRCStandard] of TCRCStandardDef = (
    (Width: 3; Poly: $3; Init: $0; RefIn: False; RefOut: False; XorOut: $7;
      Check: $4; Names: 'CRC-3/GSM'),
    (Width: 3; Poly: $3; Init: $7; RefIn: True; RefOut: True; XorOut: $0;
      Check: $6; Names: 'CRC-3/ROHC'),
    (Width: 4; Poly: $3; Init: $F; RefIn: False; RefOut: False; XorOut: $F;
      Check: $B; Names: 'CRC-4/INTERLAKEN'),
    (Width: 4; Poly: $3; Init: $0; RefIn: True; RefOut: True; XorOut: $0;
      Check: $7; Names: 'CRC-4/ITU,CRC-4/G-704'),
    (Width: 5; Poly: $9; Init: $9; RefIn: False; RefOut: False; XorOut: $00;
      Check: $00; Names: 'CRC-5/EPC,CRC-5/EPC-C1G2'),
    (Width: 5; Poly: $15; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $07; Names: 'CRC-5/ITU,CRC-5/G-704'),
    (Width: 5; Poly: $05; Init: $1F; RefIn: True; RefOut: True; XorOut: $1F;
      Check: $19; Names: 'CRC-5/USB'),
    (Width: 6; Poly: $27; Init: $3F; RefIn: False; RefOut: False; XorOut: $00;
      Check: $0D; Names: 'CRC-6/CDMA2000-A'),
    (Width: 6; Poly: $07; Init: $3F; RefIn: False; RefOut: False; XorOut: $00;
      Check: $3B; Names: 'CRC-6/CDMA2000-B'),
    (Width: 6; Poly: $19; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $26; Names: 'CRC-6/DARC'),
    (Width: 6; Poly: $2F; Init: $00; RefIn: False; RefOut: False; XorOut: $3F;
      Check: $13; Names: 'CRC-6/GSM'),
    (Width: 6; Poly: $03; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $06; Names: 'CRC-6/ITU,CRC-6/G-704'),
    (Width: 7; Poly: $09; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $75; Names: 'CRC-7,CRC-7/MMC'),
    (Width: 7; Poly: $4F; Init: $7F; RefIn: True; RefOut: True; XorOut: $00;
      Check: $53; Names: 'CRC-7/ROHC'),
    (Width: 7; Poly: $45; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $61; Names: 'CRC-7/UMTS'),
    (Width: 8; Poly: $07; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $F4; Names: 'CRC-8,CRC-8/SMBUS'),
    (Width: 8; Poly: $2F; Init: $FF; RefIn: False; RefOut: False; XorOut: $FF;
      Check: $DF; Names: 'CRC-8/AUTOSAR'),
    (Width: 8; Poly: $A7; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $26; Names: 'CRC-8/BLUETOOTH'),
    (Width: 8; Poly: $9B; Init: $FF; RefIn: False; RefOut: False; XorOut: $00;
      Check: $DA; Names: 'CRC-8/CDMA2000'),
    (Width: 8; Poly: $39; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $15; Names: 'CRC-8/DARC'),
    (Width: 8; Poly: $D5; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $BC; Names: 'CRC-8/DVB-S2'),
    (Width: 8; Poly: $1D; Init: $FF; RefIn: True; RefOut: True; XorOut: $00;
      Check: $97; Names: 'CRC-8/EBU,CRC-8/AES,CRC-8/TECH-3250'),
    (Width: 8; Poly: $1D; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $37; Names: 'CRC-8/GSM-A'),
    (Width: 8; Poly: $49; Init: $00; RefIn: False; RefOut: False; XorOut: $FF;
      Check: $94; Names: 'CRC-8/GSM-B'),
    (Width: 8; Poly: $1D; Init: $FD; RefIn: False; RefOut: False; XorOut: $00;
      Check: $7E; Names: 'CRC-8/I-CODE'),
    (Width: 8; Poly: $07; Init: $00; RefIn: False; RefOut: False; XorOut: $55;
      Check: $A1; Names: 'CRC-8/ITU,CRC-8/I-432-1'),
    (Width: 8; Poly: $9B; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $EA; Names: 'CRC-8/LTE'),
    (Width: 8; Poly: $31; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $A1; Names: 'CRC-8/MAXIM,DOW-CRC,CRC-8/MAXIM-DOW'),
    (Width: 8; Poly: $2F; Init: $00; RefIn: False; RefOut: False; XorOut: $00;
      Check: $3E; Names: 'CRC-8/OPENSAFETY'),
    (Width: 8; Poly: $07; Init: $FF; RefIn: True; RefOut: True; XorOut: $00;
      Check: $D0; Names: 'CRC-8/ROHC'),
    (Width: 8; Poly: $1D; Init: $FF; RefIn: False; RefOut: False; XorOut: $FF;
      Check: $4B; Names: 'CRC-8/SAE-J1850'),
    (Width: 8; Poly: $9B; Init: $00; RefIn: True; RefOut: True; XorOut: $00;
      Check: $25; Names: 'CRC-8/WCDMA'),
    (Width: 8; Poly: $1D; Init: $C7; RefIn: False; RefOut: False; XorOut: $00;
      Check: $99; Names: 'CRC-8/MIFARE-MAD'),
    (Width: 8; Poly: $31; Init: $FF; RefIn: False; RefOut: False; XorOut: $00;
      Check: $F7; Names: 'CRC-8/NRSC-5'),
    (Width: 10; Poly: $233; Init: $000; RefIn: False; RefOut: False;
      XorOut: $000; Check: $199; Names: 'CRC-10,CRC-10/ATM,CRC-10/I-610'),
    (Width: 10; Poly: $3D9; Init: $3FF; RefIn: False; RefOut: False;
      XorOut: $000; Check: $233; Names: 'CRC-10/CDMA2000'),
    (Width: 10; Poly: $175; Init: $000; RefIn: False; RefOut: False;
      XorOut: $3FF; Check: $12A; Names: 'CRC-10/GSM'),
    (Width: 11; Poly: $385; Init: $01A; RefIn: False; RefOut: False;
      XorOut: $000; Check: $5A3; Names: 'CRC-11,CRC-11/FLEXRAY'),
    (Width: 11; Poly: $307; Init: $000; RefIn: False; RefOut: False;
      XorOut: $000; Check: $061; Names: 'CRC-11/UMTS'),
    (Width: 12; Poly: $F13; Init: $FFF; RefIn: False; RefOut: False;
      XorOut: $000; Check: $D4D; Names: 'CRC-12/CDMA2000'),
    (Width: 12; Poly: $80F; Init: $000; RefIn: False; RefOut: False;
      XorOut: $000; Check: $F5B; Names: 'CRC-12/DECT,X-CRC-12'),
    (Width: 12; Poly: $D31; Init: $000; RefIn: False; RefOut: False;
      XorOut: $FFF; Check: $B34; Names: 'CRC-12/GSM'),
    (Width: 12; Poly: $80F; Init: $000; RefIn: False; RefOut: True;
      XorOut: $000; Check: $DAF; Names: 'CRC-12/UMTS,CRC-12/3GPP'),
    (Width: 13; Poly: $1CF5; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $04FA; Names: 'CRC-13/BBC'),
    (Width: 14; Poly: $0805; Init: $0000; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $082D; Names: 'CRC-14/DARC'),
    (Width: 14; Poly: $202D; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $3FFF; Check: $30AE; Names: 'CRC-14/GSM'),
    (Width: 15; Poly: $4599; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $059E; Names: 'CRC-15,CRC-15/CAN'),
    (Width: 15; Poly: $6815; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0001; Check: $2566; Names: 'CRC-15/MPT1327'),
    (Width: 16; Poly: $8005; Init: $0000; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $BB3D;
      Names: 'CRC-16,ARC,CRC-IBM,CRC-16/ARC,CRC-16/LHA'),
    (Width: 16; Poly: $1021; Init: $1D0F; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $E5CC;
      Names: 'CRC-16/AUG-CCITT,CRC-16/SPI-FUJITSU'),
    (Width: 16; Poly: $8005; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $FEE8;
      Names: 'CRC-16/BUYPASS,CRC-16/VERIFONE,CRC-16/UMTS'),
    (Width: 16; Poly: $1021; Init: $FFFF; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $29B1;
      Names: 'CRC-16/CCITT-False,CRC-16/AUTOSAR,CRC-16/IBM-3740'),
    (Width: 16; Poly: $C867; Init: $FFFF; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $4C06; Names: 'CRC-16/CDMA2000'),
    (Width: 16; Poly: $8005; Init: $FFFF; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $AEE7; Names: 'CRC-16/CMS'),
    (Width: 16; Poly: $8005; Init: $800D; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $9ECF; Names: 'CRC-16/DDS-110'),
    (Width: 16; Poly: $0589; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0001; Check: $007E; Names: 'CRC-16/DECT-R,R-CRC-16'),
    (Width: 16; Poly: $0589; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $007F; Names: 'CRC-16/DECT-X,X-CRC-16'),
    (Width: 16; Poly: $3D65; Init: $0000; RefIn: True; RefOut: True;
      XorOut: $FFFF; Check: $EA82; Names: 'CRC-16/DNP'),
    (Width: 16; Poly: $3D65; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $FFFF; Check: $C2B7; Names: 'CRC-16/EN13757'),
    (Width: 16; Poly: $1021; Init: $FFFF; RefIn: False; RefOut: False;
      XorOut: $FFFF; Check: $D64E;
      Names: 'CRC-16/GENIBUS,CRC-16/EPC,CRC-16/I-CODE,CRC-16/DARC,CRC-16/EPC-C1G2'),
    (Width: 16; Poly: $1021; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $FFFF; Check: $CE3C; Names: 'CRC-16/GSM'),
    (Width: 16; Poly: $6F63; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $BDF4; Names: 'CRC-16/LJ1200'),
    (Width: 16; Poly: $8005; Init: $0000; RefIn: True; RefOut: True;
      XorOut: $FFFF; Check: $44C2; Names: 'CRC-16/MAXIM,CRC-16/MAXIM-DOW'),
    (Width: 16; Poly: $1021; Init: $FFFF; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $6F91; Names: 'CRC-16/MCRF4XX'),
    (Width: 16; Poly: $5935; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $5D38; Names: 'CRC-16/OPENSAFETY-A'),
    (Width: 16; Poly: $755B; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $20FE; Names: 'CRC-16/OPENSAFETY-B'),
    (Width: 16; Poly: $1DCF; Init: $FFFF; RefIn: False; RefOut: False;
      XorOut: $FFFF; Check: $A819; Names: 'CRC-16/PROFIBUS,CRC-16/IEC-61158-2'),
    (Width: 16; Poly: $1021; Init: $B2AA; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $63D0; Names: 'CRC-16/RIELLO'),
    (Width: 16; Poly: $8BB7; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $D0DB; Names: 'CRC-16/T10-DIF'),
    (Width: 16; Poly: $A097; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $0FB3; Names: 'CRC-16/TELEDISK'),
    (Width: 16; Poly: $1021; Init: $89EC; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $26B1; Names: 'CRC-16/TMS37157'),
    (Width: 16; Poly: $8005; Init: $FFFF; RefIn: True; RefOut: True;
      XorOut: $FFFF; Check: $B4C8; Names: 'CRC-16/USB'),
    (Width: 16; Poly: $1021; Init: $C6C6; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $BF05; Names: 'CRC-A,CRC-16/ISO-IEC-14443-3-A'),
    (Width: 16; Poly: $1021; Init: $0000; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $2189;
      Names: 'KERMIT,CRC-16/CCITT,CRC-16/CCITT-True,CRC-CCITT,CRC-16/KERMIT,CRC-16/V-41-LSB'),
    (Width: 16; Poly: $8005; Init: $FFFF; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $4B37; Names: 'MODBUS,CRC-16/MODBUS'),
    (Width: 16; Poly: $1021; Init: $FFFF; RefIn: True; RefOut: True;
      XorOut: $FFFF; Check: $906E;
      Names: 'X-25,CRC-16/IBM-SDLC,CRC-16/ISO-HDLC,CRC-16/ISO-IEC-14443-3-B,CRC-B,CRC-16/X-25'),
    (Width: 16; Poly: $1021; Init: $0000; RefIn: False; RefOut: False;
      XorOut: $0000; Check: $31C3;
      Names: 'XMODEM,ZMODEM,CRC-16/ACORN,CRC-16/XMODEM,CRC-16/V-41-MSB'),
    (Width: 16; Poly: $080B; Init: $FFFF; RefIn: True; RefOut: True;
      XorOut: $0000; Check: $A066; Names: 'CRC-16/NRSC-5'),
    (Width: 17; Poly: $1685B; Init: $00000; RefIn: False; RefOut: False;
      XorOut: $00000; Check: $04F03; Names: 'CRC-17/CAN-FD'),
    (Width: 21; Poly: $102899; Init: $00000; RefIn: False; RefOut: False;
      XorOut: $00000; Check: $0ED841; Names: 'CRC-21/CAN-FD'),
    (Width: 24; Poly: $864CFB; Init: $B704CE; RefIn: False; RefOut: False;
      XorOut: $000000; Check: $21CF02; Names: 'CRC-24,CRC-24/OPENPGP'),
    (Width: 24; Poly: $00065B; Init: $555555; RefIn: True; RefOut: True;
      XorOut: $000000; Check: $C25A56; Names: 'CRC-24/BLE'),
    (Width: 24; Poly: $5D6DCB; Init: $FEDCBA; RefIn: False; RefOut: False;
      XorOut: $000000; Check: $7979BD; Names: 'CRC-24/FLEXRAY-A'),
    (Width: 24; Poly: $5D6DCB; Init: $ABCDEF; RefIn: False; RefOut: False;
      XorOut: $000000; Check: $1F23B8; Names: 'CRC-24/FLEXRAY-B'),
    (Width: 24; Poly: $328B63; Init: $FFFFFF; RefIn: False; RefOut: False;
      XorOut: $FFFFFF; Check: $B4F3E6; Names: 'CRC-24/INTERLAKEN'),
    (Width: 24; Poly: $864CFB; Init: $000000; RefIn: False; RefOut: False;
      XorOut: $000000; Check: $CDE703; Names: 'CRC-24/LTE-A'),
    (Width: 24; Poly: $800063; Init: $000000; RefIn: False; RefOut: False;
      XorOut: $000000; Check: $23EF52; Names: 'CRC-24/LTE-B'),
    (Width: 24; Poly: $800063; Init: $FFFFFF; RefIn: False; RefOut: False;
      XorOut: $FFFFFF; Check: $200FA5; Names: 'CRC-24/OS-9'),
    (Width: 30; Poly: $2030B9C7; Init: $3FFFFFFF; RefIn: False; RefOut: False;
      XorOut: $3FFFFFFF; Check: $04C34ABF; Names: 'CRC-30/CDMA'),
    (Width: 31; Poly: $04C11DB7; Init: $7FFFFFFF; RefIn: False; RefOut: False;
      XorOut: $7FFFFFFF; Check: $0CE9E46C; Names: 'CRC-31/PHILLIPS'),
    (Width: 32; Poly: $04C11DB7; Init: $FFFFFFFF; RefIn: True; RefOut: True;
      XorOut: $FFFFFFFF; Check: $CBF43926;
      Names: 'CRC-32,CRC-32/ADCCP,CRC-32/V-42,CRC-32/XZ,PKZIP,CRC-32/ISO-HDLC'),
    (Width: 32; Poly: $F4ACFB13; Init: $FFFFFFFF; RefIn: True; RefOut: True;
      XorOut: $FFFFFFFF; Check: $1697D06A; Names: 'CRC-32/AUTOSAR'),
    (Width: 32; Poly: $04C11DB7; Init: $FFFFFFFF; RefIn: False; RefOut: False;
      XorOut: $FFFFFFFF; Check: $FC891918;
      Names: 'CRC-32/BZIP2,CRC-32/AAL5,CRC-32/DECT-B,B-CRC-32'),
    (Width: 32; Poly: $1EDC6F41; Init: $FFFFFFFF; RefIn: True; RefOut: True;
      XorOut: $FFFFFFFF; Check: $E3069283;
      Names: 'CRC-32C,CRC-32/BASE91-C,CRC-32/CASTAGNOLI,CRC-32/INTERLAKEN,CRC-32/ISCSI'),
    (Width: 32; Poly: $A833982B; Init: $FFFFFFFF; RefIn: True; RefOut: True;
      XorOut: $FFFFFFFF; Check: $87315576; Names: 'CRC-32D,CRC-32/BASE91-D'),
    (Width: 32; Poly: $04C11DB7; Init: $FFFFFFFF; RefIn: False; RefOut: False;
      XorOut: $00000000; Check: $0376E6E7; Names: 'CRC-32/MPEG-2'),
    (Width: 32; Poly: $04C11DB7; Init: $FFFFFFFF; RefIn: False; RefOut: False;
      XorOut: $00000000; Check: $0376E6E7; Names: 'CRC-32/POSIX,CKSUM'),
    (Width: 32; Poly: $814141AB; Init: $00000000; RefIn: False; RefOut: False;
      XorOut: $00000000; Check: $3010BF7F; Names: 'CRC-32Q,CRC-32/AIXM'),
    (Width: 32; Poly: $04C11DB7; Init: $FFFFFFFF; RefIn: True; RefOut: True;
      XorOut: $00000000; Check: $340BC6D9; Names: 'JAMCRC,CRC-32/JAMCRC'),
    (Width: 32; Poly: $000000AF; Init: $00000000; RefIn: False; RefOut: False;
      XorOut: $00000000; Check: $BD0BE338; Names: 'XFER,CRC-32/XFER'),
    (Width: 32; Poly: $8001801B; Init: $00000000; RefIn: True; RefOut: True;
      XorOut: $00000000; Check: $6EC2EDC4; Names: 'CRC-32/CD-ROM-EDC'),
    (Width: 40; Poly: $0004820009; Init: $0000000000; RefIn: False;
      RefOut: False; XorOut: $FFFFFFFFFF; Check: $D4164FC646;
      Names: 'CRC-40/GSM'),
    (Width: 64; Poly: $42F0E1EBA9EA3693; Init: $0000000000000000;
      RefIn: False; RefOut: False; XorOut: $0000000000000000;
      Check: $6C40DF5F0B497347; Names: 'CRC-64,CRC-64/ECMA-182'),
    (Width: 64; Poly: $000000000000001B; Init: UInt64($FFFFFFFFFFFFFFFF);
      RefIn: True; RefOut: True; XorOut: UInt64($FFFFFFFFFFFFFFFF);
      Check: UInt64($B90956C775A41001); Names: 'CRC-64/GO-ISO'),
    (Width: 64; Poly: $42F0E1EBA9EA3693; Init: UInt64($FFFFFFFFFFFFFFFF);
      RefIn: False; RefOut: False; XorOut: UInt64($FFFFFFFFFFFFFFFF);
      Check: $62EC59E3F1A4F00A; Names: 'CRC-64/WE'),
    (Width: 64; Poly: $42F0E1EBA9EA3693; Init: UInt64($FFFFFFFFFFFFFFFF);
      RefIn: True; RefOut: True; XorOut: UInt64($FFFFFFFFFFFFFFFF);
      Check: UInt64($995DC9BBDF1939FA); Names: 'CRC-64/XZ,CRC-64/GO-ECMA'),
    (Width: 64; Poly: $000000000000001B; Init: $0000000000000000;
      RefIn: True; RefOut: True; XorOut: $0000000000000000;
      Check: $46A5A9388A5BEFFE; Names: 'CRC-64/1B'),
    (Width: 64; Poly: UInt64($AD93D23594C935A9);
      Init: UInt64($FFFFFFFFFFFFFFFF); RefIn: True; RefOut: True;
      XorOut: $0000000000000000; Check: UInt64($CAA717168609F281);
      Names: 'CRC-64/Jones'));

function SplitNames(const ACsv: String): THashLibStringArray;
var
  LCount, LPos, LStart, LIdx: Int32;
begin
  LCount := 1;
  for LPos := 1 to System.Length(ACsv) do
    if ACsv[LPos] = ',' then
      System.Inc(LCount);
  System.SetLength(Result, LCount);
  LIdx := 0;
  LStart := 1;
  for LPos := 1 to System.Length(ACsv) do
    if ACsv[LPos] = ',' then
    begin
      Result[LIdx] := System.Copy(ACsv, LStart, LPos - LStart);
      System.Inc(LIdx);
      LStart := LPos + 1;
    end;
  Result[LIdx] := System.Copy(ACsv, LStart,
    System.Length(ACsv) - LStart + 1);
end;

{ TCRC }

class constructor TCRC.CreateCRCCache;
begin
  FCache := TDictionary<String, TCRCCacheValue>.Create;
  FCacheLock := TCriticalSection.Create;
end;

class destructor TCRC.DestroyCRCCache;
begin
  FCache.Free;
  FCacheLock.Free;
end;

class function TCRC.GenerateCRCTable(APoly: UInt64; AWidth: Int32;
  AReflected: Boolean): THashLibMatrixUInt64Array;
var
  LCRC: UInt64;
  LIdx, LRow, LBit: Int32;
  LReflectedPoly, LHighBitMask, LMask: UInt64;
begin
  System.SetLength(Result, 16);
  for LIdx := 0 to 15 do
    System.SetLength(Result[LIdx], 256);

  if AReflected then
  begin
    LReflectedPoly := TGF2.BitReverse(APoly, AWidth);
    for LIdx := 0 to 255 do
    begin
      LCRC := UInt64(LIdx);
      for LRow := 0 to 15 do
      begin
        for LBit := 0 to 7 do
          LCRC := (LCRC shr 1) xor (UInt64(-Int64(LCRC and 1)) and LReflectedPoly);
        Result[LRow][LIdx] := LCRC;
      end;
    end;
  end
  else
  begin
    LHighBitMask := UInt64(1) shl (AWidth - 1);
    LMask := ((LHighBitMask - 1) shl 1) or 1;
    for LIdx := 0 to 255 do
    begin
      LCRC := UInt64(LIdx) shl (AWidth - 8);
      for LRow := 0 to 15 do
      begin
        for LBit := 0 to 7 do
        begin
          if (LCRC and LHighBitMask) <> 0 then
            LCRC := ((LCRC shl 1) xor APoly) and LMask
          else
            LCRC := (LCRC shl 1) and LMask;
        end;
        Result[LRow][LIdx] := LCRC;
      end;
    end;
  end;
end;

class function TCRC.GetOrCreateCacheEntry(APoly: UInt64; AWidth: Int32;
  AReflected: Boolean): TCRCCacheValue;
var
  LKey: String;
begin
  LKey := Format('Poly-%x:Width-%d:Reflected-%s',
    [APoly, AWidth, BoolToStr(AReflected, True)]);
  FCacheLock.Acquire;
  try
    if not FCache.TryGetValue(LKey, Result) then
    begin
      Result.Table := GenerateCRCTable(APoly, AWidth, AReflected);
      CRC_InitFoldRuntimeCtx(Result.Table, APoly, AWidth, AReflected,
        Result.FoldRuntime);
      FCache.Add(LKey, Result);
    end;
  finally
    FCacheLock.Release;
  end;
end;

constructor TCRC.Create(AWidth: Int32; APolynomial, AInitial: UInt64;
  AIsInputReflected, AIsOutputReflected: Boolean;
  AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);
begin
  if not(AWidth in [3 .. 64]) then
  begin
    raise EArgumentOutOfRangeHashLibException.CreateResFmt(@SWidthOutOfRange,
      [AWidth]);
  end;

  inherited Create(-1, -1); // Dummy State

  case AWidth of
    3 .. 7:
      Self.HashSize := 1;
    8 .. 16:
      Self.HashSize := 2;
    17 .. 39:
      Self.HashSize := 4;
  else
    Self.HashSize := 8;
  end;
  Self.BlockSize := 1;

  FNames := ANames;
  FWidth := AWidth;
  FPolynomial := APolynomial;
  FInitialValue := AInitial;
  FIsInputReflected := AIsInputReflected;
  FIsOutputReflected := AIsOutputReflected;
  FOutputXor := AOutputXor;
  FCheckValue := ACheckValue;

  // MSB-first CRCs narrower than a byte run left-aligned at width 8
  // (polynomial and state shifted up by FEngineShift, un-shifted at
  // finalization). LSB-first CRCs are width-agnostic and run as-is.
  if (AWidth < 8) and not AIsInputReflected then
    FEngineShift := 8 - AWidth
  else
    FEngineShift := 0;
  FEngineWidth := AWidth + FEngineShift;

  FCRCMask := (((UInt64(1) shl (FEngineWidth - 1)) - 1) shl 1) or 1;

  FCacheEntry := GetOrCreateCacheEntry(APolynomial shl FEngineShift,
    FEngineWidth, AIsInputReflected);
end;

class function TCRC.CreateCRCObject(AValue: TCRCStandard): ICRC;
var
  LDef: TCRCStandardDef;
begin
  LDef := CRCStandardDefs[AValue];
  Result := TCRC.Create(LDef.Width, LDef.Poly, LDef.Init, LDef.RefIn,
    LDef.RefOut, LDef.XorOut, LDef.Check, SplitNames(LDef.Names));
end;

function TCRC.GetNames: THashLibStringArray;
begin
  Result := FNames;
end;

function TCRC.GetWidth: Int32;
begin
  Result := FWidth;
end;

function TCRC.GetPolynomial: UInt64;
begin
  Result := FPolynomial;
end;

function TCRC.GetInitialValue: UInt64;
begin
  Result := FInitialValue;
end;

function TCRC.GetIsInputReflected: Boolean;
begin
  Result := FIsInputReflected;
end;

function TCRC.GetIsOutputReflected: Boolean;
begin
  Result := FIsOutputReflected;
end;

function TCRC.GetOutputXor: UInt64;
begin
  Result := FOutputXor;
end;

function TCRC.GetCheckValue: UInt64;
begin
  Result := FCheckValue;
end;

function TCRC.GetName: String;
begin
  Result := Format('T%s', [FNames[0]]);
end;

procedure TCRC.Initialize;
begin
  if FIsInputReflected then
    FHash := TGF2.BitReverse(FInitialValue, FWidth)
  else
    FHash := FInitialValue shl FEngineShift;
end;

procedure TCRC.UpdateCRCViaByteTable(AData: PByte; ADataLength, AIndex: Int32);
var
  LLength: Int32;
  LTemp: UInt64;
  LCRCTable: THashLibMatrixUInt64Array;
  LPtrData: PByte;
begin
  LLength := ADataLength;
  LPtrData := AData + AIndex;
  LTemp := FHash;
  LCRCTable := FCacheEntry.Table;

  if FIsInputReflected then
  begin
    while LLength > 0 do
    begin
      LTemp := (LTemp shr 8) xor LCRCTable[0][Byte(LTemp xor LPtrData^)];
      System.Inc(LPtrData);
      System.Dec(LLength);
    end;
  end
  else
  begin
    while LLength > 0 do
    begin
      LTemp := (LTemp shl 8) xor LCRCTable[0]
        [Byte((LTemp shr (FEngineWidth - 8)) xor LPtrData^)];
      System.Inc(LPtrData);
      System.Dec(LLength);
    end;
  end;

  FHash := LTemp;
end;

procedure TCRC.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  LPtrAData: PByte;
  LFoldFunc: TCRCFoldFunc;
  LState: UInt64;
  LProcessed, LTail: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}

  LPtrAData := PByte(AData);

  if ALength >= MinSimdBytes then
  begin
    if FIsInputReflected then
    begin
      LFoldFunc := CRC_Fold.Reflected;
      LState := FHash;
    end
    else
    begin
      LFoldFunc := CRC_Fold.Fwd;
      if CRC_Fold.UsesCarrylessMul then
        LState := FHash shl (64 - FEngineWidth)
      else
        LState := FHash;
    end;

    LProcessed := ALength and (not Int32(15));
    FHash := LFoldFunc(LPtrAData + AIndex, UInt32(LProcessed), @LState,
      @FCacheEntry.FoldRuntime) and FCRCMask;
    LTail := ALength - LProcessed;
    if LTail > 0 then
      UpdateCRCViaByteTable(LPtrAData, LTail, AIndex + LProcessed);
  end
  else
    UpdateCRCViaByteTable(LPtrAData, ALength, AIndex);
end;

function TCRC.TransformFinal: IHashResult;
begin
  FHash := FHash shr FEngineShift;
  if FIsInputReflected xor FIsOutputReflected then
    FHash := TGF2.BitReverse(FHash, FWidth);
  FHash := (FHash xor FOutputXor) and (FCRCMask shr FEngineShift);

  case HashSize of
    1:
      Result := THashResult.Create(UInt8(FHash));
    2:
      Result := THashResult.Create(UInt16(FHash));
    4:
      Result := THashResult.Create(UInt32(FHash));
  else
    Result := THashResult.Create(FHash);
  end;

  Initialize();
end;

function TCRC.Clone(): IHash;
var
  LHashInstance: TCRC;
begin
  LHashInstance := TCRC.Create(FWidth, FPolynomial, FInitialValue,
    FIsInputReflected, FIsOutputReflected, FOutputXor, FCheckValue,
    System.Copy(FNames));
  LHashInstance.FHash := FHash;
  Result := LHashInstance;
  Result.BufferSize := BufferSize;
end;

end.
