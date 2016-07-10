unit uIHashInfo;

interface

uses
  uHashLibTypes,
  uIHash,
  uNullable;

type

  IFastHash32 = Interface(IInterface)
    ['{BA8F0056-E1E0-4C47-8E67-B95886FF0232}']
    function ComputeStringFast(const a_data: String): Int32;
    function ComputeBytesFast(a_data: THashLibByteArray): Int32;
  end;

  ITransformBlock = Interface(IInterface)
    ['{0C375CFF-B379-41B8-955F-A32E22991651}']
  end;

  IBlockHash = Interface(IHash)
    ['{3B9A2D29-AC4E-44E4-92B1-6AF9A64DFF0A}']
  end;

  INonBlockHash = Interface(IInterface)
    ['{7C7E8B14-DBC7-44A3-BB7C-B24E0BFAA09C}']
  end;

  IChecksum = Interface(IInterface)
    ['{EF0885C5-D331-44D8-89CA-05409E20F76E}']
  end;

{$WARNINGS OFF}

  ICRC = Interface(IBlockHash)
    ['{44A105E5-6716-43C0-BE69-AE80F87FDC39}']

    procedure Initialize();
    function GetNames: THashLibStringArray;
    property Names: THashLibStringArray read GetNames;
    function GetWidth: Int32;
    property Width: Int32 read GetWidth;
    function GetPolynomial: UInt64;
    property Polynomial: UInt64 read GetPolynomial;
    function GetInit: UInt64;
    property Init: UInt64 read GetInit;
    function GetReflectIn: Boolean;
    property ReflectIn: Boolean read GetReflectIn;
    function GetReflectOut: Boolean;
    property ReflectOut: Boolean read GetReflectOut;
    function GetXOROut: UInt64;
    property XOROut: UInt64 read GetXOROut;
    function GetCheckValue: UInt64;
    property CheckValue: UInt64 read GetCheckValue;

  end;

{$WARNINGS ON}

  ICrypto = Interface(IBlockHash)
    ['{5C669048-644C-4E96-B411-9FEA603D7086}']
  end;

  ICryptoNotBuildIn = Interface(ICrypto)
    ['{391E62CE-219D-4D33-A753-C32D63353685}']
  end;

  IWithKey = Interface(IHash)
    ['{DD5E0FE4-3573-4051-B7CF-F23BABE982D8}']

    function GetKey(): THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);
    property Key: THashLibByteArray read GetKey write SetKey;
    function GetKeyLength(): TNullableInteger;
    property KeyLength: TNullableInteger read GetKeyLength;

  end;

  IHMAC = Interface(IWithKey)
    ['{A6D4DCC6-F6C3-4110-8CA2-FBE85227676E}']
  end;

  IHMACNotBuildIn = Interface(IHMAC)
    ['{A44E01D3-164E-4E3F-9551-3EFFDE95A36C}']
  end;

  IHash16 = Interface(IHash)
    ['{C15AF648-C9F7-460D-9F74-B68CA593C2F8}']
  end;

  IHash32 = Interface(IHash)
    ['{004BBFDB-71B6-4C74-ABE8-88EC1777263D}']
  end;

  IHash64 = Interface(IHash)
    ['{F0354E86-3BEC-4EBC-B17D-ABFC91C02997}']
  end;

  IHash128 = Interface(IHash)
    ['{8DD14E37-DDD6-455C-A795-21A15C9E5376}']
  end;

  IHashWithKey = Interface(IWithKey)
    ['{D38AE885-651F-4F15-BF90-5B64A0F24E49}']
  end;

implementation

end.
