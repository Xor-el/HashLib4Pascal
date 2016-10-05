unit HlpMurmurHash3_x86_128;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
{$IFDEF DELPHI}
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn,
  HlpNullable,
  HlpBits;

type
  TMurmurHash3_x86_128 = class sealed(TBlockHash, IHash128, IHashWithKey,
    ITransformBlock)

  strict private

    Fm_h1, Fm_h2, Fm_h3, Fm_h4: UInt32;
    Fm_key: UInt32;

{$REGION 'Consts'}

  const
    CKEY = UInt32($0);

    C1 = UInt32($239B961B);
    C2 = UInt32($AB0E9789);
    C3 = UInt32($38B34AE5);
    C4 = UInt32($A1E38B93);
    C5 = UInt32($85EBCA6B);
    C6 = UInt32($C2B2AE35);

    C7 = UInt32($561CCD1B);
    C8 = UInt32($0BCAA747);
    C9 = UInt32($96CD1C35);
    C10 = UInt32($32AC3B17);

{$ENDREGION}
    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);

  strict protected

    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;
    function GetResult(): THashLibByteArray; override;
    procedure Finish(); override;

  public

    constructor Create();
    procedure Initialize(); override;
    property KeyLength: TNullableInteger read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;
  end;

implementation

{ TMurmurHash3_x86_128 }

constructor TMurmurHash3_x86_128.Create;
begin
  Inherited Create(16, 16);
  Fm_key := CKEY;

end;

procedure TMurmurHash3_x86_128.Finish;
var
  &length: Int32;
  data: THashLibByteArray;
  k4, k3, k2, k1: UInt32;
begin
  length := Fm_buffer.Pos;
  data := Fm_buffer.GetBytesZeroPadded();
  case length of
    15:
      begin
        k4 := UInt32(data[14]) shl 16;
        k4 := k4 xor (UInt32(data[13]) shl 8);
        k4 := k4 xor (UInt32(data[12]) shl 0);

        k4 := k4 * C4;
        k4 := TBits.RotateLeft32(k4, 18);
        k4 := k4 * C1;
        Fm_h4 := Fm_h4 xor k4;
      end;

    14:
      begin
        k4 := UInt32(data[13]) shl 8;
        k4 := k4 xor (UInt32(data[12]) shl 0);
        k4 := k4 * C4;
        k4 := TBits.RotateLeft32(k4, 18);
        k4 := k4 * C1;
        Fm_h4 := Fm_h4 xor k4;
      end;

    13:
      begin
        k4 := UInt32(data[12]) shl 0;
        k4 := k4 * C4;
        k4 := TBits.RotateLeft32(k4, 18);
        k4 := k4 * C1;
        Fm_h4 := Fm_h4 xor k4;
      end;

  end;

  if (length > 12) then
    length := 12;

  case length of

    12:
      begin
        k3 := UInt32(data[11]) shl 24;
        k3 := k3 xor (UInt32(data[10]) shl 16);
        k3 := k3 xor (UInt32(data[9]) shl 8);
        k3 := k3 xor (UInt32(data[8]) shl 0);

        k3 := k3 * C3;
        k3 := TBits.RotateLeft32(k3, 17);
        k3 := k3 * C4;
        Fm_h3 := Fm_h3 xor k3;
      end;

    11:
      begin
        k3 := UInt32(data[10]) shl 16;
        k3 := k3 xor (UInt32(data[9]) shl 8);
        k3 := k3 xor (UInt32(data[8]) shl 0);

        k3 := k3 * C3;
        k3 := TBits.RotateLeft32(k3, 17);
        k3 := k3 * C4;
        Fm_h3 := Fm_h3 xor k3;
      end;

    10:
      begin
        k3 := UInt32(data[9]) shl 8;
        k3 := k3 xor (UInt32(data[8]) shl 0);

        k3 := k3 * C3;
        k3 := TBits.RotateLeft32(k3, 17);
        k3 := k3 * C4;
        Fm_h3 := Fm_h3 xor k3;
      end;

    9:
      begin
        k3 := UInt32(data[8]) shl 0;

        k3 := k3 * C3;
        k3 := TBits.RotateLeft32(k3, 17);
        k3 := k3 * C4;
        Fm_h3 := Fm_h3 xor k3;
      end;

  end;

  if (length > 8) then
    length := 8;

  case length of

    8:
      begin
        k2 := UInt32(data[7]) shl 24;
        k2 := k2 xor (UInt32(data[6]) shl 16);
        k2 := k2 xor (UInt32(data[5]) shl 8);
        k2 := k2 xor (UInt32(data[4]) shl 0);

        k2 := k2 * C2;
        k2 := TBits.RotateLeft32(k2, 16);
        k2 := k2 * C3;
        Fm_h2 := Fm_h2 xor k2;
      end;

    7:
      begin
        k2 := UInt32(data[6]) shl 16;
        k2 := k2 xor (UInt32(data[5]) shl 8);
        k2 := k2 xor (UInt32(data[4]) shl 0);

        k2 := k2 * C2;
        k2 := TBits.RotateLeft32(k2, 16);
        k2 := k2 * C3;
        Fm_h2 := Fm_h2 xor k2;
      end;

    6:
      begin
        k2 := UInt32(data[5]) shl 8;
        k2 := k2 xor (UInt32(data[4]) shl 0);

        k2 := k2 * C2;
        k2 := TBits.RotateLeft32(k2, 16);
        k2 := k2 * C3;
        Fm_h2 := Fm_h2 xor k2;
      end;

    5:
      begin
        k2 := UInt32(data[4]) shl 0;

        k2 := k2 * C2;
        k2 := TBits.RotateLeft32(k2, 16);
        k2 := k2 * C3;
        Fm_h2 := Fm_h2 xor k2;
      end;

  end;

  if (length > 4) then
    length := 4;

  case length of

    4:
      begin
        k1 := UInt32(data[3]) shl 24;
        k1 := k1 xor (UInt32(data[2]) shl 16);
        k1 := k1 xor (UInt32(data[1]) shl 8);
        k1 := k1 xor (UInt32(data[0]) shl 0);

        k1 := k1 * C1;
        k1 := TBits.RotateLeft32(k1, 15);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    3:
      begin
        k1 := UInt32(data[2]) shl 16;
        k1 := k1 xor (UInt32(data[1]) shl 8);
        k1 := k1 xor (UInt32(data[0]) shl 0);

        k1 := k1 * C1;
        k1 := TBits.RotateLeft32(k1, 15);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    2:
      begin
        k1 := UInt32(data[1]) shl 8;
        k1 := k1 xor (UInt32(data[0]) shl 0);

        k1 := k1 * C1;
        k1 := TBits.RotateLeft32(k1, 15);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    1:
      begin
        k1 := UInt32(data[0]) shl 0;

        k1 := k1 * C1;
        k1 := TBits.RotateLeft32(k1, 15);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

  end;

  Fm_h1 := Fm_h1 xor Fm_processed_bytes;
  Fm_h2 := Fm_h2 xor Fm_processed_bytes;
  Fm_h3 := Fm_h3 xor Fm_processed_bytes;
  Fm_h4 := Fm_h4 xor Fm_processed_bytes;

  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h1 := Fm_h1 + Fm_h3;
  Fm_h1 := Fm_h1 + Fm_h4;
  Fm_h2 := Fm_h2 + Fm_h1;
  Fm_h3 := Fm_h3 + Fm_h1;
  Fm_h4 := Fm_h4 + Fm_h1;

  Fm_h1 := Fm_h1 xor (Fm_h1 shr 16);
  Fm_h1 := Fm_h1 * C5;
  Fm_h1 := Fm_h1 xor (Fm_h1 shr 13);
  Fm_h1 := Fm_h1 * C6;
  Fm_h1 := Fm_h1 xor (Fm_h1 shr 16);

  Fm_h2 := Fm_h2 xor (Fm_h2 shr 16);
  Fm_h2 := Fm_h2 * C5;
  Fm_h2 := Fm_h2 xor (Fm_h2 shr 13);
  Fm_h2 := Fm_h2 * C6;
  Fm_h2 := Fm_h2 xor (Fm_h2 shr 16);

  Fm_h3 := Fm_h3 xor (Fm_h3 shr 16);
  Fm_h3 := Fm_h3 * C5;
  Fm_h3 := Fm_h3 xor (Fm_h3 shr 13);
  Fm_h3 := Fm_h3 * C6;
  Fm_h3 := Fm_h3 xor (Fm_h3 shr 16);

  Fm_h4 := Fm_h4 xor (Fm_h4 shr 16);
  Fm_h4 := Fm_h4 * C5;
  Fm_h4 := Fm_h4 xor (Fm_h4 shr 13);
  Fm_h4 := Fm_h4 * C6;
  Fm_h4 := Fm_h4 xor (Fm_h4 shr 16);

  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h1 := Fm_h1 + Fm_h3;
  Fm_h1 := Fm_h1 + Fm_h4;
  Fm_h2 := Fm_h2 + Fm_h1;
  Fm_h3 := Fm_h3 + Fm_h1;
  Fm_h4 := Fm_h4 + Fm_h1;

end;

function TMurmurHash3_x86_128.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

function TMurmurHash3_x86_128.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

function TMurmurHash3_x86_128.GetResult: THashLibByteArray;
begin
  System.SetLength(result, 16);

  Fm_h1 := TBits.ReverseBytesUInt32(Fm_h1);
  Fm_h2 := TBits.ReverseBytesUInt32(Fm_h2);
  Fm_h3 := TBits.ReverseBytesUInt32(Fm_h3);
  Fm_h4 := TBits.ReverseBytesUInt32(Fm_h4);

  TConverters.ConvertUInt32ToBytes(Fm_h1, result, 0);
  TConverters.ConvertUInt32ToBytes(Fm_h2, result, 4);
  TConverters.ConvertUInt32ToBytes(Fm_h3, result, 8);
  TConverters.ConvertUInt32ToBytes(Fm_h4, result, 12);
end;

procedure TMurmurHash3_x86_128.Initialize;
begin
  Fm_h1 := Fm_key;
  Fm_h2 := Fm_key;
  Fm_h3 := Fm_key;
  Fm_h4 := Fm_key;

  Inherited Initialize();

end;

procedure TMurmurHash3_x86_128.SetKey(value: THashLibByteArray);
begin
  if (value = Nil) then
  begin
    Fm_key := CKEY;
  end

  else
  begin
{$IFDEF DEBUG}
    System.Assert(System.length(value) = KeyLength.value);
{$ENDIF}
    Fm_key := TConverters.ConvertBytesToUInt32a2(value);

  end;
end;

procedure TMurmurHash3_x86_128.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  k1, k2, k3, k4, u1, u2, u3, u4: UInt32;
begin

  u1 := UInt32(a_data[a_index]);
  System.Inc(a_index);

  u2 := UInt32(a_data[a_index]) shl 8;
  System.Inc(a_index);

  u3 := UInt32(a_data[a_index]) shl 16;
  System.Inc(a_index);

  u4 := UInt32(a_data[a_index]) shl 24;
  System.Inc(a_index);

  k1 := u1 or u2 or u3 or u4;

  k1 := k1 * C1;
  k1 := TBits.RotateLeft32(k1, 15);
  k1 := k1 * C2;
  Fm_h1 := Fm_h1 xor k1;

  Fm_h1 := TBits.RotateLeft32(Fm_h1, 19);

  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h1 := Fm_h1 * 5 + C7;

  u1 := UInt32(a_data[a_index]);
  System.Inc(a_index);

  u2 := UInt32(a_data[a_index]) shl 8;
  System.Inc(a_index);

  u3 := UInt32(a_data[a_index]) shl 16;
  System.Inc(a_index);

  u4 := UInt32(a_data[a_index]) shl 24;
  System.Inc(a_index);

  k2 := u1 or u2 or u3 or u4;

  k2 := k2 * C2;
  k2 := TBits.RotateLeft32(k2, 16);
  k2 := k2 * C3;
  Fm_h2 := Fm_h2 xor k2;

  Fm_h2 := TBits.RotateLeft32(Fm_h2, 17);

  Fm_h2 := Fm_h2 + Fm_h3;
  Fm_h2 := Fm_h2 * 5 + C8;

  u1 := UInt32(a_data[a_index]);
  System.Inc(a_index);

  u2 := UInt32(a_data[a_index]) shl 8;
  System.Inc(a_index);

  u3 := UInt32(a_data[a_index]) shl 16;
  System.Inc(a_index);

  u4 := UInt32(a_data[a_index]) shl 24;
  System.Inc(a_index);

  k3 := u1 or u2 or u3 or u4;

  k3 := k3 * C3;
  k3 := TBits.RotateLeft32(k3, 17);
  k3 := k3 * C4;
  Fm_h3 := Fm_h3 xor k3;

  Fm_h3 := TBits.RotateLeft32(Fm_h3, 15);

  Fm_h3 := Fm_h3 + Fm_h4;
  Fm_h3 := Fm_h3 * 5 + C9;

  u1 := UInt32(a_data[a_index]);
  System.Inc(a_index);

  u2 := UInt32(a_data[a_index]) shl 8;
  System.Inc(a_index);

  u3 := UInt32(a_data[a_index]) shl 16;
  System.Inc(a_index);

  u4 := UInt32(a_data[a_index]) shl 24;

  k4 := u1 or u2 or u3 or u4;

  k4 := k4 * C4;
  k4 := TBits.RotateLeft32(k4, 18);
  k4 := k4 * C1;
  Fm_h4 := Fm_h4 xor k4;

  Fm_h4 := TBits.RotateLeft32(Fm_h4, 13);

  Fm_h4 := Fm_h4 + Fm_h1;
  Fm_h4 := Fm_h4 * 5 + C10;

end;

end.
