unit HlpMurmurHash3_x64_128;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
{$IFDEF DELPHI}
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpHashBuffer,
  HlpConverters,
  HlpIHashInfo,
  HlpHashCryptoNotBuildIn,
  HlpNullable,
  HlpBits;

type
  TMurmurHash3_x64_128 = class sealed(TBlockHash, IHash128, IHashWithKey,
    ITransformBlock)

  strict private

    Fm_h1, Fm_h2: UInt64;
    Fm_key: UInt32;

{$REGION 'Consts'}

  const
    CKEY = UInt32($0);

{$IFDEF FPC}
    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".

    C1: UInt64 = ($87C37B91114253D5);
    C2: UInt64 = ($4CF5AD432745937F);

    C5: UInt64 = ($FF51AFD7ED558CCD);
    C6: UInt64 = ($C4CEB9FE1A85EC53);

{$ELSE}
    C1 = UInt64($87C37B91114253D5);
    C2 = UInt64($4CF5AD432745937F);

    C5 = UInt64($FF51AFD7ED558CCD);
    C6 = UInt64($C4CEB9FE1A85EC53);
{$ENDIF FPC}
    C3 = UInt32($52DCE729);
    C4 = UInt32($38495AB5);

{$ENDREGION}
    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray; inline;
    procedure SetKey(value: THashLibByteArray); inline;

  strict protected

    procedure TransformBlock(a_data: PByte; a_data_length: Int32;
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

{ TMurmurHash3_x64_128 }

constructor TMurmurHash3_x64_128.Create;
begin
  Inherited Create(16, 16);
  Fm_key := CKEY;

end;

procedure TMurmurHash3_x64_128.Finish;
var
  &length: Int32;
  data: THashLibByteArray;
  k2, k1: UInt64;
begin

  length := Fm_buffer.Pos;
  data := Fm_buffer.GetBytesZeroPadded();
  case length of
    15:
      begin
        k2 := UInt64(data[14]) shl 48;
        k2 := k2 xor (UInt64(data[13]) shl 40);
        k2 := k2 xor (UInt64(data[12]) shl 32);
        k2 := k2 xor (UInt64(data[11]) shl 24);
        k2 := k2 xor (UInt64(data[10]) shl 16);
        k2 := k2 xor (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    14:
      begin
        k2 := (UInt64(data[13]) shl 40);
        k2 := k2 xor (UInt64(data[12]) shl 32);
        k2 := k2 xor (UInt64(data[11]) shl 24);
        k2 := k2 xor (UInt64(data[10]) shl 16);
        k2 := k2 xor (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    13:
      begin
        k2 := (UInt64(data[12]) shl 32);
        k2 := k2 xor (UInt64(data[11]) shl 24);
        k2 := k2 xor (UInt64(data[10]) shl 16);
        k2 := k2 xor (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    12:
      begin
        k2 := (UInt64(data[11]) shl 24);
        k2 := k2 xor (UInt64(data[10]) shl 16);
        k2 := k2 xor (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    11:
      begin
        k2 := (UInt64(data[10]) shl 16);
        k2 := k2 xor (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    10:
      begin
        k2 := (UInt64(data[9]) shl 8);
        k2 := k2 xor (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

    9:
      begin
        k2 := (UInt64(data[8]) shl 0);
        k2 := k2 * C2;
        k2 := TBits.RotateLeft64(k2, 33);
        k2 := k2 * C1;
        Fm_h2 := Fm_h2 xor k2;
      end;

  end;

  if (length > 8) then
    length := 8;

  case length of
    8:
      begin
        k1 := UInt64(data[7]) shl 56;
        k1 := k1 xor (UInt64(data[6]) shl 48);
        k1 := k1 xor UInt64(data[5]) shl 40;
        k1 := k1 xor UInt64(data[4]) shl 32;
        k1 := k1 xor UInt64(data[3]) shl 24;
        k1 := k1 xor UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    7:
      begin
        k1 := (UInt64(data[6]) shl 48);
        k1 := k1 xor UInt64(data[5]) shl 40;
        k1 := k1 xor UInt64(data[4]) shl 32;
        k1 := k1 xor UInt64(data[3]) shl 24;
        k1 := k1 xor UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    6:
      begin
        k1 := UInt64(data[5]) shl 40;
        k1 := k1 xor UInt64(data[4]) shl 32;
        k1 := k1 xor UInt64(data[3]) shl 24;
        k1 := k1 xor UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    5:
      begin
        k1 := UInt64(data[4]) shl 32;
        k1 := k1 xor UInt64(data[3]) shl 24;
        k1 := k1 xor UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    4:
      begin
        k1 := UInt64(data[3]) shl 24;
        k1 := k1 xor UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    3:
      begin
        k1 := UInt64(data[2]) shl 16;
        k1 := k1 xor UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    2:
      begin
        k1 := UInt64(data[1]) shl 8;
        k1 := k1 xor UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

    1:
      begin
        k1 := UInt64(data[0]) shl 0;
        k1 := k1 * C1;
        k1 := TBits.RotateLeft64(k1, 31);
        k1 := k1 * C2;
        Fm_h1 := Fm_h1 xor k1;
      end;

  end;

  Fm_h1 := Fm_h1 xor Fm_processed_bytes;
  Fm_h2 := Fm_h2 xor Fm_processed_bytes;

  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h2 := Fm_h2 + Fm_h1;

  Fm_h1 := Fm_h1 xor (Fm_h1 shr 33);
  Fm_h1 := Fm_h1 * C5;
  Fm_h1 := Fm_h1 xor (Fm_h1 shr 33);
  Fm_h1 := Fm_h1 * C6;
  Fm_h1 := Fm_h1 xor (Fm_h1 shr 33);

  Fm_h2 := Fm_h2 xor (Fm_h2 shr 33);
  Fm_h2 := Fm_h2 * C5;
  Fm_h2 := Fm_h2 xor (Fm_h2 shr 33);
  Fm_h2 := Fm_h2 * C6;
  Fm_h2 := Fm_h2 xor (Fm_h2 shr 33);

  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h2 := Fm_h2 + Fm_h1;

end;

function TMurmurHash3_x64_128.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

function TMurmurHash3_x64_128.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

function TMurmurHash3_x64_128.GetResult: THashLibByteArray;
begin
  System.SetLength(result, 16);

  Fm_h1 := TBits.ReverseBytesUInt64(Fm_h1);
  Fm_h2 := TBits.ReverseBytesUInt64(Fm_h2);

  TConverters.ConvertUInt64ToBytes(Fm_h1, result, 0);
  TConverters.ConvertUInt64ToBytes(Fm_h2, result, 8);
end;

procedure TMurmurHash3_x64_128.Initialize;
begin
  Fm_h1 := Fm_key;
  Fm_h2 := Fm_key;

  Inherited Initialize();

end;

procedure TMurmurHash3_x64_128.SetKey(value: THashLibByteArray);
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

procedure TMurmurHash3_x64_128.TransformBlock(a_data: PByte;
  a_data_length: Int32; a_index: Int32);
var
  k1, k2: UInt64;
begin

  k1 := TConverters.ConvertBytesToUInt64a2(a_data, a_index);

  System.Inc(a_index, 8);

  k1 := k1 * C1;
  k1 := TBits.RotateLeft64(k1, 31);
  k1 := k1 * C2;
  Fm_h1 := Fm_h1 xor k1;

  Fm_h1 := (Fm_h1 shl 27) or (Fm_h1 shr 37);
  Fm_h1 := Fm_h1 + Fm_h2;
  Fm_h1 := Fm_h1 * 5 + C3;

  k2 := TConverters.ConvertBytesToUInt64a2(a_data, a_index);

  k2 := k2 * C2;
  k2 := TBits.RotateLeft64(k2, 33);
  k2 := k2 * C1;
  Fm_h2 := Fm_h2 xor k2;

  Fm_h2 := TBits.RotateLeft64(Fm_h2, 31);
  Fm_h2 := Fm_h2 + Fm_h1;
  Fm_h2 := Fm_h2 * 5 + C4;

end;

end.
