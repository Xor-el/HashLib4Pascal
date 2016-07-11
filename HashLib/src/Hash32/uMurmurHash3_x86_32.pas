unit uMurmurHash3_x86_32;

{$I ..\..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uConverters,
  uIHashInfo,
  uHashCryptoNotBuildIn,
  uNullable
{$IFDEF DELPHI}
    , uBits
{$ENDIF DELPHI};

type

  TMurmurHash3_x86_32 = class sealed(TBlockHash, IHash32, IFastHash32,
    IHashWithKey, ITransformBlock)

  strict private

    Fm_key, Fm_h: UInt32;

  const
    CKEY = UInt32($0);

    C1 = UInt32($CC9E2D51);
    C2 = UInt32($1B873593);
    C3 = UInt32($E6546B64);
    C4 = UInt32($85EBCA6B);
    C5 = UInt32($C2B2AE35);

    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);
    procedure TransformUInt32Fast(a_data: UInt32);

  strict protected
    procedure TransformBlock(a_data: THashLibByteArray;
      a_index: Int32); override;
    procedure Finish(); override;
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;
    function ComputeStringFast(const a_data: String): Int32;
    function ComputeBytesFast(a_data: THashLibByteArray): Int32;
    property KeyLength: TNullableInteger read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TMurmurHash3_x86_32 }

constructor TMurmurHash3_x86_32.Create;
begin
  Inherited Create(4, 4);
  Fm_key := CKEY;

end;

procedure TMurmurHash3_x86_32.Finish;
var
  left: UInt64;
  buffer: THashLibByteArray;
  k: UInt32;
begin
  left := Fm_processed_bytes mod UInt64(BlockSize);

  if (left <> 0) then
  begin
    buffer := Fm_buffer.GetBytesZeroPadded();

    case (left) of

      3:
        begin
          k := UInt32(buffer[2]) shl 16 or (UInt32(buffer[1]) shl 8) or
            UInt32(buffer[0]);
          k := k * C1;
          k := (k shl 15) or (k shr 17);
          k := k * C2;
          Fm_h := Fm_h xor k;

        end;
      2:
        begin

          k := (UInt32(buffer[1]) shl 8) or UInt32(buffer[0]);
          k := k * C1;
          k := (k shl 15) or (k shr 17);
          k := k * C2;
          Fm_h := Fm_h xor k;

        end;
      1:
        begin

          k := UInt32(buffer[0]);
          k := k * C1;
          k := (k shl 15) or (k shr 17);
          k := k * C2;
          Fm_h := Fm_h xor k;

        end;
    end;
  end;

  Fm_h := Fm_h xor UInt32(Fm_processed_bytes);

  Fm_h := Fm_h xor (Fm_h shr 16);
  Fm_h := Fm_h * C4;
  Fm_h := Fm_h xor (Fm_h shr 13);
  Fm_h := Fm_h * C5;
  Fm_h := Fm_h xor (Fm_h shr 16);
end;

function TMurmurHash3_x86_32.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

procedure TMurmurHash3_x86_32.SetKey(value: THashLibByteArray);
begin
  if (value = Nil) then
  begin
    Fm_key := CKEY;
  end
  else
  begin
{$IFDEF DEBUG}
    System.Assert(System.Length(value) = KeyLength.value);
{$ENDIF}
    Fm_key := TConverters.ConvertBytesToUInt32a2(value);
  end;
end;

function TMurmurHash3_x86_32.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

function TMurmurHash3_x86_32.GetResult: THashLibByteArray;
begin
  System.SetLength(result, 4);
{$IFDEF FPC}
  Fm_h := BEtoN(Fm_h);
{$ENDIF FPC}
{$IFDEF DELPHI}
  // since Delphi compiles to just Little Endian CPU'S, we can blindly assume
  // Little Endian and Swap.
  Fm_h := TBits.ReverseBytesUInt32(Fm_h);
{$ENDIF DELPHI}
  result[0] := Byte(Fm_h);
  result[1] := Byte(Fm_h shr 8);
  result[2] := Byte(Fm_h shr 16);
  result[3] := Byte(Fm_h shr 24);

end;

procedure TMurmurHash3_x86_32.Initialize;
begin
  Fm_h := Fm_key;
  inherited Initialize();
end;

procedure TMurmurHash3_x86_32.TransformBlock(a_data: THashLibByteArray;
  a_index: Int32);
var
  k, u1, u2, u3, u4: UInt32;

begin
  u1 := a_data[a_index];
  System.Inc(a_index);
  u2 := UInt32(a_data[a_index]) shl 8;
  System.Inc(a_index);
  u3 := UInt32(a_data[a_index]) shl 16;
  System.Inc(a_index);
  u4 := UInt32(a_data[a_index]) shl 24;
  k := u1 or u2 or u3 or u4;

  TransformUInt32Fast(k);
end;

procedure TMurmurHash3_x86_32.TransformUInt32Fast(a_data: UInt32);
var
  k: UInt32;
begin
  k := a_data;

  k := k * C1;
  k := (k shl 15) or (k shr 17);
  k := k * C2;

  Fm_h := Fm_h xor k;
  Fm_h := (Fm_h shl 13) or (Fm_h shr 19);
  Fm_h := Fm_h * 5 + C3;
end;

{$OVERFLOWCHECKS OFF}

function TMurmurHash3_x86_32.ComputeBytesFast(a_data: THashLibByteArray): Int32;
var
  &length, current_index: Int32;
  k: UInt32;
begin
  Fm_h := Fm_key;

  current_index := 0;
  Length := System.Length(a_data);

  while (Length >= 4) do
  begin
    k := UInt32(a_data[current_index]) or
      (UInt32(a_data[current_index + 1]) shl 8) or
      (UInt32(a_data[current_index + 2]) shl 16) or
      (UInt32(a_data[current_index + 3]) shl 24);

    k := k * C1;
    k := (k shl 15) or (k shr 17);
    k := k * C2;

    Fm_h := Fm_h xor k;
    Fm_h := (Fm_h shl 13) or (Fm_h shr 19);
    Fm_h := Fm_h * 5 + C3;

    current_index := current_index + 4;
    System.Dec(Length, 4);
  end;

  case (Length) of
    3:
      begin
        k := UInt32(a_data[current_index + 2]) shl 16 or
          (UInt32(a_data[current_index + 1]) shl 8) or
          UInt32(a_data[current_index]);
        k := k * C1;
        k := (k shl 15) or (k shr 17);
        k := k * C2;
        Fm_h := Fm_h xor k;

      end;
    2:
      begin

        k := (UInt32(a_data[current_index + 1]) shl 8) or
          UInt32(a_data[current_index]);
        k := k * C1;
        k := (k shl 15) or (k shr 17);
        k := k * C2;
        Fm_h := Fm_h xor k;

      end;
    1:
      begin

        k := UInt32(a_data[current_index]);
        k := k * C1;
        k := (k shl 15) or (k shr 17);
        k := k * C2;
        Fm_h := Fm_h xor k;

      end;
  end;

  Fm_h := Fm_h xor UInt32(System.Length(a_data));

  Fm_h := Fm_h xor (Fm_h shr 16);
  Fm_h := Fm_h * C4;
  Fm_h := Fm_h xor (Fm_h shr 13);
  Fm_h := Fm_h * C5;
  Fm_h := Fm_h xor (Fm_h shr 16);

  result := Int32(Fm_h);
  Initialize();

end;

{$OVERFLOWCHECKS ON}
{$OVERFLOWCHECKS OFF}

function TMurmurHash3_x86_32.ComputeStringFast(const a_data: String): Int32;
var
  &length, current_index: Int32;
  k, u1: UInt32;
begin
  Fm_h := Fm_key;
  Length := System.Length(a_data) * System.SizeOf(Char);
  current_index := 0;

  while (Length >= 4) do
  begin
    u1 := UInt32(System.Ord(a_data[current_index]));
    System.Inc(current_index);
    k := u1 or (UInt32(System.Ord(a_data[current_index]) shl 16));
    System.Inc(current_index);

    TransformUInt32Fast(k);

    System.Dec(Length, 4);
  end;

  if (Length = 2) then
  begin
    k := UInt32(System.Ord(a_data[current_index]));
    k := k * C1;
    k := (k shl 15) or (k shr 17);
    k := k * C2;
    Fm_h := Fm_h xor k;
  end;

  Fm_h := Fm_h xor (UInt32(System.Length(a_data)) * System.SizeOf(Char));

  Fm_h := Fm_h xor (Fm_h shr 16);
  Fm_h := Fm_h * C4;
  Fm_h := Fm_h xor (Fm_h shr 13);
  Fm_h := Fm_h * C5;
  Fm_h := Fm_h xor (Fm_h shr 16);

  result := Int32(Fm_h);
  Initialize();

end;

{$OVERFLOWCHECKS ON}

end.
