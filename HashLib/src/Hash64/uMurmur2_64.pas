unit uMurmur2_64;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uConverters,
  uIHashInfo,
  uHashResult,
  uIHashResult,
  uMultipleTransformNonBlock,
  uNullable;

type

  TMurmur2_64 = class sealed(TMultipleTransformNonBlock, IHash64, IHashWithKey,
    ITransformBlock)

  strict private

    Fm_key, Fm_working_key: UInt32;

  const
    CKEY = UInt32($0);
{$IFDEF FPC}
    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
{$WARNINGS OFF}
{$R-}
    M: UInt64 = ($C6A4A7935BD1E995);
{$R+}
{$WARNINGS ON}
{$ELSE}
    M = UInt64($C6A4A7935BD1E995);
{$ENDIF FPC}
    R = Int32(47);

    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);

  strict protected
    function ComputeAggregatedBytes(a_data: THashLibByteArray)
      : IHashResult; override;

  public
    constructor Create();
    procedure Initialize(); override;
    property KeyLength: TNullableInteger read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TMurmur2_64 }

function TMurmur2_64.ComputeAggregatedBytes(a_data: THashLibByteArray)
  : IHashResult;
var
  &length, current_index: Int32;
  h, k, u1, u2, u3, u4, u5, u6, u7, u8: UInt64;
begin

  length := System.length(a_data);

  if (length = 0) then
  begin
    result := THashResult.Create(UInt64(0));
    Exit;
  end;

  h := Fm_working_key xor UInt64(length);
  current_index := 0;

  while (length >= 8) do
  begin
    u1 := UInt64(a_data[current_index]);
    System.Inc(current_index);

    u2 := UInt64(a_data[current_index]) shl 8;
    System.Inc(current_index);

    u3 := UInt64(a_data[current_index]) shl 16;
    System.Inc(current_index);

    u4 := UInt64(a_data[current_index]) shl 24;
    System.Inc(current_index);

    u5 := UInt64(a_data[current_index]) shl 32;
    System.Inc(current_index);

    u6 := UInt64(a_data[current_index]) shl 40;
    System.Inc(current_index);

    u7 := UInt64(a_data[current_index]) shl 48;
    System.Inc(current_index);

    u8 := UInt64(a_data[current_index]) shl 56;
    System.Inc(current_index);

    k := u1 or u2 or u3 or u4 or u5 or u6 or u7 or u8;

    k := k * M;
    k := k xor (k shr R);
    k := k * M;

    h := h xor k;
    h := h * M;

    System.Dec(length, 8);

  end;

  case length of
    7:
      begin
        u1 := UInt64(a_data[current_index]) shl 48;
        System.Inc(current_index);

        u2 := UInt64(a_data[current_index]) shl 40;
        System.Inc(current_index);

        u3 := UInt64(a_data[current_index]) shl 32;
        System.Inc(current_index);

        u4 := UInt64(a_data[current_index]) shl 24;
        System.Inc(current_index);

        u5 := UInt64(a_data[current_index]) shl 16;
        System.Inc(current_index);

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u1 or u2 or u3 or u4 or u5 or u6 or u7);
        h := h * M;
      end;

    6:
      begin

        u2 := UInt64(a_data[current_index]) shl 40;
        System.Inc(current_index);

        u3 := UInt64(a_data[current_index]) shl 32;
        System.Inc(current_index);

        u4 := UInt64(a_data[current_index]) shl 24;
        System.Inc(current_index);

        u5 := UInt64(a_data[current_index]) shl 16;
        System.Inc(current_index);

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u2 or u3 or u4 or u5 or u6 or u7);
        h := h * M;
      end;

    5:
      begin

        u3 := UInt64(a_data[current_index]) shl 32;
        System.Inc(current_index);

        u4 := UInt64(a_data[current_index]) shl 24;
        System.Inc(current_index);

        u5 := UInt64(a_data[current_index]) shl 16;
        System.Inc(current_index);

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u3 or u4 or u5 or u6 or u7);
        h := h * M;
      end;

    4:
      begin

        u4 := UInt64(a_data[current_index]) shl 24;
        System.Inc(current_index);

        u5 := UInt64(a_data[current_index]) shl 16;
        System.Inc(current_index);

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u4 or u5 or u6 or u7);
        h := h * M;
      end;

    3:
      begin

        u5 := UInt64(a_data[current_index]) shl 16;
        System.Inc(current_index);

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u5 or u6 or u7);
        h := h * M;
      end;

    2:
      begin

        u6 := UInt64(a_data[current_index]) shl 8;
        System.Inc(current_index);

        u7 := UInt64(a_data[current_index]);

        h := h xor (u6 or u7);
        h := h * M;
      end;

    1:
      begin

        u7 := UInt64(a_data[current_index]);

        h := h xor (u7);
        h := h * M;
      end;

  end;

  h := h xor (h shr R);
  h := h * M;
  h := h xor (h shr R);

  result := THashResult.Create(h);

end;

constructor TMurmur2_64.Create;
begin
  Inherited Create(8, 8);
  Fm_key := CKEY;

end;

function TMurmur2_64.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

function TMurmur2_64.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

procedure TMurmur2_64.Initialize;
begin
  Fm_working_key := Fm_key;

  Inherited Initialize();

end;

procedure TMurmur2_64.SetKey(value: THashLibByteArray);
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

end.
