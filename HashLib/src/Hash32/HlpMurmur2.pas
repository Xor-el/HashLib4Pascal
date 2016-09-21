unit HlpMurmur2;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpConverters,
  HlpIHashInfo,
  HlpHashResult,
  HlpIHashResult,
  HlpMultipleTransformNonBlock,
  HlpNullable;

type

  TMurmur2 = class sealed(TMultipleTransformNonBlock, IHash32, IFastHash32,
    IHashWithKey, ITransformBlock)

  strict private
    class var

      Fm_key, Fm_working_key, Fm_h: UInt32;

  const
    CKEY = UInt32($0);
    M = UInt32($5BD1E995);
    R = Int32(24);

    function InternalComputeBytes(a_data: THashLibByteArray): Int32;
    procedure TransformUInt32Fast(a_data: UInt32);
    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);

  strict protected
    function ComputeAggregatedBytes(a_data: THashLibByteArray)
      : IHashResult; override;

  public
    constructor Create();
    procedure Initialize(); override;
    function ComputeStringFast(const a_data: String): Int32;
    function ComputeBytesFast(a_data: THashLibByteArray): Int32;
    property KeyLength: TNullableInteger read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TMurmur2 }

constructor TMurmur2.Create;
begin
  Inherited Create(4, 4);
  Fm_key := CKEY;

end;

function TMurmur2.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

procedure TMurmur2.SetKey(value: THashLibByteArray);
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

procedure TMurmur2.TransformUInt32Fast(a_data: UInt32);
begin
  a_data := a_data * M;
  a_data := a_data xor (a_data shr R);
  a_data := a_data * M;

  Fm_h := Fm_h * M;
  Fm_h := Fm_h xor a_data;
end;

function TMurmur2.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

procedure TMurmur2.Initialize;
begin
  Fm_working_key := Fm_key;
  inherited Initialize();
end;

{$OVERFLOWCHECKS OFF}

function TMurmur2.InternalComputeBytes(a_data: THashLibByteArray): Int32;
var
  &length, current_index: Int32;
  k, u1, u2, u3, u4: UInt32;
begin
  Length := System.Length(a_data);

  if (Length = 0) then
  begin
    result := 0;
    Exit;
  end;

  Fm_h := Fm_working_key xor UInt32(Length);
  current_index := 0;

  while (Length >= 4) do
  begin
    u1 := a_data[current_index];
    System.Inc(current_index);
    u2 := UInt32(a_data[current_index]) shl 8;
    System.Inc(current_index);
    u3 := UInt32(a_data[current_index]) shl 16;
    System.Inc(current_index);
    u4 := UInt32(a_data[current_index]) shl 24;
    System.Inc(current_index);
    k := u1 or u2 or u3 or u4;

    TransformUInt32Fast(k);
    System.Dec(Length, 4);
  end;

  case Length of
    3:
      begin
        u1 := a_data[current_index];
        System.Inc(current_index);
        Fm_h := Fm_h xor (Byte(u1) or (a_data[current_index] shl 8));
        System.Inc(current_index);
        Fm_h := Fm_h xor UInt32(a_data[current_index] shl 16);

        Fm_h := Fm_h * M;
      end;

    2:
      begin
        u1 := a_data[current_index];
        System.Inc(current_index);
        Fm_h := Fm_h xor (Byte(u1) or (a_data[current_index] shl 8));

        Fm_h := Fm_h * M;
      end;
    1:
      begin
        Fm_h := Fm_h xor (a_data[current_index]);

        Fm_h := Fm_h * M;
      end;

  end;

  Fm_h := Fm_h xor (Fm_h shr 13);

  Fm_h := Fm_h * M;
  Fm_h := Fm_h xor (Fm_h shr 15);

  result := Int32(Fm_h);
end;

{$OVERFLOWCHECKS ON}

function TMurmur2.ComputeAggregatedBytes(a_data: THashLibByteArray)
  : IHashResult;

begin
  result := THashResult.Create(InternalComputeBytes(a_data));
end;

function TMurmur2.ComputeBytesFast(a_data: THashLibByteArray): Int32;
begin
  Initialize();

  result := InternalComputeBytes(a_data);
end;

{$OVERFLOWCHECKS OFF}

function TMurmur2.ComputeStringFast(const a_data: String): Int32;
var
  &length, current_index: Int32;
  k, u1, u2: UInt32;
begin
  Initialize();

  Length := System.Length(a_data) * 2;

  if (Length = 0) then
  begin
    result := 0;
    Exit;
  end;

  Fm_h := Fm_working_key xor UInt32(Length);
  current_index := 0;

  while (Length >= 4) do
  begin
    u1 := System.Ord(a_data[current_index]);
    System.Inc(current_index);
    u2 := System.Ord(a_data[current_index]);
    System.Inc(current_index);
    k := u1 or (u2 shl 16);

    TransformUInt32Fast(k);

    System.Dec(Length, 4);

  end;

  if (Length = 2) then
  begin
    Fm_h := Fm_h xor UInt32(a_data[current_index]);
    Fm_h := Fm_h * M;
  end;

  Fm_h := Fm_h xor (Fm_h shr 13);
  Fm_h := Fm_h * M;
  Fm_h := Fm_h xor (Fm_h shr 15);

  result := Int32(Fm_h);
end;

{$OVERFLOWCHECKS ON}

end.
