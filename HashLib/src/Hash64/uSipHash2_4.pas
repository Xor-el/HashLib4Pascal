unit uSipHash2_4;

{$I ..\Include\HashLib.inc}
// compression rounds c = 2,
// finalization rounds d = 4

interface

uses
  uHashLibTypes,
  uConverters,
  uIHashInfo,
  uHashCryptoNotBuildIn,
  uNullable
{$IFDEF DELPHI}
    , uBitConverter,
  uBits
{$ENDIF DELPHI};

type
  /// <summary>
  /// SipHash 2 - 4 algorithm.
  /// <summary>
  TSipHash2_4 = class sealed(TBlockHash, IHash64, IHashWithKey, ITransformBlock)

  strict private

    Fm_v0, Fm_v1, Fm_v2, Fm_v3, Fm_key0, Fm_key1: UInt64;

{$REGION 'Consts'}

  const
    V0 = UInt64($736F6D6570736575);
    V1 = UInt64($646F72616E646F6D);
    V2 = UInt64($6C7967656E657261);
    V3 = UInt64($7465646279746573);
    KEY0 = UInt64($0706050403020100);
    KEY1 = UInt64($0F0E0D0C0B0A0908);

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

{ TSipHash2_4 }

constructor TSipHash2_4.Create;
begin
  Inherited Create(8, 8);
  Fm_key0 := KEY0;
  Fm_key1 := KEY1;

end;

procedure TSipHash2_4.Finish;
var
  b: UInt64;
  buffer: THashLibByteArray;
begin
  b := Fm_processed_bytes shl 56;

  buffer := Fm_buffer.GetBytesZeroPadded();
  b := b or TConverters.ConvertBytesToUInt64a2(buffer, 0);

  Fm_v3 := Fm_v3 xor b;

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 xor b;
  Fm_v2 := Fm_v2 xor $FF;

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));
end;

function TSipHash2_4.GetKey: THashLibByteArray;
var
  LKey: THashLibByteArray;
begin
  System.SetLength(LKey, KeyLength.value);

  TConverters.ConvertUInt64ToBytes(Fm_key0, LKey, 0);
  TConverters.ConvertUInt64ToBytes(Fm_key1, LKey, 8);

  result := LKey;
end;

function TSipHash2_4.GetKeyLength: TNullableInteger;
begin
  result := 16;
end;

function TSipHash2_4.GetResult: THashLibByteArray;
var
  b: UInt64;
begin
  b := Fm_v0 xor Fm_v1 xor Fm_v2 xor Fm_v3;
{$IFDEF FPC}
  b := BEtoN(b);
{$ENDIF FPC}
{$IFDEF DELPHI}
  // since Delphi compiles to just Little Endian CPU'S, we can blindly assume
  // Little Endian and Swap.
  b := TBits.ReverseBytesUInt64(b);
{$ENDIF DELPHI}
  result := TConverters.ConvertUInt64ToBytes(b);
end;

procedure TSipHash2_4.Initialize;
begin
  Inherited Initialize();

  Fm_v0 := V0;
  Fm_v1 := V1;
  Fm_v2 := V2;
  Fm_v3 := V3;

  Fm_v3 := Fm_v3 xor Fm_key1;
  Fm_v2 := Fm_v2 xor Fm_key0;
  Fm_v1 := Fm_v1 xor Fm_key1;
  Fm_v0 := Fm_v0 xor Fm_key0;

end;

procedure TSipHash2_4.SetKey(value: THashLibByteArray);
begin
  if (value = Nil) then
  begin
    Fm_key0 := KEY0;
    Fm_key1 := KEY1;
  end

  else
  begin
{$IFDEF DEBUG}
    System.Assert(System.Length(value) = KeyLength.value);
{$ENDIF}
    Fm_key0 := TConverters.ConvertBytesToUInt64a2(value, 0);
    Fm_key1 := TConverters.ConvertBytesToUInt64a2(value, 8);
  end;
end;

procedure TSipHash2_4.TransformBlock(a_data: THashLibByteArray; a_index: Int32);
var
  m: UInt64;
begin
  m := TConverters.ConvertBytesToUInt64a2(a_data, a_index);

  Fm_v3 := Fm_v3 xor m;

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 13) or (Fm_v1 shr (64 - 13));
  Fm_v1 := Fm_v1 xor Fm_v0;
  Fm_v0 := (Fm_v0 shl 32) or (Fm_v0 shr (64 - 32));
  Fm_v2 := Fm_v2 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 16) or (Fm_v3 shr (64 - 16));
  Fm_v3 := Fm_v3 xor Fm_v2;
  Fm_v0 := Fm_v0 + Fm_v3;
  Fm_v3 := (Fm_v3 shl 21) or (Fm_v3 shr (64 - 21));
  Fm_v3 := Fm_v3 xor Fm_v0;
  Fm_v2 := Fm_v2 + Fm_v1;
  Fm_v1 := (Fm_v1 shl 17) or (Fm_v1 shr (64 - 17));
  Fm_v1 := Fm_v1 xor Fm_v2;
  Fm_v2 := (Fm_v2 shl 32) or (Fm_v2 shr (64 - 32));

  Fm_v0 := Fm_v0 xor m;

end;

end.
