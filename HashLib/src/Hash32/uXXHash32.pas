unit uXXHash32;

{$I ..\Include\HashLib.inc}

interface

uses
  uHashLibTypes,
  uHash,
  uConverters,
  uIHashInfo,
  uHashResult,
  uIHashResult,
  uNullable,
  uBits;

type

  TXXHash32 = class sealed(THash, IHash32, IBlockHash, IHashWithKey,
    ITransformBlock)

  strict private

    Fm_key, Fm_hash, Fv1, Fv2, Fv3, Fv4: UInt32;
    FptrLimit, FptrEnd, FptrBuffer, FptrTemp: Pointer;

  const
    CKEY = UInt32(0);

    PRIME32_1 = UInt32(2654435761);
    PRIME32_2 = UInt32(2246822519);
    PRIME32_3 = UInt32(3266489917);
    PRIME32_4 = UInt32(668265263);
    PRIME32_5 = UInt32(374761393);

    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);

  type

    TXXH_State = Record

    private

      total_len: UInt64;
      memsize, v1, v2, v3, v4: UInt32;
      memory: THashLibByteArray;

    end;

  strict private
    F_state: TXXH_State;

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index, a_length: Int32); override;
    function TransformFinal(): IHashResult; override;
    property KeyLength: TNullableInteger read GetKeyLength;
    property Key: THashLibByteArray read GetKey write SetKey;

  end;

implementation

{ TXXHash32 }

constructor TXXHash32.Create;
begin
  Inherited Create(4, 16);
  Fm_key := CKEY;

end;

function TXXHash32.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt32ToBytes(Fm_key);
end;

function TXXHash32.GetKeyLength: TNullableInteger;
begin
  result := 4;
end;

procedure TXXHash32.Initialize;
begin
  Fm_hash := 0;
  F_state.v1 := Fm_key + PRIME32_1 + PRIME32_2;
  F_state.v2 := Fm_key + PRIME32_2;
  F_state.v3 := Fm_key + 0;
  F_state.v4 := Fm_key - PRIME32_1;
  F_state.total_len := 0;
  F_state.memsize := 0;
  System.SetLength(F_state.memory, 16);

end;

procedure TXXHash32.SetKey(value: THashLibByteArray);
begin
  if (value = Nil) then
  begin
    Fm_key := CKEY;
  end
  else
  begin
{$IFDEF DEBUG}
    System.Assert(System.Length(value) = KeyLength.Value);
{$ENDIF}
    Fm_key := TConverters.ConvertBytesToUInt32a2(value);
  end;
end;

procedure TXXHash32.TransformBytes(a_data: THashLibByteArray;
  a_index, a_length: Int32);
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_length >= 0);
  System.Assert(a_index + a_length <= System.Length(a_data));
{$ENDIF}
  FptrBuffer := @a_data[a_index];
  F_state.total_len := F_state.total_len + UInt64(a_length);

  if ((F_state.memsize + UInt32(a_length)) < UInt32(16)) then
  begin

    FptrTemp := {%H-}Pointer({%H-}NativeUInt(F_state.memory) + F_state.memsize);

    System.Move(FptrBuffer^, FptrTemp^, a_length);

    F_state.memsize := F_state.memsize + UInt32(a_length);

    Exit;
  end;

  FptrEnd := {%H-}Pointer({%H-}NativeUInt(FptrBuffer) + UInt32(a_length));

  if F_state.memsize > 0 then
  begin
    FptrTemp := {%H-}Pointer({%H-}NativeUInt(F_state.memory) + F_state.memsize);
    System.Move(FptrBuffer^, FptrTemp^, 16 - F_state.memsize);

    F_state.v1 := PRIME32_1 * TBits.RotateLeft32(F_state.v1 + PRIME32_2 *
      PCardinal(F_state.memory)^, 13);
    F_state.v2 := PRIME32_1 * TBits.RotateLeft32(F_state.v2 + PRIME32_2 *
      {%H-}PCardinal({%H-}NativeUInt(F_state.memory) + 4)^, 13);
    F_state.v3 := PRIME32_1 * TBits.RotateLeft32(F_state.v3 + PRIME32_2 *
      {%H-}PCardinal({%H-}NativeUInt(F_state.memory) + 8)^, 13);
    F_state.v4 := PRIME32_1 * TBits.RotateLeft32(F_state.v4 + PRIME32_2 *
      {%H-}PCardinal({%H-}NativeUInt(F_state.memory) + 12)^, 13);

    FptrBuffer := {%H-}Pointer({%H-}NativeUInt(FptrBuffer) + (16 - F_state.memsize));
    F_state.memsize := 0;
  end;

  if {%H-}NativeUInt({%H-}FptrBuffer) <= ({%H-}NativeUInt({%H-}FptrEnd) - 16) then
  begin
    Fv1 := F_state.v1;
    Fv2 := F_state.v2;
    Fv3 := F_state.v3;
    Fv4 := F_state.v4;

    FptrLimit := {%H-}Pointer({%H-}NativeUInt(FptrEnd) - 16);
    repeat
      Fv1 := PRIME32_1 * TBits.RotateLeft32
        (Fv1 + PRIME32_2 * {%H-}PCardinal({%H-}FptrBuffer)^, 13);
      Fv2 := PRIME32_1 * TBits.RotateLeft32
        (Fv2 + PRIME32_2 * {%H-}PCardinal({%H-}NativeUInt(FptrBuffer) + 4)^, 13);
      Fv3 := PRIME32_1 * TBits.RotateLeft32
        (Fv3 + PRIME32_2 * {%H-}PCardinal({%H-}NativeUInt(FptrBuffer) + 8)^, 13);
      Fv4 := PRIME32_1 * TBits.RotateLeft32
        (Fv4 + PRIME32_2 * {%H-}PCardinal({%H-}NativeUInt(FptrBuffer) + 12)^, 13);
      System.Inc({%H-}NativeUInt(FptrBuffer), 16);
    until not({%H-}NativeUInt(FptrBuffer) <= {%H-}NativeUInt(FptrLimit));

    F_state.v1 := Fv1;
    F_state.v2 := Fv2;
    F_state.v3 := Fv3;
    F_state.v4 := Fv4;
  end;

  if {%H-}NativeUInt(FptrBuffer) < {%H-}NativeUInt(FptrEnd) then
  begin
    FptrTemp := F_state.memory;
    System.Move(FptrBuffer^, FptrTemp^, {%H-}NativeUInt(FptrEnd) -
      {%H-}NativeUInt(FptrBuffer));
    F_state.memsize := {%H-}NativeUInt(FptrEnd) - {%H-}NativeUInt(FptrBuffer);
  end;

end;

function TXXHash32.TransformFinal: IHashResult;
begin

  if F_state.total_len >= UInt64(16) then
    Fm_hash := TBits.RotateLeft32(F_state.v1, 1) +
      TBits.RotateLeft32(F_state.v2, 7) + TBits.RotateLeft32(F_state.v3, 12) +
      TBits.RotateLeft32(F_state.v4, 18)
  else
    Fm_hash := Fm_key + PRIME32_5;
  System.Inc(Fm_hash, F_state.total_len);

  FptrBuffer := F_state.memory;
  FptrEnd := {%H-}Pointer({%H-}NativeUInt(FptrBuffer) + F_state.memsize);
  while ({%H-}NativeUInt({%H-}FptrBuffer) + 4) <= ({%H-}NativeUInt({%H-}FptrEnd)) do
  begin
    Fm_hash := Fm_hash + {%H-}PCardinal({%H-}FptrBuffer)^ * PRIME32_3;
    Fm_hash := TBits.RotateLeft32(Fm_hash, 17) * PRIME32_4;
    System.Inc({%H-}NativeUInt({%H-}FptrBuffer), 4);
  end;

  while {%H-}NativeUInt({%H-}FptrBuffer) <{%H-}NativeUInt({%H-}FptrEnd) do
  begin
    Fm_hash := Fm_hash + PByte(FptrBuffer)^ * PRIME32_5;
    Fm_hash := TBits.RotateLeft32(Fm_hash, 11) * PRIME32_1;
    System.Inc({%H-}NativeUInt({%H-}FptrBuffer));
  end;

  Fm_hash := Fm_hash xor (Fm_hash shr 15);
  Fm_hash := Fm_hash * PRIME32_2;
  Fm_hash := Fm_hash xor (Fm_hash shr 13);
  Fm_hash := Fm_hash * PRIME32_3;
  Fm_hash := Fm_hash xor (Fm_hash shr 16);

  result := THashResult.Create(Fm_hash);
  Initialize();
end;

end.
