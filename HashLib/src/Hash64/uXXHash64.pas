unit uXXHash64;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI}
  uBitConverter,
{$ENDIF DELPHI}
  uHashLibTypes,
  uHash,
  uConverters,
  uIHashInfo,
  uHashResult,
  uIHashResult,
  uNullable,
  uBits;

type

  TXXHash64 = class sealed(THash, IHash64, IBlockHash, IHashWithKey,
    ITransformBlock)

  strict private

    Fm_key, Fm_hash, Fv1, Fv2, Fv3, Fv4: UInt64;
    FptrLimit, FptrEnd, FptrBuffer, FptrTemp: Pointer;

  const
    CKEY = UInt64(0);

{$IFDEF FPC}
    // to bypass Internal error (200706094) on FPC, We use "Typed Constant".
    PRIME64_1: UInt64 = (11400714785074694791);
    PRIME64_2: UInt64 = (14029467366897019727);
    PRIME64_3: UInt64 = (1609587929392839161);
    PRIME64_4: UInt64 = (9650029242287828579);
    PRIME64_5: UInt64 = (2870177450012600261);
{$ELSE}
    PRIME64_1 = UInt64(11400714785074694791);
    PRIME64_2 = UInt64(14029467366897019727);
    PRIME64_3 = UInt64(1609587929392839161);
    PRIME64_4 = UInt64(9650029242287828579);
    PRIME64_5 = UInt64(2870177450012600261);
{$ENDIF FPC}
    function GetKeyLength(): TNullableInteger;
    function GetKey: THashLibByteArray;
    procedure SetKey(value: THashLibByteArray);

  type

    TXXH_State = Record

    private

      total_len, v1, v2, v3, v4: UInt64;
      memsize: UInt32;
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

{ TXXHash64 }

constructor TXXHash64.Create;
begin
  Inherited Create(8, 32);
  Fm_key := CKEY;

end;

function TXXHash64.GetKey: THashLibByteArray;
begin
  result := TConverters.ConvertUInt64ToBytes(Fm_key);
end;

function TXXHash64.GetKeyLength: TNullableInteger;
begin
  result := 8;
end;

procedure TXXHash64.Initialize;
begin
  Fm_hash := 0;
  F_state.v1 := Fm_key + PRIME64_1 + PRIME64_2;
  F_state.v2 := Fm_key + PRIME64_2;
  F_state.v3 := Fm_key + 0;
  F_state.v4 := Fm_key - PRIME64_1;
  F_state.total_len := 0;
  F_state.memsize := 0;
  System.SetLength(F_state.memory, 32);

end;

procedure TXXHash64.SetKey(value: THashLibByteArray);
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
    Fm_key := TConverters.ConvertBytesToUInt64a2(value);
  end;
end;

procedure TXXHash64.TransformBytes(a_data: THashLibByteArray;
  a_index, a_length: Int32);
begin

{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_length >= 0);
  System.Assert(a_index + a_length <= System.Length(a_data));
{$ENDIF}
  FptrBuffer := @a_data[a_index];
  F_state.total_len := F_state.total_len + UInt64(a_length);

  if ((F_state.memsize + UInt32(a_length)) < UInt32(32)) then
  begin

    FptrTemp := {%H-}Pointer({%H-}NativeUInt({%H-}F_state.memory) + F_state.memsize);

    System.Move(FptrBuffer^, FptrTemp^, a_length);

    F_state.memsize := F_state.memsize + UInt32(a_length);
    Exit;
  end;

  FptrEnd := {%H-}Pointer({%H-}NativeUInt({%H-}FptrBuffer) + UInt32(a_length));

  if F_state.memsize > 0 then
  begin
    FptrTemp := {%H-}Pointer({%H-}NativeUInt({%H-}F_state.memory) + F_state.memsize);
    System.Move(FptrBuffer^, FptrTemp^, 32 - F_state.memsize);

    F_state.v1 := PRIME64_1 * TBits.RotateLeft64(F_state.v1 + PRIME64_2 *
      PUInt64(F_state.memory)^, 31);
    F_state.v2 := PRIME64_1 * TBits.RotateLeft64(F_state.v2 + PRIME64_2 *
      {%H-}PUInt64({%H-}NativeUInt({%H-}F_state.memory) + 8)^, 31);
    F_state.v3 := PRIME64_1 * TBits.RotateLeft64(F_state.v3 + PRIME64_2 *
      {%H-}PUInt64({%H-}NativeUInt({%H-}F_state.memory) + 16)^, 31);
    F_state.v4 := PRIME64_1 * TBits.RotateLeft64(F_state.v4 + PRIME64_2 *
      {%H-}PUInt64({%H-}NativeUInt({%H-}F_state.memory) + 24)^, 31);

    FptrBuffer := {%H-}Pointer({%H-}NativeUInt(FptrBuffer) + (32 - F_state.memsize));
    F_state.memsize := 0;
  end;

  if {%H-}NativeUInt({%H-}FptrBuffer) <= ({%H-}NativeUInt({%H-}FptrEnd) - 32) then
  begin
    Fv1 := F_state.v1;
    Fv2 := F_state.v2;
    Fv3 := F_state.v3;
    Fv4 := F_state.v4;

    FptrLimit := {%H-}Pointer({%H-}NativeUInt(FptrEnd) - 32);
    repeat
      Fv1 := PRIME64_1 * TBits.RotateLeft64
        (Fv1 + PRIME64_2 * PUInt64(FptrBuffer)^, 31);
      Fv2 := PRIME64_1 * TBits.RotateLeft64
        (Fv2 + PRIME64_2 * {%H-}PUInt64({%H-}NativeUInt({%H-}FptrBuffer) + 8)^, 31);
      Fv3 := PRIME64_1 * TBits.RotateLeft64
        (Fv3 + PRIME64_2 * {%H-}PUInt64({%H-}NativeUInt({%H-}FptrBuffer) + 16)^, 31);
      Fv4 := PRIME64_1 * TBits.RotateLeft64
        (Fv4 + PRIME64_2 * {%H-}PUInt64({%H-}NativeUInt({%H-}FptrBuffer) + 24)^, 31);
      System.Inc({%H-}NativeUInt({%H-}FptrBuffer), 32);
    until not({%H-}NativeUInt({%H-}FptrBuffer) <= {%H-}NativeUInt({%H-}FptrLimit));

    F_state.v1 := Fv1;
    F_state.v2 := Fv2;
    F_state.v3 := Fv3;
    F_state.v4 := Fv4;
  end;

  if {%H-}NativeUInt({%H-}FptrBuffer) < {%H-}NativeUInt({%H-}FptrEnd) then
  begin
    FptrTemp := F_state.memory;
    System.Move(FptrBuffer^, FptrTemp^, {%H-}NativeUInt({%H-}FptrEnd) -
      {%H-}NativeUInt({%H-}FptrBuffer));
    F_state.memsize := {%H-}NativeUInt({%H-}FptrEnd) - {%H-}NativeUInt({%H-}FptrBuffer);
  end;

end;

function TXXHash64.TransformFinal: IHashResult;
begin

  if F_state.total_len >= UInt64(32) then
  begin
    Fv1 := F_state.v1;
    Fv2 := F_state.v2;
    Fv3 := F_state.v3;
    Fv4 := F_state.v4;

    Fm_hash := TBits.RotateLeft64(Fv1, 1) + TBits.RotateLeft64(Fv2, 7) +
      TBits.RotateLeft64(Fv3, 12) + TBits.RotateLeft64(Fv4, 18);

    Fv1 := TBits.RotateLeft64(Fv1 * PRIME64_2, 31) * PRIME64_1;
    Fm_hash := (Fm_hash xor Fv1) * PRIME64_1 + PRIME64_4;

    Fv2 := TBits.RotateLeft64(Fv2 * PRIME64_2, 31) * PRIME64_1;
    Fm_hash := (Fm_hash xor Fv2) * PRIME64_1 + PRIME64_4;

    Fv3 := TBits.RotateLeft64(Fv3 * PRIME64_2, 31) * PRIME64_1;
    Fm_hash := (Fm_hash xor Fv3) * PRIME64_1 + PRIME64_4;

    Fv4 := TBits.RotateLeft64(Fv4 * PRIME64_2, 31) * PRIME64_1;
    Fm_hash := (Fm_hash xor Fv4) * PRIME64_1 + PRIME64_4;
  end
  else
    Fm_hash := Fm_key + PRIME64_5;

  System.Inc(Fm_hash, F_state.total_len);

  FptrBuffer := F_state.memory;
  FptrEnd := {%H-}Pointer({%H-}NativeUInt({%H-}FptrBuffer) + F_state.memsize);

  while ({%H-}NativeUInt({%H-}FptrBuffer) + 8) <= {%H-}NativeUInt({%H-}FptrEnd) do
  begin
    Fm_hash := Fm_hash xor (PRIME64_1 * TBits.RotateLeft64(PRIME64_2 *
      PUInt64(FptrBuffer)^, 31));
    Fm_hash := TBits.RotateLeft64(Fm_hash, 27) * PRIME64_1 + PRIME64_4;
    System.Inc({%H-}NativeUInt({%H-}FptrBuffer), 8);
  end;

  if ({%H-}NativeUInt({%H-}FptrBuffer) + 4) <= {%H-}NativeUInt({%H-}FptrEnd) then
  begin
    Fm_hash := Fm_hash xor PCardinal(FptrBuffer)^ * PRIME64_1;
    Fm_hash := TBits.RotateLeft64(Fm_hash, 23) * PRIME64_2 + PRIME64_3;
    System.Inc({%H-}NativeUInt({%H-}FptrBuffer), 4);
  end;

  while {%H-}NativeUInt({%H-}FptrBuffer) < {%H-}NativeUInt({%H-}FptrEnd) do
  begin
    Fm_hash := Fm_hash xor (PByte(FptrBuffer)^ * PRIME64_5);
    Fm_hash := TBits.RotateLeft64(Fm_hash, 11) * PRIME64_1;
    System.Inc({%H-}NativeUInt(FptrBuffer));
  end;

  Fm_hash := Fm_hash xor (Fm_hash shr 33);
  Fm_hash := Fm_hash * PRIME64_2;
  Fm_hash := Fm_hash xor (Fm_hash shr 29);
  Fm_hash := Fm_hash * PRIME64_3;
  Fm_hash := Fm_hash xor (Fm_hash shr 32);

  result := THashResult.Create(Fm_hash);
  Initialize();

end;

end.
