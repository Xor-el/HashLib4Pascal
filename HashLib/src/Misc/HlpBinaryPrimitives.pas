unit HlpBinaryPrimitives;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpBitOperations,
  SysUtils,
  HlpHashLibTypes;

type
  TBinaryPrimitives = class
  private
    class procedure CheckBounds(const AData: THashLibByteArray; AOffset, ANeeded: Integer); static; inline;

    // Wire LE/BE value to native integer
    class function LeToNativeUInt16(AValue: UInt16): UInt16; static; inline;
    class function LeToNativeUInt32(AValue: UInt32): UInt32; static; inline;
    class function LeToNativeUInt64(AValue: UInt64): UInt64; static; inline;
    class function BeToNativeUInt16(AValue: UInt16): UInt16; static; inline;
    class function BeToNativeUInt32(AValue: UInt32): UInt32; static; inline;
    class function BeToNativeUInt64(AValue: UInt64): UInt64; static; inline;

    // Copy with byte-reversal within each 32/64-bit lane
    class procedure SwapCopyUInt32(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static;
    class procedure SwapCopyUInt64(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static;

    // Semantic LE/BE read/write at PByte+Offset
    class function ReadUInt16LEAt(AInput: PByte; AOffset: Integer): UInt16; static; inline;
    class function ReadUInt16BEAt(AInput: PByte; AOffset: Integer): UInt16; static; inline;
    class function ReadUInt32LEAt(AInput: PByte; AOffset: Integer): UInt32; static; inline;
    class function ReadUInt32BEAt(AInput: PByte; AOffset: Integer): UInt32; static; inline;
    class function ReadUInt64LEAt(AInput: PByte; AOffset: Integer): UInt64; static; inline;
    class function ReadUInt64BEAt(AInput: PByte; AOffset: Integer): UInt64; static; inline;

    class procedure WriteUInt16LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt16); static; inline;
    class procedure WriteUInt16BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt16); static; inline;
    class procedure WriteUInt32LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt32); static; inline;
    class procedure WriteUInt32BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt32); static; inline;
    class procedure WriteUInt64LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt64); static; inline;
    class procedure WriteUInt64BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt64); static; inline;

  public
    /// <summary>Alignment-safe native-order word load (not a wire-endian read).</summary>
    class function LoadUInt16(AInput: PWord): UInt16; static; inline;
    /// <summary>Alignment-safe native-order dword load (not a wire-endian read).</summary>
    class function LoadUInt32(AInput: PCardinal): UInt32; static; inline;
    /// <summary>Alignment-safe native-order qword load (not a wire-endian read).</summary>
    class function LoadUInt64(AInput: PUInt64): UInt64; static; inline;
    /// <summary>Alignment-safe native-order word store (not a wire-endian write).</summary>
    class procedure StoreUInt16(AOutput: PWord; AValue: UInt16); static; inline;
    /// <summary>Alignment-safe native-order dword store (not a wire-endian write).</summary>
    class procedure StoreUInt32(AOutput: PCardinal; AValue: UInt32); static; inline;
    /// <summary>Alignment-safe native-order qword store (not a wire-endian write).</summary>
    class procedure StoreUInt64(AOutput: PUInt64; AValue: UInt64); static; inline;

    // Copy block; preserve LE or BE wire layout
    class procedure CopyUInt32LittleEndian(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static; inline;
    class procedure CopyUInt32BigEndian(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static; inline;
    class procedure CopyUInt64LittleEndian(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static; inline;
    class procedure CopyUInt64BigEndian(ASource: Pointer; ASourceIndex: Integer;
      ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer); static; inline;

    class procedure WriteUInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt16); overload; static; inline;
    class procedure WriteUInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt32); overload; static; inline;
    class procedure WriteUInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt64); overload; static; inline;

    class procedure WriteInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int16); static; inline;
    class procedure WriteInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int32); static; inline;
    class procedure WriteInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int64); static; inline;

    class procedure WriteSingleLittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Single); static; inline;
    class procedure WriteDoubleLittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Double); static; inline;

    class procedure WriteUInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt16); overload; static; inline;
    class procedure WriteUInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt32); overload; static; inline;
    class procedure WriteUInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt64); overload; static; inline;

    class procedure WriteInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int16); static; inline;
    class procedure WriteInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int32); static; inline;
    class procedure WriteInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int64); static; inline;

    class procedure WriteSingleBigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Single); static; inline;
    class procedure WriteDoubleBigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Double); static; inline;

    class function ReadUInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt16; overload; static; inline;
    class function ReadUInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt32; overload; static; inline;
    class function ReadUInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt64; overload; static; inline;

    class function ReadInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int16; static; inline;
    class function ReadInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int32; static; inline;
    class function ReadInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int64; static; inline;

    class function ReadSingleLittleEndian(const AData: THashLibByteArray; AOffset: Integer): Single; static; inline;
    class function ReadDoubleLittleEndian(const AData: THashLibByteArray; AOffset: Integer): Double; static; inline;

    class function ReadUInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt16; overload; static; inline;
    class function ReadUInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt32; overload; static; inline;
    class function ReadUInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt64; overload; static; inline;

    class function ReadInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int16; static; inline;
    class function ReadInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int32; static; inline;
    class function ReadInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int64; static; inline;

    class function ReadSingleBigEndian(const AData: THashLibByteArray; AOffset: Integer): Single; static; inline;
    class function ReadDoubleBigEndian(const AData: THashLibByteArray; AOffset: Integer): Double; static; inline;

    // PByte+Offset overloads
    class procedure WriteUInt16LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt16); overload; static; inline;
    class procedure WriteUInt32LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt32); overload; static; inline;
    class procedure WriteUInt64LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt64); overload; static; inline;

    class procedure WriteUInt16BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt16); overload; static; inline;
    class procedure WriteUInt32BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt32); overload; static; inline;
    class procedure WriteUInt64BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt64); overload; static; inline;

    class function ReadUInt16LittleEndian(AInput: PByte; AOffset: Integer): UInt16; overload; static; inline;
    class function ReadUInt32LittleEndian(AInput: PByte; AOffset: Integer): UInt32; overload; static; inline;
    class function ReadUInt64LittleEndian(AInput: PByte; AOffset: Integer): UInt64; overload; static; inline;

    class function ReadUInt16BigEndian(AInput: PByte; AOffset: Integer): UInt16; overload; static; inline;
    class function ReadUInt32BigEndian(AInput: PByte; AOffset: Integer): UInt32; overload; static; inline;
    class function ReadUInt64BigEndian(AInput: PByte; AOffset: Integer): UInt64; overload; static; inline;
  end;

implementation

{ TBinaryPrimitives }

class procedure TBinaryPrimitives.CheckBounds(const AData: THashLibByteArray; AOffset, ANeeded: Integer);
begin
  if (AOffset < 0) or (AOffset + ANeeded > Length(AData)) then
    raise EArgumentOutOfRangeException.Create('AOffset');
end;

// ============================================================================
// Host-endian conversion
// ============================================================================

class function TBinaryPrimitives.LeToNativeUInt16(AValue: UInt16): UInt16;
begin
{$IFDEF FPC}
  Result := LEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := AValue;
  {$ELSE}
  Result := TBitOperations.ReverseBytesUInt16(AValue);
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

class function TBinaryPrimitives.LeToNativeUInt32(AValue: UInt32): UInt32;
begin
{$IFDEF FPC}
  Result := LEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := AValue;
  {$ELSE}
  Result := TBitOperations.ReverseBytesUInt32(AValue);
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

class function TBinaryPrimitives.LeToNativeUInt64(AValue: UInt64): UInt64;
begin
{$IFDEF FPC}
  Result := LEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := AValue;
  {$ELSE}
  Result := TBitOperations.ReverseBytesUInt64(AValue);
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

class function TBinaryPrimitives.BeToNativeUInt16(AValue: UInt16): UInt16;
begin
{$IFDEF FPC}
  Result := BEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := TBitOperations.ReverseBytesUInt16(AValue);
  {$ELSE}
  Result := AValue;
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

class function TBinaryPrimitives.BeToNativeUInt32(AValue: UInt32): UInt32;
begin
{$IFDEF FPC}
  Result := BEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := TBitOperations.ReverseBytesUInt32(AValue);
  {$ELSE}
  Result := AValue;
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

class function TBinaryPrimitives.BeToNativeUInt64(AValue: UInt64): UInt64;
begin
{$IFDEF FPC}
  Result := BEtoN(AValue);
{$ELSE}
  {$IFDEF HASHLIB_LITTLE_ENDIAN}
  Result := TBitOperations.ReverseBytesUInt64(AValue);
  {$ELSE}
  Result := AValue;
  {$ENDIF HASHLIB_LITTLE_ENDIAN}
{$ENDIF FPC}
end;

// ============================================================================
// Raw memory load/store
// ============================================================================

class function TBinaryPrimitives.LoadUInt16(AInput: PWord): UInt16;
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AInput^, Result, SizeOf(UInt16));
{$ELSE}
  Result := AInput^;
{$ENDIF}
end;

class function TBinaryPrimitives.LoadUInt32(AInput: PCardinal): UInt32;
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AInput^, Result, SizeOf(UInt32));
{$ELSE}
  Result := AInput^;
{$ENDIF}
end;

class function TBinaryPrimitives.LoadUInt64(AInput: PUInt64): UInt64;
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AInput^, Result, SizeOf(UInt64));
{$ELSE}
  Result := AInput^;
{$ENDIF}
end;

class procedure TBinaryPrimitives.StoreUInt16(AOutput: PWord; AValue: UInt16);
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AValue, AOutput^, SizeOf(UInt16));
{$ELSE}
  AOutput^ := AValue;
{$ENDIF}
end;

class procedure TBinaryPrimitives.StoreUInt32(AOutput: PCardinal; AValue: UInt32);
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AValue, AOutput^, SizeOf(UInt32));
{$ELSE}
  AOutput^ := AValue;
{$ENDIF}
end;

class procedure TBinaryPrimitives.StoreUInt64(AOutput: PUInt64; AValue: UInt64);
begin
{$IFDEF HASHLIB_REQUIRES_PROPER_ALIGNMENT}
  Move(AValue, AOutput^, SizeOf(UInt64));
{$ELSE}
  AOutput^ := AValue;
{$ENDIF}
end;

// ============================================================================
// Bulk copy
// ============================================================================

class procedure TBinaryPrimitives.SwapCopyUInt32(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
var
  LSrcWord, LDestWord, LSrcWordEnd: PCardinal;
  LSrcByte, LDestByte: PByte;
  LByteIdx: Integer;
begin
  if ((NativeUInt(PByte(ADestination)) or NativeUInt(PByte(ASource)) or
    NativeUInt(ASourceIndex) or NativeUInt(ADestinationIndex) or NativeUInt(ASize)) and 3) = 0 then
  begin
    LSrcWord := PCardinal(PByte(ASource) + ASourceIndex);
    LSrcWordEnd := PCardinal(PByte(ASource) + ASourceIndex + ASize);
    LDestWord := PCardinal(PByte(ADestination) + ADestinationIndex);
    while LSrcWord < LSrcWordEnd do
    begin
      LDestWord^ := TBitOperations.ReverseBytesUInt32(LSrcWord^);
      Inc(LDestWord);
      Inc(LSrcWord);
    end;
  end
  else
  begin
    LSrcByte := PByte(ASource) + ASourceIndex;
    LDestByte := PByte(ADestination) + ADestinationIndex;
    LByteIdx := 0;
    while LByteIdx < ASize do
    begin
      LDestByte[LByteIdx] := LSrcByte[LByteIdx xor 3];
      Inc(LByteIdx);
    end;
  end;
end;

class procedure TBinaryPrimitives.SwapCopyUInt64(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
var
  LSrcWord, LDestWord, LSrcWordEnd: PUInt64;
  LSrcByte, LDestByte: PByte;
  LByteIdx: Integer;
begin
  if ((NativeUInt(PByte(ADestination)) or NativeUInt(PByte(ASource)) or
    NativeUInt(ASourceIndex) or NativeUInt(ADestinationIndex) or NativeUInt(ASize)) and 7) = 0 then
  begin
    LSrcWord := PUInt64(PByte(ASource) + ASourceIndex);
    LSrcWordEnd := PUInt64(PByte(ASource) + ASourceIndex + ASize);
    LDestWord := PUInt64(PByte(ADestination) + ADestinationIndex);
    while LSrcWord < LSrcWordEnd do
    begin
      LDestWord^ := TBitOperations.ReverseBytesUInt64(LSrcWord^);
      Inc(LDestWord);
      Inc(LSrcWord);
    end;
  end
  else
  begin
    LSrcByte := PByte(ASource) + ASourceIndex;
    LDestByte := PByte(ADestination) + ADestinationIndex;
    LByteIdx := 0;
    while LByteIdx < ASize do
    begin
      LDestByte[LByteIdx] := LSrcByte[LByteIdx xor 7];
      Inc(LByteIdx);
    end;
  end;
end;

class procedure TBinaryPrimitives.CopyUInt32LittleEndian(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  Move(Pointer(PByte(ASource) + ASourceIndex)^,
    Pointer(PByte(ADestination) + ADestinationIndex)^, ASize);
{$ELSE}
  SwapCopyUInt32(ASource, ASourceIndex, ADestination, ADestinationIndex, ASize);
{$ENDIF}
end;

class procedure TBinaryPrimitives.CopyUInt32BigEndian(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  SwapCopyUInt32(ASource, ASourceIndex, ADestination, ADestinationIndex, ASize);
{$ELSE}
  Move(Pointer(PByte(ASource) + ASourceIndex)^,
    Pointer(PByte(ADestination) + ADestinationIndex)^, ASize);
{$ENDIF}
end;

class procedure TBinaryPrimitives.CopyUInt64LittleEndian(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  Move(Pointer(PByte(ASource) + ASourceIndex)^,
    Pointer(PByte(ADestination) + ADestinationIndex)^, ASize);
{$ELSE}
  SwapCopyUInt64(ASource, ASourceIndex, ADestination, ADestinationIndex, ASize);
{$ENDIF}
end;

class procedure TBinaryPrimitives.CopyUInt64BigEndian(ASource: Pointer; ASourceIndex: Integer;
  ADestination: Pointer; ADestinationIndex: Integer; ASize: Integer);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  SwapCopyUInt64(ASource, ASourceIndex, ADestination, ADestinationIndex, ASize);
{$ELSE}
  Move(Pointer(PByte(ASource) + ASourceIndex)^,
    Pointer(PByte(ADestination) + ADestinationIndex)^, ASize);
{$ENDIF}
end;

// ============================================================================
// Pointer read/write cores
// ============================================================================

class function TBinaryPrimitives.ReadUInt16LEAt(AInput: PByte; AOffset: Integer): UInt16;
begin
  Result := LeToNativeUInt16(LoadUInt16(PWord(AInput + AOffset)));
end;

class function TBinaryPrimitives.ReadUInt16BEAt(AInput: PByte; AOffset: Integer): UInt16;
begin
  Result := BeToNativeUInt16(LoadUInt16(PWord(AInput + AOffset)));
end;

class function TBinaryPrimitives.ReadUInt32LEAt(AInput: PByte; AOffset: Integer): UInt32;
begin
  Result := LeToNativeUInt32(LoadUInt32(PCardinal(AInput + AOffset)));
end;

class function TBinaryPrimitives.ReadUInt32BEAt(AInput: PByte; AOffset: Integer): UInt32;
begin
  Result := BeToNativeUInt32(LoadUInt32(PCardinal(AInput + AOffset)));
end;

class function TBinaryPrimitives.ReadUInt64LEAt(AInput: PByte; AOffset: Integer): UInt64;
begin
  Result := LeToNativeUInt64(LoadUInt64(PUInt64(AInput + AOffset)));
end;

class function TBinaryPrimitives.ReadUInt64BEAt(AInput: PByte; AOffset: Integer): UInt64;
begin
  Result := BeToNativeUInt64(LoadUInt64(PUInt64(AInput + AOffset)));
end;

class procedure TBinaryPrimitives.WriteUInt16LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt16);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  StoreUInt16(PWord(AOutput + AOffset), AValue);
{$ELSE}
  AOutput[AOffset]     := Byte(AValue);
  AOutput[AOffset + 1] := Byte(AValue shr 8);
{$ENDIF}
end;

class procedure TBinaryPrimitives.WriteUInt16BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt16);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  AOutput[AOffset]     := Byte(AValue shr 8);
  AOutput[AOffset + 1] := Byte(AValue);
{$ELSE}
  StoreUInt16(PWord(AOutput + AOffset), AValue);
{$ENDIF}
end;

class procedure TBinaryPrimitives.WriteUInt32LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt32);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  StoreUInt32(PCardinal(AOutput + AOffset), AValue);
{$ELSE}
  AOutput[AOffset]     := Byte(AValue);
  AOutput[AOffset + 1] := Byte(AValue shr 8);
  AOutput[AOffset + 2] := Byte(AValue shr 16);
  AOutput[AOffset + 3] := Byte(AValue shr 24);
{$ENDIF}
end;

class procedure TBinaryPrimitives.WriteUInt32BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt32);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  AOutput[AOffset]     := Byte(AValue shr 24);
  AOutput[AOffset + 1] := Byte(AValue shr 16);
  AOutput[AOffset + 2] := Byte(AValue shr 8);
  AOutput[AOffset + 3] := Byte(AValue);
{$ELSE}
  StoreUInt32(PCardinal(AOutput + AOffset), AValue);
{$ENDIF}
end;

class procedure TBinaryPrimitives.WriteUInt64LEAt(AOutput: PByte; AOffset: Integer; AValue: UInt64);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  StoreUInt64(PUInt64(AOutput + AOffset), AValue);
{$ELSE}
  AOutput[AOffset]     := Byte(AValue);
  AOutput[AOffset + 1] := Byte(AValue shr 8);
  AOutput[AOffset + 2] := Byte(AValue shr 16);
  AOutput[AOffset + 3] := Byte(AValue shr 24);
  AOutput[AOffset + 4] := Byte(AValue shr 32);
  AOutput[AOffset + 5] := Byte(AValue shr 40);
  AOutput[AOffset + 6] := Byte(AValue shr 48);
  AOutput[AOffset + 7] := Byte(AValue shr 56);
{$ENDIF}
end;

class procedure TBinaryPrimitives.WriteUInt64BEAt(AOutput: PByte; AOffset: Integer; AValue: UInt64);
begin
{$IFDEF HASHLIB_LITTLE_ENDIAN}
  AOutput[AOffset]     := Byte(AValue shr 56);
  AOutput[AOffset + 1] := Byte(AValue shr 48);
  AOutput[AOffset + 2] := Byte(AValue shr 40);
  AOutput[AOffset + 3] := Byte(AValue shr 32);
  AOutput[AOffset + 4] := Byte(AValue shr 24);
  AOutput[AOffset + 5] := Byte(AValue shr 16);
  AOutput[AOffset + 6] := Byte(AValue shr 8);
  AOutput[AOffset + 7] := Byte(AValue);
{$ELSE}
  StoreUInt64(PUInt64(AOutput + AOffset), AValue);
{$ENDIF}
end;

// ============================================================================
// Public pointer read/write overloads
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt16);
begin
  WriteUInt16LEAt(AOutput, AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt32LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt32);
begin
  WriteUInt32LEAt(AOutput, AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt64LittleEndian(AOutput: PByte; AOffset: Integer; AValue: UInt64);
begin
  WriteUInt64LEAt(AOutput, AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt16BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt16);
begin
  WriteUInt16BEAt(AOutput, AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt32BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt32);
begin
  WriteUInt32BEAt(AOutput, AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt64BigEndian(AOutput: PByte; AOffset: Integer; AValue: UInt64);
begin
  WriteUInt64BEAt(AOutput, AOffset, AValue);
end;

class function TBinaryPrimitives.ReadUInt16LittleEndian(AInput: PByte; AOffset: Integer): UInt16;
begin
  Result := ReadUInt16LEAt(AInput, AOffset);
end;

class function TBinaryPrimitives.ReadUInt32LittleEndian(AInput: PByte; AOffset: Integer): UInt32;
begin
  Result := ReadUInt32LEAt(AInput, AOffset);
end;

class function TBinaryPrimitives.ReadUInt64LittleEndian(AInput: PByte; AOffset: Integer): UInt64;
begin
  Result := ReadUInt64LEAt(AInput, AOffset);
end;

class function TBinaryPrimitives.ReadUInt16BigEndian(AInput: PByte; AOffset: Integer): UInt16;
begin
  Result := ReadUInt16BEAt(AInput, AOffset);
end;

class function TBinaryPrimitives.ReadUInt32BigEndian(AInput: PByte; AOffset: Integer): UInt32;
begin
  Result := ReadUInt32BEAt(AInput, AOffset);
end;

class function TBinaryPrimitives.ReadUInt64BigEndian(AInput: PByte; AOffset: Integer): UInt64;
begin
  Result := ReadUInt64BEAt(AInput, AOffset);
end;

// ============================================================================
// Public Write Methods - Little Endian (TArray)
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt16);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  WriteUInt16LEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt32);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  WriteUInt32LEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt64);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  WriteUInt64LEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int16);
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  WriteUInt16LEAt(PByte(AData), AOffset, UInt16(AValue));
end;

class procedure TBinaryPrimitives.WriteInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int32);
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  WriteUInt32LEAt(PByte(AData), AOffset, UInt32(AValue));
end;

class procedure TBinaryPrimitives.WriteInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int64);
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  WriteUInt64LEAt(PByte(AData), AOffset, UInt64(AValue));
end;

class procedure TBinaryPrimitives.WriteSingleLittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Single);
var
  LBits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  Move(AValue, LBits, SizeOf(Single));
  WriteUInt32LEAt(PByte(AData), AOffset, LBits);
end;

class procedure TBinaryPrimitives.WriteDoubleLittleEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Double);
var
  LBits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  Move(AValue, LBits, SizeOf(Double));
  WriteUInt64LEAt(PByte(AData), AOffset, LBits);
end;

// ============================================================================
// Public Write Methods - Big Endian (TArray)
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt16);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  WriteUInt16BEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt32);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  WriteUInt32BEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteUInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: UInt64);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  WriteUInt64BEAt(PByte(AData), AOffset, AValue);
end;

class procedure TBinaryPrimitives.WriteInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int16);
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  WriteUInt16BEAt(PByte(AData), AOffset, UInt16(AValue));
end;

class procedure TBinaryPrimitives.WriteInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int32);
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  WriteUInt32BEAt(PByte(AData), AOffset, UInt32(AValue));
end;

class procedure TBinaryPrimitives.WriteInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Int64);
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  WriteUInt64BEAt(PByte(AData), AOffset, UInt64(AValue));
end;

class procedure TBinaryPrimitives.WriteSingleBigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Single);
var
  LBits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  Move(AValue, LBits, SizeOf(Single));
  WriteUInt32BEAt(PByte(AData), AOffset, LBits);
end;

class procedure TBinaryPrimitives.WriteDoubleBigEndian(const AData: THashLibByteArray; AOffset: Integer; AValue: Double);
var
  LBits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  Move(AValue, LBits, SizeOf(Double));
  WriteUInt64BEAt(PByte(AData), AOffset, LBits);
end;

// ============================================================================
// Public Read Methods - Little Endian (TArray)
// ============================================================================

class function TBinaryPrimitives.ReadUInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt16;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  Result := ReadUInt16LEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadUInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  Result := ReadUInt32LEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadUInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer): UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  Result := ReadUInt64LEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadInt16LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int16;
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  Result := Int16(ReadUInt16LEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadInt32LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int32;
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  Result := Int32(ReadUInt32LEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadInt64LittleEndian(const AData: THashLibByteArray; AOffset: Integer): Int64;
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  Result := Int64(ReadUInt64LEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadSingleLittleEndian(const AData: THashLibByteArray; AOffset: Integer): Single;
var
  LBits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  LBits := ReadUInt32LEAt(PByte(AData), AOffset);
  Move(LBits, Result, SizeOf(Single));
end;

class function TBinaryPrimitives.ReadDoubleLittleEndian(const AData: THashLibByteArray; AOffset: Integer): Double;
var
  LBits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  LBits := ReadUInt64LEAt(PByte(AData), AOffset);
  Move(LBits, Result, SizeOf(Double));
end;

// ============================================================================
// Public Read Methods - Big Endian (TArray)
// ============================================================================

class function TBinaryPrimitives.ReadUInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt16;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  Result := ReadUInt16BEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadUInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  Result := ReadUInt32BEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadUInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer): UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  Result := ReadUInt64BEAt(PByte(AData), AOffset);
end;

class function TBinaryPrimitives.ReadInt16BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int16;
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  Result := Int16(ReadUInt16BEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadInt32BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int32;
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  Result := Int32(ReadUInt32BEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadInt64BigEndian(const AData: THashLibByteArray; AOffset: Integer): Int64;
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  Result := Int64(ReadUInt64BEAt(PByte(AData), AOffset));
end;

class function TBinaryPrimitives.ReadSingleBigEndian(const AData: THashLibByteArray; AOffset: Integer): Single;
var
  LBits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  LBits := ReadUInt32BEAt(PByte(AData), AOffset);
  Move(LBits, Result, SizeOf(Single));
end;

class function TBinaryPrimitives.ReadDoubleBigEndian(const AData: THashLibByteArray; AOffset: Integer): Double;
var
  LBits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  LBits := ReadUInt64BEAt(PByte(AData), AOffset);
  Move(LBits, Result, SizeOf(Double));
end;

end.
