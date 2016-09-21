unit HlpHash;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFNDEF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.TypInfo,
{$ELSE}
  TypInfo,
{$ENDIF HAS_UNITSCOPE}
{$ENDIF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.Classes,
  System.SysUtils,
{$ELSE}
  Classes,
  SysUtils,
{$ENDIF HAS_UNITSCOPE}
  HlpHashLibTypes,
  HlpArrayExtensions,
  HlpConverters,
  HlpIHash,
  HlpIHashResult;

resourcestring
  SIndexOutOfRange = 'Current Index Is Out Of Range';
  SEndOfStream = 'Cannot Access Outside Stream Boundaries';

type
  THash = class abstract(TInterfacedObject, IHash)

  strict private

    Fm_buffer_size, Fm_block_size, Fm_hash_size: Int32;

  const
    BUFFER_SIZE = Int32(64 * 1024); // 64Kb

    function GetBlockSize: Int32; virtual;
    function GetHashSize: Int32; virtual;

    function GetBufferSize: Int32;
    procedure SetBufferSize(value: Int32);

  strict protected

    function GetName: String; virtual;

  public

    constructor Create(a_hash_size, a_block_size: Int32);
    property Name: String read GetName;
    property BlockSize: Int32 read GetBlockSize;
    property HashSize: Int32 read GetHashSize;
    function ComputeString(const a_data: String; a_encoding: TEncoding)
      : IHashResult; virtual;
    function ComputeBytes(a_data: THashLibByteArray): IHashResult; virtual;
    function ComputeUntyped(const a_data; a_length: Int64): IHashResult;
    function ComputeStream(a_stream: TStream; a_length: Int64 = -1)
      : IHashResult;
    function ComputeFile(const a_file_name: String; a_from: Int64 = 0;
      a_length: Int64 = -1): IHashResult;
    procedure TransformString(const a_data: String; a_encoding: TEncoding);
    procedure TransformBytes(a_data: THashLibByteArray); overload;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index: Int32); overload;
    procedure TransformBytes(a_data: THashLibByteArray; a_index: Int32;
      a_length: Int32); overload; virtual; abstract;
    procedure TransformUntyped(const a_data; a_length: Int64);
    procedure TransformStream(a_stream: TStream; a_length: Int64 = -1);
    procedure TransformFile(const a_file_name: String; a_from: Int64 = 0;
      a_length: Int64 = -1);
    procedure Initialize(); virtual; abstract;
    function TransformFinal(): IHashResult; virtual; abstract;

    property BufferSize: Int32 read GetBufferSize write SetBufferSize;
  end;

implementation

{ THash }

constructor THash.Create(a_hash_size, a_block_size: Int32);
begin
{$IFDEF DEBUG}
  System.Assert((a_block_size > 0) or (a_block_size = -1));
  System.Assert(a_hash_size > 0);
{$ENDIF}
  Fm_block_size := a_block_size;
  Fm_hash_size := a_hash_size;
  Fm_buffer_size := BUFFER_SIZE;
end;

function THash.GetName: String;
begin
  result := Self.ClassName;
end;

function THash.GetBufferSize: Int32;
begin
  result := Fm_buffer_size;
end;

procedure THash.SetBufferSize(value: Int32);
begin
  Fm_buffer_size := value;
end;

function THash.GetBlockSize: Int32;
begin
  result := Fm_block_size;
end;

function THash.GetHashSize: Int32;
begin
  result := Fm_hash_size;
end;

function THash.ComputeString(const a_data: String; a_encoding: TEncoding)
  : IHashResult;
begin
  result := ComputeBytes(TConverters.ConvertStringToBytes(a_data, a_encoding));
end;

function THash.ComputeUntyped(const a_data; a_length: Int64): IHashResult;

begin

  Initialize();
  TransformUntyped(a_data, a_length);
  result := TransformFinal();

end;

procedure THash.TransformUntyped(const a_data; a_length: Int64);
var
  PtrBuffer, PtrEnd: PByte;
  ArrBuffer: THashLibByteArray;
begin
  PtrBuffer := @a_data;
  if PtrBuffer <> Nil then
  begin
    System.SetLength(ArrBuffer, BufferSize);
    PtrEnd := (PtrBuffer) + a_length;

    while PtrBuffer <= PtrEnd do
    begin

      if (PtrEnd - PtrBuffer) >= BufferSize then
      begin
        System.Move(PtrBuffer^, ArrBuffer[0], BufferSize);
        TransformBytes(ArrBuffer);

      end
      else
      begin
        System.SetLength(ArrBuffer, PtrEnd - PtrBuffer);
        System.Move(PtrBuffer^, ArrBuffer[0], System.Length(ArrBuffer));
        TransformBytes(ArrBuffer);
      end;
      System.Inc(PtrBuffer, BufferSize);
    end;

  end;
end;

function THash.ComputeStream(a_stream: TStream; a_length: Int64): IHashResult;
begin
  Initialize();
  TransformStream(a_stream, a_length);
  result := TransformFinal();

end;

function THash.ComputeFile(const a_file_name: String; a_from, a_length: Int64)
  : IHashResult;
begin
  Initialize();
  TransformFile(a_file_name, a_from, a_length);
  result := TransformFinal();

end;

function THash.ComputeBytes(a_data: THashLibByteArray): IHashResult;
begin
  Initialize();
  TransformBytes(a_data);
  result := TransformFinal();

end;

procedure THash.TransformString(const a_data: String; a_encoding: TEncoding);
begin
  TransformBytes(TConverters.ConvertStringToBytes(a_data, a_encoding));
end;

procedure THash.TransformBytes(a_data: THashLibByteArray);
begin
  TransformBytes(a_data, 0, System.Length(a_data));
end;

procedure THash.TransformBytes(a_data: THashLibByteArray; a_index: Int32);
var
  &Length: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
{$ENDIF}
  Length := System.Length(a_data) - a_index;

{$IFDEF DEBUG}
  System.Assert(Length >= 0);
{$ENDIF}
  TransformBytes(a_data, a_index, Length);
end;

procedure THash.TransformStream(a_stream: TStream; a_length: Int64);
var
  data: THashLibByteArray;
  total: Int64;
  readed: Int32;
begin
{$IFDEF DEBUG}
  System.Assert((a_length = -1) or (a_length > 0));
{$ENDIF}
  if (a_stream <> Nil) then
  begin
    if (a_length > -1) then
    begin

      if ((a_stream.Position + a_length) > a_stream.Size) then
        raise EIndexOutOfRangeException.CreateRes(@SIndexOutOfRange);
    end;

    if (a_stream.Position >= a_stream.Size) then
      Exit;
  end;

  total := 0;
  System.SetLength(data, BufferSize);
  while True do
  begin
    readed := a_stream.Read(data[0], System.Length(data));
    if ((a_length = -1) and (readed <> BufferSize)) then
      data := THashLibByteArray(THashLibArrayHelper<Byte>.SubArray
        (THashLibGenericArray<Byte>(data), 0, readed))

    else if ((a_length <> -1) and (total + readed >= a_length)) then
      data := THashLibByteArray(THashLibArrayHelper<Byte>.SubArray
        (THashLibGenericArray<Byte>(data), 0, Int32(a_length - total)));

    total := total + System.Length(data);

    TransformBytes(data, 0, System.Length(data));
    if (a_length = -1) then
    begin
      if (readed <> BufferSize) then
        break;
    end
    else if (a_length = total) then
      break
    else if (readed <> BufferSize) then
      raise EndOfStreamException.CreateRes(@SEndOfStream);
  end;

end;

procedure THash.TransformFile(const a_file_name: String;
  a_from, a_length: Int64);
var
  MyFileStream: TFileStream;
begin
{$IFDEF DEBUG}
  System.Assert(FileExists(a_file_name));
  System.Assert(a_from >= 0);
  System.Assert((a_length = -1) or (a_length > 0));
{$ENDIF}
  MyFileStream := TFileStream.Create(a_file_name, fmOpenRead or
    fmShareDenyWrite);

  try
    MyFileStream.Seek(a_from, TSeekOrigin.soBeginning);
    TransformStream(MyFileStream, a_length);
  finally
    MyFileStream.Free;
  end;
end;

end.
