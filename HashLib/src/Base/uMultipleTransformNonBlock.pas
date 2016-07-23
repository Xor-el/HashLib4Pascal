unit uMultipleTransformNonBlock;

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
  System.Generics.Collections,
{$ELSE}
{$IFDEF FPC}
  fgl,
{$ENDIF FPC}
{$IFDEF DELPHI}
  Generics.Collections,
{$ENDIF DELPHI}
{$ENDIF HAS_UNITSCOPE}
  uHashLibTypes,
  uHash,
  uIHashInfo,
  uIHashResult,
  uArrayExtensions;

type

  TMultipleTransformNonBlock = class abstract(THash, INonBlockHash)

  strict private

    Fm_list: {$IFDEF DELPHI} TList<THashLibByteArray>
{$ELSE} TFPGList<THashLibByteArray> {$ENDIF};

    function Aggregate(): THashLibByteArray;

  strict protected
    function ComputeAggregatedBytes(a_data: THashLibByteArray): IHashResult;
      virtual; abstract;

  public
    constructor Create(a_hash_size, a_block_size: Int32);
    destructor Destroy; override;
    procedure Initialize(); override;
    procedure TransformBytes(a_data: THashLibByteArray;
      a_index, a_length: Int32); override;
    function TransformFinal(): IHashResult; override;
    function ComputeBytes(a_data: THashLibByteArray): IHashResult; override;

  end;

implementation

{ TMultipleTransformNonBlock }

function TMultipleTransformNonBlock.Aggregate: THashLibByteArray;
var
  sum, index: Int32;
  arr: THashLibByteArray;
begin
  sum := 0;
  for arr in Fm_list do
  begin
    sum := sum + System.Length(arr);
  end;

  System.SetLength(result, sum);
  index := 0;

  for arr in Fm_list do

  begin
    THashLibArrayHelper<Byte>.Copy(THashLibGenericArray<Byte>(arr), 0,
      THashLibGenericArray<Byte>(result), index, System.Length(arr));
    index := index + System.Length(arr);
  end;

end;

constructor TMultipleTransformNonBlock.Create(a_hash_size, a_block_size: Int32);
begin
  Inherited Create(a_hash_size, a_block_size);
  Fm_list := {$IFDEF DELPHI} TList<THashLibByteArray>
{$ELSE} TFPGList<THashLibByteArray> {$ENDIF}.Create();
end;

destructor TMultipleTransformNonBlock.Destroy;
begin
  Fm_list.Free;
  inherited Destroy;
end;

procedure TMultipleTransformNonBlock.Initialize;
begin
  Fm_list.Clear;
end;

procedure TMultipleTransformNonBlock.TransformBytes(a_data: THashLibByteArray;
  a_index, a_length: Int32);

begin
{$IFDEF DEBUG}
  System.Assert(a_index >= 0);
  System.Assert(a_length >= 0);
  System.Assert(a_index + a_length <= System.Length(a_data));
{$ENDIF}
  Fm_list.Add(System.Copy(a_data, a_index, a_length));

end;

function TMultipleTransformNonBlock.TransformFinal: IHashResult;
begin
  result := ComputeAggregatedBytes(Aggregate());
  Initialize();
end;

function TMultipleTransformNonBlock.ComputeBytes(a_data: THashLibByteArray)
  : IHashResult;
begin
  Initialize();
  result := ComputeAggregatedBytes(a_data);
end;

end.
