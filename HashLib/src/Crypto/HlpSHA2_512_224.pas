unit HlpSHA2_512_224;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
{$IFNDEF DELPHIXE7_UP}
{$IFDEF HAS_UNITSCOPE}
  System.TypInfo,
{$ELSE}
  TypInfo,
{$ENDIF HAS_UNITSCOPE}
{$ENDIF DELPHIXE7_UP}
  HlpHashLibTypes,
  HlpSHA2_512Base,
  HlpConverters;

type
  TSHA2_512_224 = class sealed(TSHA2_512Base)

  strict protected
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA2_512_224 }

constructor TSHA2_512_224.Create;
begin
  Inherited Create(28);
end;

function TSHA2_512_224.GetResult: THashLibByteArray;
var
  tempResult: THashLibByteArray;
begin
  tempResult := TConverters.ConvertUInt64ToBytesSwapOrder(Fm_state);
  System.SetLength(result, HashSize);
  System.Move(tempResult[0], result[0], HashSize * System.SizeOf(Byte));
end;

procedure TSHA2_512_224.Initialize;
begin

  Fptr_Fm_state[0] := $8C3D37C819544DA2;
  Fptr_Fm_state[1] := $73E1996689DCD4D6;
  Fptr_Fm_state[2] := $1DFAB7AE32FF9C82;
  Fptr_Fm_state[3] := $679DD514582F9FCF;
  Fptr_Fm_state[4] := $0F6D2B697BD44DA8;
  Fptr_Fm_state[5] := $77E36F7304C48942;
  Fptr_Fm_state[6] := $3F9D85A86A1D36C8;
  Fptr_Fm_state[7] := $1112E6AD91D692A1;

  Inherited Initialize();

end;

end.
