unit HlpSHA2_256;

{$I ..\Include\HashLib.inc}

interface

uses
{$IFDEF DELPHI2010}
  SysUtils, // to get rid of compiler hint "not inlined" on Delphi 2010.
{$ENDIF DELPHI2010}
  HlpHashLibTypes,
{$IFDEF DELPHI}
  HlpBitConverter,
{$ENDIF DELPHI}
  HlpSHA2_256Base,
  HlpConverters;

type
  TSHA2_256 = class sealed(TSHA2_256Base)

  strict protected
    function GetResult(): THashLibByteArray; override;

  public
    constructor Create();
    procedure Initialize(); override;

  end;

implementation

{ TSHA2_256 }

constructor TSHA2_256.Create;
begin
  Inherited Create(32);
end;

function TSHA2_256.GetResult: THashLibByteArray;
begin

  System.SetLength(result, 8 * System.SizeOf(UInt32));
  TConverters.be32_copy(PCardinal(Fm_state), 0, PByte(result), 0,
    System.Length(result));

end;

procedure TSHA2_256.Initialize;
begin
  Fptr_Fm_state[0] := $6A09E667;
  Fptr_Fm_state[1] := $BB67AE85;
  Fptr_Fm_state[2] := $3C6EF372;
  Fptr_Fm_state[3] := $A54FF53A;
  Fptr_Fm_state[4] := $510E527F;
  Fptr_Fm_state[5] := $9B05688C;
  Fptr_Fm_state[6] := $1F83D9AB;
  Fptr_Fm_state[7] := $5BE0CD19;

  Inherited Initialize();

end;

end.
