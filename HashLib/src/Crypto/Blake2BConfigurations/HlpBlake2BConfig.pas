unit HlpBlake2BConfig;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpIBlake2BConfig,
  HlpHashLibTypes;

type

  TBlake2BConfig = class sealed(TInterfacedObject, IBlake2BConfig)

  strict private

  var

    FHashSize: Int32;
    FPersonalisation, FSalt, FKey: THashLibByteArray;

    function GetPersonalisation: THashLibByteArray; inline;
    procedure SetPersonalisation(value: THashLibByteArray); inline;

    function GetSalt: THashLibByteArray; inline;
    procedure SetSalt(value: THashLibByteArray); inline;

    function GetKey: THashLibByteArray; inline;
    procedure SetKey(value: THashLibByteArray); inline;

    function GetHashSize: Int32; inline;
    procedure SetHashSize(value: Int32); inline;

  public
    constructor Create();
    property Personalisation: THashLibByteArray read GetPersonalisation
      write SetPersonalisation;
    property Salt: THashLibByteArray read GetSalt write SetSalt;
    property Key: THashLibByteArray read GetKey write SetKey;
    property HashSize: Int32 read GetHashSize write SetHashSize;

  end;

implementation

{ TBlake2BConfig }

constructor TBlake2BConfig.Create();
begin
  HashSize := 64;
end;

function TBlake2BConfig.GetHashSize: Int32;
begin
  result := FHashSize;
end;

function TBlake2BConfig.GetKey: THashLibByteArray;
begin
  result := FKey;
end;

function TBlake2BConfig.GetPersonalisation: THashLibByteArray;
begin
  result := FPersonalisation;
end;

function TBlake2BConfig.GetSalt: THashLibByteArray;
begin
  result := FSalt;
end;

procedure TBlake2BConfig.SetHashSize(value: Int32);
begin
  FHashSize := value;
end;

procedure TBlake2BConfig.SetKey(value: THashLibByteArray);
begin
  FKey := value;
end;

procedure TBlake2BConfig.SetPersonalisation(value: THashLibByteArray);
begin
  FPersonalisation := value;
end;

procedure TBlake2BConfig.SetSalt(value: THashLibByteArray);
begin
  FSalt := value;
end;

end.
