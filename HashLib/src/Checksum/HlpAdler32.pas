unit HlpAdler32;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpHashLibTypes,
  HlpIHashInfo,
  HlpHash,
  HlpIHash,
  HlpHashResult,
  HlpIHashResult;

type
  TAdler32 = class sealed(THash, IChecksum, IHash32, ITransformBlock)

  strict private
  var
    FA, FB: UInt32;

  const
    MOD_ADLER = UInt32(65521);

  public
    constructor Create();
    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal: IHashResult; override;
    function Clone(): IHash; override;

  end;

implementation

{ TAdler32 }

function TAdler32.Clone(): IHash;
var
  LHashInstance: TAdler32;
begin
  LHashInstance := TAdler32.Create();
  LHashInstance.FA := FA;
  LHashInstance.FB := FB;
  result := LHashInstance as IHash;
  result.BufferSize := BufferSize;
end;

constructor TAdler32.Create;
begin
  Inherited Create(4, 1);
end;

procedure TAdler32.Initialize;
begin
  FA := 1;
  FB := 0;
end;

procedure TAdler32.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
var
  i, n: Int32;

begin
{$IFDEF DEBUG}
  System.Assert(AIndex >= 0);
  System.Assert(ALength >= 0);
  System.Assert(AIndex + ALength <= System.Length(AData));
{$ENDIF DEBUG}
  i := AIndex;

  { while ALength > 0 do
    begin
    FA := (FA + AData[i]) mod MOD_ADLER;
    FB := (FB + FA) mod MOD_ADLER;
    System.Inc(i);
    System.Dec(ALength);
    end; }

  // lifted from PngEncoder Adler32.cs

  while ALength > 0 do
  begin
    // We can defer the modulo operation:
    // FA maximally grows from 65521 to 65521 + 255 * 3800
    // FB maximally grows by3800 * median(FA) = 2090079800 < 2^31
    n := 3800;
    if (n > ALength) then
    begin
      n := ALength;
    end;
    ALength := ALength - n;

    while (n - 1) >= 0 do
    begin
      FA := (FA + AData[i]);
      FB := (FB + FA);
      System.Inc(i);
      System.Dec(n);
    end;
    FA := FA mod MOD_ADLER;
    FB := FB mod MOD_ADLER;

  end;

end;

function TAdler32.TransformFinal: IHashResult;
begin
  result := THashResult.Create(UInt32((FB shl 16) or FA));
  Initialize();
end;

end.
