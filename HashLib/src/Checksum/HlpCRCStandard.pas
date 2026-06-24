unit HlpCRCStandard;

{$I ..\Include\HashLib.inc}

{
  Width-specific CRC wrappers (TCRC16 / TCRC32 / TCRC64) that expose the
  IHash16 / IHash32 / IHash64 interfaces while delegating all work to the
  generic engine in HlpCRC (TCRC). The high-throughput PKZIP/Castagnoli
  variants live separately in HlpCRC32Fast.
}

interface

uses
  HlpHashLibTypes,
  HlpHash,
  HlpIHash,
  HlpICRC,
  HlpIHashResult,
  HlpIHashInfo,
  HlpCRC;

type

  TCRC16Polynomials = class sealed(TObject)

  private

    const

    BUYPASS = UInt16($8005);

  end;

  TCRC16 = class(THash, IChecksum, IHash16, ITransformBlock)

  strict private
  var
    FCRCAlgorithm: ICRC;

  public
    constructor Create(APolynomial, AInitial: UInt64;
      AIsInputReflected, AIsOutputReflected: Boolean;
      AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);

    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;

  end;

  TCRC16_BUYPASS = class sealed(TCRC16)

  public
    constructor Create();

  end;

  TCRC32Polynomials = class sealed(TObject)

  private

    const

    PKZIP = UInt32($04C11DB7);
    Castagnoli = UInt32($1EDC6F41);

  end;

  TCRC32 = class(THash, IChecksum, IHash32, ITransformBlock)

  strict private
  var
    FCRCAlgorithm: ICRC;

  public

    constructor Create(APolynomial, AInitial: UInt64;
      AIsInputReflected, AIsOutputReflected: Boolean;
      AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);

    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;
    function Clone(): IHash; override;

  end;

  TCRC32_PKZIP = class sealed(TCRC32)

  public
    constructor Create();

  end;

  TCRC32_CASTAGNOLI = class sealed(TCRC32)

  public
    constructor Create();

  end;

  TCRC64Polynomials = class sealed(TObject)

  private

    const

    ECMA_182 = UInt64($42F0E1EBA9EA3693);

  end;

  TCRC64 = class(THash, IChecksum, IHash64, ITransformBlock)

  strict private
  var
    FCRCAlgorithm: ICRC;

  public
    constructor Create(APolynomial, AInitial: UInt64;
      AIsInputReflected, AIsOutputReflected: Boolean;
      AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);

    procedure Initialize(); override;
    procedure TransformBytes(const AData: THashLibByteArray;
      AIndex, ALength: Int32); override;
    function TransformFinal(): IHashResult; override;
    function Clone(): IHash; override;

  end;

  TCRC64_ECMA_182 = class sealed(TCRC64)

  public
    constructor Create();

  end;

implementation

{ TCRC16 }

constructor TCRC16.Create(APolynomial, AInitial: UInt64;
  AIsInputReflected, AIsOutputReflected: Boolean;
  AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);
begin
  inherited Create(2, 1);
  FCRCAlgorithm := TCRC.Create(16, APolynomial, AInitial, AIsInputReflected,
    AIsOutputReflected, AOutputXor, ACheckValue, ANames);
end;

procedure TCRC16.Initialize;
begin
  FCRCAlgorithm.Initialize;
end;

procedure TCRC16.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  FCRCAlgorithm.TransformBytes(AData, AIndex, ALength);
end;

function TCRC16.TransformFinal: IHashResult;
begin
  Result := FCRCAlgorithm.TransformFinal();
end;

{ TCRC16_BUYPASS }

constructor TCRC16_BUYPASS.Create;
begin
  inherited Create(TCRC16Polynomials.BUYPASS, $0000, False, False, $0000, $FEE8,
    THashLibStringArray.Create('CRC-16/BUYPASS', 'CRC-16/VERIFONE',
    'CRC-16/UMTS'));
end;

{ TCRC32 }

function TCRC32.Clone(): IHash;
begin
  Result := FCRCAlgorithm.Clone();
end;

constructor TCRC32.Create(APolynomial, AInitial: UInt64;
  AIsInputReflected, AIsOutputReflected: Boolean;
  AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);
begin
  inherited Create(4, 1);
  FCRCAlgorithm := TCRC.Create(32, APolynomial, AInitial, AIsInputReflected,
    AIsOutputReflected, AOutputXor, ACheckValue, ANames);
end;

procedure TCRC32.Initialize;
begin
  FCRCAlgorithm.Initialize;
end;

procedure TCRC32.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  FCRCAlgorithm.TransformBytes(AData, AIndex, ALength);
end;

function TCRC32.TransformFinal: IHashResult;
begin
  Result := FCRCAlgorithm.TransformFinal();
end;

{ TCRC32_PKZIP }

constructor TCRC32_PKZIP.Create;
begin
  inherited Create(TCRC32Polynomials.PKZIP, $FFFFFFFF, True, True, $FFFFFFFF,
    $CBF43926, THashLibStringArray.Create('CRC-32', 'CRC-32/ADCCP',
    'CRC-32/V-42', 'CRC-32/XZ', 'PKZIP', 'CRC-32/ISO-HDLC'));

end;

{ TCRC32_CASTAGNOLI }

constructor TCRC32_CASTAGNOLI.Create;
begin
  inherited Create(TCRC32Polynomials.Castagnoli, $FFFFFFFF, True, True,
    $FFFFFFFF, $E3069283, THashLibStringArray.Create('CRC-32C',
    'CRC-32/BASE91-C', 'CRC-32/CASTAGNOLI', 'CRC-32/INTERLAKEN',
    'CRC-32/ISCSI'));

end;

{ TCRC64 }

function TCRC64.Clone(): IHash;
begin
  Result := FCRCAlgorithm.Clone();
end;

constructor TCRC64.Create(APolynomial, AInitial: UInt64;
  AIsInputReflected, AIsOutputReflected: Boolean;
  AOutputXor, ACheckValue: UInt64; const ANames: THashLibStringArray);
begin
  inherited Create(8, 1);
  FCRCAlgorithm := TCRC.Create(64, APolynomial, AInitial, AIsInputReflected,
    AIsOutputReflected, AOutputXor, ACheckValue, ANames);
end;

procedure TCRC64.Initialize;
begin
  FCRCAlgorithm.Initialize;
end;

procedure TCRC64.TransformBytes(const AData: THashLibByteArray;
  AIndex, ALength: Int32);
begin
  FCRCAlgorithm.TransformBytes(AData, AIndex, ALength);
end;

function TCRC64.TransformFinal: IHashResult;
begin
  Result := FCRCAlgorithm.TransformFinal();
end;

{ TCRC64_ECMA_182 }

constructor TCRC64_ECMA_182.Create;
begin
  inherited Create(TCRC64Polynomials.ECMA_182, $0000000000000000, False, False,
    $0000000000000000, $6C40DF5F0B497347, THashLibStringArray.Create('CRC-64',
    'CRC-64/ECMA-182'));
end;

end.
