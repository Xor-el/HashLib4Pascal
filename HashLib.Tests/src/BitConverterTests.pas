unit BitConverterTests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HlpBitConverter;

type

  THashLibTestCase = class abstract(TTestCase)

  end;

type

  TBitConverterTestCase = class abstract(THashLibTestCase)
  protected
    FBuffer: TBytes;

  end;

type

  TTestToAndFroBoolean = class(TBitConverterTestCase)

  private

    FBoolean, FResult: Boolean;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroChar = class(TBitConverterTestCase)

  private

    FChar, FResult: Char;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroDouble = class(TBitConverterTestCase)

  private

    FDouble, FResult: Double;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroInt16 = class(TBitConverterTestCase)

  private

    FInt16, FResult: Int16;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroInt32 = class(TBitConverterTestCase)

  private

    FInt32, FResult: Int32;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroInt64 = class(TBitConverterTestCase)

  private

    FInt64, FResult: Int64;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroSingle = class(TBitConverterTestCase)

  private

    FSingle, FResult: Single;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroUInt8 = class(TBitConverterTestCase)

  private

    FUInt8, FResult: UInt8;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroUInt16 = class(TBitConverterTestCase)

  private

    FUInt16, FResult: UInt16;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroUInt32 = class(TBitConverterTestCase)

  private

    FUInt32, FResult: UInt32;

  published
    procedure TestConversion;

  end;

type

  TTestToAndFroUInt64 = class(TBitConverterTestCase)

  private

    FUInt64, FResult: UInt64;

  published
    procedure TestConversion;

  end;

implementation

{ TTestToAndFroBoolean }

procedure TTestToAndFroBoolean.TestConversion;
begin
  FBoolean := True;
  FBuffer := TBitConverter.GetBytes(FBoolean);
  FResult := TBitConverter.ToBoolean(FBuffer, 0);
  CheckEquals(FBoolean, FResult, Format('Expected %s but got %s.',
    [SysUtils.BoolToStr(FBoolean, True), SysUtils.BoolToStr(FResult, True)]));

end;

{ TTestToAndFroChar }

procedure TTestToAndFroChar.TestConversion;
begin
  FChar := 'X';
  FBuffer := TBitConverter.GetBytes(FChar);
  FResult := TBitConverter.ToChar(FBuffer, 0);
  CheckEquals(FChar, FResult, Format('Expected %s but got %s.',
    [FChar, FResult]));

end;

{ TTestToAndFroDouble }

procedure TTestToAndFroDouble.TestConversion;
begin
  FDouble := 2.56;
  FBuffer := TBitConverter.GetBytes(FDouble);
  FResult := TBitConverter.ToDouble(FBuffer, 0);
  CheckEquals(FDouble, FResult, Format('Expected %s but got %s.',
    [FloatToStr(FDouble), FloatToStr(FResult)]));

end;

{ TTestToAndFroInt16 }

procedure TTestToAndFroInt16.TestConversion;
begin
  FInt16 := -4;
  FBuffer := TBitConverter.GetBytes(FInt16);
  FResult := TBitConverter.ToInt16(FBuffer, 0);
  CheckEquals(FInt16, FResult, Format('Expected %s but got %s.',
    [IntToStr(FInt16), IntToStr(FResult)]));

end;

{ TTestToAndFroInt32 }

procedure TTestToAndFroInt32.TestConversion;
begin
  FInt32 := -18;
  FBuffer := TBitConverter.GetBytes(FInt32);
  FResult := TBitConverter.ToInt32(FBuffer, 0);
  CheckEquals(FInt32, FResult, Format('Expected %s but got %s.',
    [IntToStr(FInt32), IntToStr(FResult)]));

end;

{ TTestToAndFroInt64 }

procedure TTestToAndFroInt64.TestConversion;
begin
  FInt64 := -6578;
  FBuffer := TBitConverter.GetBytes(FInt64);
  FResult := TBitConverter.ToInt64(FBuffer, 0);
  CheckEquals(FInt64, FResult, Format('Expected %s but got %s.',
    [IntToStr(FInt64), IntToStr(FResult)]));

end;

{ TTestToAndFroSingle }

procedure TTestToAndFroSingle.TestConversion;
begin
  FSingle := -5.64;
  FBuffer := TBitConverter.GetBytes(FSingle);
  FResult := TBitConverter.ToSingle(FBuffer, 0);
  CheckEquals(FSingle, FResult, Format('Expected %s but got %s.',
    [FloatToStr(FSingle), FloatToStr(FResult)]));

end;

{ TTestToAndFroUInt8 }

procedure TTestToAndFroUInt8.TestConversion;
begin
  FUInt8 := 7;
  FBuffer := TBitConverter.GetBytes(FUInt8);
  FResult := TBitConverter.ToUInt8(FBuffer, 0);
{$IFDEF FPC}
  CheckEquals(FUInt8, FResult, Format('Expected %s but got %s.',
    [IntToStr(FUInt8), IntToStr(FResult)]));
{$ELSE}
  CheckEquals(FUInt8, FResult, Format('Expected %s but got %s.',
    [UIntToStr(FUInt8), UIntToStr(FResult)]));
{$ENDIF FPC}
end;

{ TTestToAndFroUInt16 }

procedure TTestToAndFroUInt16.TestConversion;
begin
  FUInt16 := 14;
  FBuffer := TBitConverter.GetBytes(FUInt16);
  FResult := TBitConverter.ToUInt16(FBuffer, 0);
{$IFDEF FPC}
  CheckEquals(FUInt16, FResult, Format('Expected %s but got %s.',
    [IntToStr(FUInt16), IntToStr(FResult)]));
{$ELSE}
  CheckEquals(FUInt16, FResult, Format('Expected %s but got %s.',
    [UIntToStr(FUInt16), UIntToStr(FResult)]));
{$ENDIF FPC}
end;

{ TTestToAndFroUInt32 }

procedure TTestToAndFroUInt32.TestConversion;
begin
  FUInt32 := 25;
  FBuffer := TBitConverter.GetBytes(FUInt32);
  FResult := TBitConverter.ToUInt32(FBuffer, 0);
{$IFDEF FPC}
  CheckEquals(FUInt32, FResult, Format('Expected %s but got %s.',
    [IntToStr(FUInt32), IntToStr(FResult)]));
{$ELSE}
  CheckEquals(FUInt32, FResult, Format('Expected %s but got %s.',
    [UIntToStr(FUInt32), UIntToStr(FResult)]));
{$ENDIF FPC}
end;

{ TTestToAndFroUInt64 }

procedure TTestToAndFroUInt64.TestConversion;
begin
  FUInt64 := 75;
  FBuffer := TBitConverter.GetBytes(FUInt64);
  FResult := TBitConverter.ToUInt64(FBuffer, 0);
{$IFDEF FPC}
  CheckEquals(FUInt64, FResult, Format('Expected %s but got %s.',
    [IntToStr(FUInt64), IntToStr(FResult)]));
{$ELSE}
  CheckEquals(FUInt64, FResult, Format('Expected %s but got %s.',
    [UIntToStr(FUInt64), UIntToStr(FResult)]));
{$ENDIF FPC}
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestToAndFroBoolean);
RegisterTest(TTestToAndFroChar);
RegisterTest(TTestToAndFroDouble);
RegisterTest(TTestToAndFroInt16);
RegisterTest(TTestToAndFroInt32);
RegisterTest(TTestToAndFroInt64);
RegisterTest(TTestToAndFroSingle);
RegisterTest(TTestToAndFroUInt8);
RegisterTest(TTestToAndFroUInt16);
RegisterTest(TTestToAndFroUInt32);
RegisterTest(TTestToAndFroUInt64);
{$ELSE}
  RegisterTest(TTestToAndFroBoolean.Suite);
RegisterTest(TTestToAndFroChar.Suite);
RegisterTest(TTestToAndFroDouble.Suite);
RegisterTest(TTestToAndFroInt16.Suite);
RegisterTest(TTestToAndFroInt32.Suite);
RegisterTest(TTestToAndFroInt64.Suite);
RegisterTest(TTestToAndFroSingle.Suite);
RegisterTest(TTestToAndFroUInt8.Suite);
RegisterTest(TTestToAndFroUInt16.Suite);
RegisterTest(TTestToAndFroUInt32.Suite);
RegisterTest(TTestToAndFroUInt64.Suite);
{$ENDIF FPC}

end.
