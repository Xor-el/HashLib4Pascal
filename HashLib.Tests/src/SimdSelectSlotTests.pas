unit SimdSelectSlotTests;

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  HlpSimdLevels,
  HlpX86SimdFeatures,
  HlpArmSimdFeatures;

type

  THashLibTestCase = class abstract(TTestCase)

  end;

type

  // Exercises the pure overload of TX86SimdFeatures.SelectSlot, which
  // takes the active level as a parameter and is therefore fully
  // deterministic and host-CPU-independent.
  TTestX86SelectSlot = class(THashLibTestCase)
  published
    procedure TestExactMatch;
    procedure TestStepDownOnUnsupportedTier;
    procedure TestAllDeclaredTiersAboveActive;
    procedure TestEmptyTiers;
    procedure TestTierOrderIndependence;
    procedure TestScalarHost;
    procedure TestScalarTierAlwaysReachable;
  end;

type

  // Symmetric coverage for the ARM surface, since the same SelectSlot
  // shape lives on TArmSimdFeatures.
  TTestArmSelectSlot = class(THashLibTestCase)
  published
    procedure TestExactMatch;
    procedure TestStepDownOnUnsupportedTier;
    procedure TestAllDeclaredTiersAboveActive;
    procedure TestEmptyTiers;
    procedure TestTierOrderIndependence;
    procedure TestScalarHost;
  end;

implementation

function X86LevelName(ALevel: TX86SimdLevel): string;
begin
  case ALevel of
    TX86SimdLevel.Scalar: Result := 'Scalar';
    TX86SimdLevel.SSE2:   Result := 'SSE2';
    TX86SimdLevel.SSE3:   Result := 'SSE3';
    TX86SimdLevel.SSSE3:  Result := 'SSSE3';
    TX86SimdLevel.SSE41:  Result := 'SSE41';
    TX86SimdLevel.SSE42:  Result := 'SSE42';
    TX86SimdLevel.AVX2:   Result := 'AVX2';
  else
    Result := 'Unknown';
  end;
end;

function ArmLevelName(ALevel: TArmSimdLevel): string;
begin
  case ALevel of
    TArmSimdLevel.Scalar: Result := 'Scalar';
    TArmSimdLevel.NEON:   Result := 'NEON';
    TArmSimdLevel.SVE:    Result := 'SVE';
    TArmSimdLevel.SVE2:   Result := 'SVE2';
  else
    Result := 'Unknown';
  end;
end;

{ TTestX86SelectSlot }

procedure TTestX86SelectSlot.TestExactMatch;
var
  LResult: TX86SimdLevel;
begin
  // Active host advertises AVX2; AVX2 is declared, so it should win.
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.AVX2,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.AVX2,
    Format('Expected AVX2 but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestStepDownOnUnsupportedTier;
var
  LResult: TX86SimdLevel;
begin
  // Host advertises SSE41 (probed but not declared by the algorithm).
  // The algorithm declares only AVX2 and SSE2; SelectSlot must step
  // down to SSE2 (the central future-proofing claim).
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE41,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.SSE2,
    Format('Expected SSE2 but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestAllDeclaredTiersAboveActive;
var
  LResult: TX86SimdLevel;
begin
  // Host caps at SSE2; algorithm declares only AVX2. No tier matches,
  // so SelectSlot must fall back to Scalar.
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE2,
    [TX86SimdLevel.AVX2]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestEmptyTiers;
var
  LResult: TX86SimdLevel;
  LEmpty: array of TX86SimdLevel;
begin
  // An algorithm with no SIMD impls passes an empty tier array.
  // SelectSlot must fall back to Scalar regardless of host capability.
  System.SetLength(LEmpty, 0);
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.AVX2, LEmpty);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestTierOrderIndependence;
var
  LDescending, LAscending: TX86SimdLevel;
begin
  // SelectSlot reasons over the set of declared tiers, not their order.
  // Both orderings must yield the same result for the same host level.
  LDescending := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE42,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  LAscending := TX86SimdFeatures.SelectSlot(TX86SimdLevel.SSE42,
    [TX86SimdLevel.SSE2, TX86SimdLevel.AVX2]);
  CheckTrue(LDescending = LAscending,
    Format('Order-dependent result: descending=%s ascending=%s.',
      [X86LevelName(LDescending), X86LevelName(LAscending)]));
  CheckTrue(LDescending = TX86SimdLevel.SSE2,
    Format('Expected SSE2 but got %s.', [X86LevelName(LDescending)]));
end;

procedure TTestX86SelectSlot.TestScalarHost;
var
  LResult: TX86SimdLevel;
begin
  // A host that probed Scalar must never select any SIMD tier.
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.Scalar,
    [TX86SimdLevel.AVX2, TX86SimdLevel.SSE2]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

procedure TTestX86SelectSlot.TestScalarTierAlwaysReachable;
var
  LResult: TX86SimdLevel;
begin
  // If the algorithm explicitly declares Scalar as a tier, that is
  // always reachable - even on a Scalar host.
  LResult := TX86SimdFeatures.SelectSlot(TX86SimdLevel.Scalar,
    [TX86SimdLevel.Scalar]);
  CheckTrue(LResult = TX86SimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [X86LevelName(LResult)]));
end;

{ TTestArmSelectSlot }

procedure TTestArmSelectSlot.TestExactMatch;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE2,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.SVE2,
    Format('Expected SVE2 but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestStepDownOnUnsupportedTier;
var
  LResult: TArmSimdLevel;
begin
  // Host advertises SVE; algorithm offers SVE2 + NEON only.
  // Must step down to NEON (highest reachable declared tier).
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.NEON,
    Format('Expected NEON but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestAllDeclaredTiersAboveActive;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.NEON,
    [TArmSimdLevel.SVE2]);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestEmptyTiers;
var
  LResult: TArmSimdLevel;
  LEmpty: array of TArmSimdLevel;
begin
  System.SetLength(LEmpty, 0);
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE2, LEmpty);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

procedure TTestArmSelectSlot.TestTierOrderIndependence;
var
  LDescending, LAscending: TArmSimdLevel;
begin
  LDescending := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  LAscending := TArmSimdFeatures.SelectSlot(TArmSimdLevel.SVE,
    [TArmSimdLevel.NEON, TArmSimdLevel.SVE2]);
  CheckTrue(LDescending = LAscending,
    Format('Order-dependent result: descending=%s ascending=%s.',
      [ArmLevelName(LDescending), ArmLevelName(LAscending)]));
  CheckTrue(LDescending = TArmSimdLevel.NEON,
    Format('Expected NEON but got %s.', [ArmLevelName(LDescending)]));
end;

procedure TTestArmSelectSlot.TestScalarHost;
var
  LResult: TArmSimdLevel;
begin
  LResult := TArmSimdFeatures.SelectSlot(TArmSimdLevel.Scalar,
    [TArmSimdLevel.SVE2, TArmSimdLevel.NEON]);
  CheckTrue(LResult = TArmSimdLevel.Scalar,
    Format('Expected Scalar but got %s.', [ArmLevelName(LResult)]));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX86SelectSlot);
  RegisterTest(TTestArmSelectSlot);
{$ELSE}
  RegisterTest(TTestX86SelectSlot.Suite);
  RegisterTest(TTestArmSelectSlot.Suite);
{$ENDIF FPC}

end.
