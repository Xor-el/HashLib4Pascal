unit HlpCpuFeatures;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpSimdLevels,
  HlpX86SimdFeatures,
  HlpArmSimdFeatures;

type
  TCpuFeaturesX86 = class of TX86SimdFeatures;
  TCpuFeaturesArm = class of TArmSimdFeatures;

  TCpuFeatures = class sealed
  strict private
    class function GetX86(): TCpuFeaturesX86; static;
    class function GetArm(): TCpuFeaturesArm; static;

  public
    class property X86: TCpuFeaturesX86 read GetX86;
    class property Arm: TCpuFeaturesArm read GetArm;
  end;

implementation

{ TCpuFeatures }

class function TCpuFeatures.GetX86(): TCpuFeaturesX86;
begin
  Result := TX86SimdFeatures;
end;

class function TCpuFeatures.GetArm(): TCpuFeaturesArm;
begin
  Result := TArmSimdFeatures;
end;

end.
