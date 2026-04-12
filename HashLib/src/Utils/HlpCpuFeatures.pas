unit HlpCpuFeatures;

{$I ..\Include\HashLib.inc}

interface

uses
  HlpSimdLevels
{$IF DEFINED(HASHLIB_X86)}
  , HlpX86SimdFeatures
{$IFEND}
{$IF DEFINED(HASHLIB_ARM)}
  , HlpArmSimdFeatures
{$IFEND}
  ;

type
{$IF DEFINED(HASHLIB_X86)}
  TCpuFeaturesX86 = class of TX86SimdFeatures;
{$IFEND}
{$IF DEFINED(HASHLIB_ARM)}
  TCpuFeaturesArm = class of TArmSimdFeatures;
{$IFEND}

  TCpuFeatures = class sealed
  strict private
  {$IF DEFINED(HASHLIB_X86)}
    class function GetX86(): TCpuFeaturesX86; static;
  {$IFEND}
  {$IF DEFINED(HASHLIB_ARM)}
    class function GetArm(): TCpuFeaturesArm; static;
  {$IFEND}

  public
  {$IF DEFINED(HASHLIB_X86)}
    class property X86: TCpuFeaturesX86 read GetX86;
  {$IFEND}
  {$IF DEFINED(HASHLIB_ARM)}
    class property Arm: TCpuFeaturesArm read GetArm;
  {$IFEND}
  end;

implementation

{ TCpuFeatures }

{$IF DEFINED(HASHLIB_X86)}
class function TCpuFeatures.GetX86(): TCpuFeaturesX86;
begin
  Result := TX86SimdFeatures;
end;
{$IFEND}

{$IF DEFINED(HASHLIB_ARM)}
class function TCpuFeatures.GetArm(): TCpuFeaturesArm;
begin
  Result := TArmSimdFeatures;
end;
{$IFEND}

end.
