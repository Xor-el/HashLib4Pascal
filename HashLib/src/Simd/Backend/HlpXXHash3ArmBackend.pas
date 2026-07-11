unit HlpXXHash3ArmBackend;

{$I ..\..\Include\HashLib.inc}

interface

uses
  HlpXXHash3;

type
  /// <summary>
  /// Arm SIMD backend for XXH3: owns the AArch64 NEON accumulate / scramble /
  /// init-secret kernels (bodies in <c>Include\Simd\XXH3\</c>) and the runtime
  /// tier selection via <c>TCpuFeatures.Arm</c>. Compiles on every target -
  /// without Arm SIMD the selectors return the scalar routines.
  /// </summary>
  TXXHash3ArmBackend = class sealed
  public
    class function SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc; static;
    class function SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc; static;
    class function SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc; static;
    class function SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc; static;
  end;

implementation

{$IFDEF HASHLIB_AARCH64_ASM}

uses
  HlpCpuFeatures,
  HlpSimdLevels;

// =============================================================================
// SIMD kernels
//   aarch64: NEON
// =============================================================================

procedure XXH3_Accumulate512_Neon(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_aarch64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3Acc512Neon_aarch64.inc}
end;

procedure XXH3_ScrambleAcc_Neon(AAcc: Pointer; ASecret: Pointer);
  {$I ..\..\Include\Simd\Common\HlpSimdProc2Begin_aarch64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3ScrambleNeon_aarch64.inc}
end;

procedure XXH3_InitSecret_Neon(ACustomSecret: Pointer;
  ADefaultSecret: Pointer; ASeed: UInt64);
  {$I ..\..\Include\Simd\Common\HlpSimdProc3Begin_aarch64.inc}
  {$I ..\..\Include\Simd\XXH3\XXH3InitSecretNeon_aarch64.inc}
end;

procedure XXH3_Accumulate_Neon(AAcc: Pointer; AInput: Pointer;
  ASecret: Pointer; ANbStripes: Int32);
begin
  XXH3_Accumulate_Loop(AAcc, AInput, ASecret, ANbStripes, @XXH3_Accumulate512_Neon);
end;

{$ENDIF HASHLIB_AARCH64_ASM}

{ TXXHash3ArmBackend }

class function TXXHash3ArmBackend.SelectAccumulate512(AScalar: TXXH3Accumulate512Proc): TXXH3Accumulate512Proc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@XXH3_Accumulate512_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3ArmBackend.SelectAccumulate(AScalar: TXXH3AccumulateProc): TXXH3AccumulateProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@XXH3_Accumulate_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3ArmBackend.SelectScrambleAcc(AScalar: TXXH3ScrambleAccProc): TXXH3ScrambleAccProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@XXH3_ScrambleAcc_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

class function TXXHash3ArmBackend.SelectInitSecret(AScalar: TXXH3InitSecretProc): TXXH3InitSecretProc;
begin
{$IFDEF HASHLIB_AARCH64_ASM}
  case TCpuFeatures.Arm.SelectSlot([TArmSimdLevel.NEON]) of
    TArmSimdLevel.NEON: Exit(@XXH3_InitSecret_Neon);
  end;
{$ENDIF}
  Result := AScalar;
end;

end.
