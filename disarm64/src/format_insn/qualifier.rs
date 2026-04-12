//! Qualifier mapping and indexing helpers for ARM64 operand formatting.

use crate::registers::FpRegSize;
use crate::registers::SimdRegArrangement;
use disarm64_defn::InsnFlags;
use disarm64_defn::InsnOperandQualifier;

use super::bits::{bit_range, bit_set};

/// Map a scalar qualifier to FpRegSize.
pub(crate) fn qualifier_to_fp_size(qual: &InsnOperandQualifier) -> Option<FpRegSize> {
    match qual {
        InsnOperandQualifier::S_B => Some(FpRegSize::B8),
        InsnOperandQualifier::S_H => Some(FpRegSize::H16),
        InsnOperandQualifier::S_S => Some(FpRegSize::S32),
        InsnOperandQualifier::S_D => Some(FpRegSize::D64),
        InsnOperandQualifier::S_Q => Some(FpRegSize::Q128),
        _ => None,
    }
}

/// Extract the element size category from a vector qualifier.
/// Returns 0=B, 1=H, 2=S, 3=D, or 0xFF for non-vector qualifiers.
pub(crate) fn qualifier_element_size(q: &InsnOperandQualifier) -> u8 {
    match q {
        InsnOperandQualifier::V_8B | InsnOperandQualifier::V_16B => 0,
        InsnOperandQualifier::V_2H | InsnOperandQualifier::V_4H | InsnOperandQualifier::V_8H => 1,
        InsnOperandQualifier::V_2S | InsnOperandQualifier::V_4S => 2,
        InsnOperandQualifier::V_1D | InsnOperandQualifier::V_2D => 3,
        _ => 0xFF,
    }
}

/// Compute qualifier index for scalar ASISD from a size/level value.
/// For lists with 3+ entries: idx = size (direct mapping).
/// For 2-entry lists: idx = size - 1 (widening/narrowing offset).
/// FP scalar [S_S,S_D] with bit22-only indexing should be handled separately.
pub(crate) fn scalar_size_qualifier_idx(
    qualifiers: &[InsnOperandQualifier],
    size: usize,
) -> Option<usize> {
    let idx = if qualifiers.len() >= 3 {
        size
    } else if qualifiers.len() == 2 {
        // 2-element widening/narrowing: size encodes source level,
        // qualifier index is offset by 1 regardless of starting qualifier.
        // [S_H,S_S]: size=1→0, size=2→1
        // [S_S,S_D]: size=1→0, size=2→1
        size.checked_sub(1)?
    } else {
        0
    };
    if idx < qualifiers.len() {
        Some(idx)
    } else {
        None
    }
}

/// Compute immh level from bits[22:19] for shift instructions.
/// Returns 0=B, 1=H, 2=S, 3=D, or None if immh=0 (reserved).
pub(crate) fn immh_level(bits: u32) -> Option<usize> {
    let immh = bit_range(bits, 19, 4);
    if immh >= 8 {
        Some(3)
    } else if immh >= 4 {
        Some(2)
    } else if immh >= 2 {
        Some(1)
    } else if immh >= 1 {
        Some(0)
    } else {
        None
    }
}

/// Compute qualifier index for ASIMDINS from imm5 level and Q bit.
/// Returns None if imm5<3:0> == 0 or D-level with Q=0.
pub(crate) fn asimdins_qualifier_idx(bits: u32) -> Option<usize> {
    let imm5 = bit_range(bits, 16, 5);
    let q = bit_set(bits, 30) as usize;

    if imm5 & 1 != 0 {
        Some(q) // B: 0 or 1
    } else if imm5 & 2 != 0 {
        Some(2 + q) // H: 2 or 3
    } else if imm5 & 4 != 0 {
        Some(4 + q) // S: 4 or 5
    } else if imm5 & 8 != 0 {
        if q == 0 {
            None // D with Q=0 is undefined
        } else {
            Some(6) // D: only Q=1
        }
    } else {
        None // imm5<3:0> == 0 is reserved
    }
}

/// Determine element size suffix from imm5 encoding.
/// Returns (suffix char, index) or None if imm5<3:0> == 0.
pub(crate) fn decode_imm5_element(imm5: u32) -> Option<(char, u32)> {
    if imm5 & 1 != 0 {
        Some(('b', imm5 >> 1))
    } else if imm5 & 2 != 0 {
        Some(('h', imm5 >> 2))
    } else if imm5 & 4 != 0 {
        Some(('s', imm5 >> 3))
    } else if imm5 & 8 != 0 {
        Some(('d', imm5 >> 4))
    } else {
        None
    }
}

/// Map a qualifier to a SimdRegArrangement.
pub(crate) fn qualifier_to_simd_reg(qual: &InsnOperandQualifier) -> Option<SimdRegArrangement> {
    match qual {
        InsnOperandQualifier::V_8B => Some(SimdRegArrangement::Vector8B),
        InsnOperandQualifier::V_16B => Some(SimdRegArrangement::Vector16B),
        InsnOperandQualifier::V_2H => Some(SimdRegArrangement::Vector2H),
        InsnOperandQualifier::V_4H => Some(SimdRegArrangement::Vector4H),
        InsnOperandQualifier::V_8H => Some(SimdRegArrangement::Vector8H),
        InsnOperandQualifier::V_2S => Some(SimdRegArrangement::Vector2S),
        InsnOperandQualifier::V_4S => Some(SimdRegArrangement::Vector4S),
        InsnOperandQualifier::V_1D => Some(SimdRegArrangement::Vector1D),
        InsnOperandQualifier::V_2D => Some(SimdRegArrangement::Vector2D),
        InsnOperandQualifier::V_1Q => Some(SimdRegArrangement::Vector1Q),
        _ => None,
    }
}

/// Map a qualifier to a vector arrangement suffix string.
pub(crate) fn qualifier_arrangement(qual: InsnOperandQualifier) -> Option<&'static str> {
    match qual {
        InsnOperandQualifier::V_8B => Some("8b"),
        InsnOperandQualifier::V_16B => Some("16b"),
        InsnOperandQualifier::V_4H => Some("4h"),
        InsnOperandQualifier::V_8H => Some("8h"),
        InsnOperandQualifier::V_2S => Some("2s"),
        InsnOperandQualifier::V_4S => Some("4s"),
        InsnOperandQualifier::V_1D => Some("1d"),
        InsnOperandQualifier::V_2D => Some("2d"),
        InsnOperandQualifier::V_1Q => Some("1q"),
        _ => None,
    }
}

/// Resolve vector arrangement from size and Q bits using a qualifier list.
pub(crate) fn resolve_sizeq_arrangement(
    qualifiers: &[InsnOperandQualifier],
    size: u32,
    q: bool,
) -> Option<&'static str> {
    let idx = if qualifiers.len() >= 7 {
        // Full [8B,16B,4H,8H,2S,4S,2D]: idx = size*2+Q, D only with Q=1
        if size == 3 {
            if !q {
                return None;
            }
            6
        } else {
            size as usize * 2 + q as usize
        }
    } else if qualifiers.len() >= 4 && qualifiers.first() == Some(&InsnOperandQualifier::V_8B) {
        // Same as above, abbreviated
        if size == 3 {
            if !q {
                return None;
            }
            6.min(qualifiers.len() - 1)
        } else {
            (size as usize * 2 + q as usize).min(qualifiers.len() - 1)
        }
    } else {
        size as usize * 2 + q as usize
    };
    qualifiers.get(idx).and_then(|q| qualifier_arrangement(*q))
}

/// Resolve qualifier index for Em/Em16 from size and Q bits.
pub(crate) fn resolve_em_qualifier_idx(
    qualifiers: &[InsnOperandQualifier],
    flags: InsnFlags,
    bits: u32,
    mask: u32,
) -> usize {
    let size = bit_range(bits, 22, 2) as usize;
    let q = bit_set(bits, 30) as usize;
    let len = qualifiers.len();

    if flags.contains(InsnFlags::HAS_SIZEQ_FIELD) {
        match len {
            4 => {
                // [S_H, S_H, S_S, S_S]: (size-1)*2 + Q
                if size >= 1 {
                    (size - 1) * 2 + q
                } else {
                    0
                }
            }
            3 => {
                let first = qualifiers.first().copied();
                if matches!(first, Some(InsnOperandQualifier::S_S)) {
                    // [S_S, S_S, S_D]: FP — bit22 selects S/D, Q selects width
                    if size & 1 != 0 {
                        2 // D
                    } else {
                        q // S, Q selects idx 0 or 1
                    }
                } else {
                    // [S_H, S_H, S_S]: size-level, (size-1)*2+Q clamped
                    if size >= 1 {
                        ((size - 1) * 2 + q).min(len - 1)
                    } else {
                        0
                    }
                }
            }
            2 => {
                if qualifiers[0] == qualifiers[1] {
                    q // Same qualifier: Q selects variant
                } else {
                    size.saturating_sub(1)
                }
            }
            _ => 0,
        }
    } else if flags.contains(InsnFlags::HAS_ADVSIMD_SCALAR_SIZE) {
        // FP [S_S,S_D] with bit23 constrained: use bit22 alone
        let fp_scalar = len == 2
            && matches!(qualifiers.first(), Some(InsnOperandQualifier::S_S))
            && (mask >> 23) & 1 != 0;
        if fp_scalar {
            bit_range(bits, 22, 1) as usize
        } else {
            scalar_size_qualifier_idx(qualifiers, size).unwrap_or(0)
        }
    } else {
        0
    }
}
