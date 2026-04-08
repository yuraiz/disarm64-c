//! Floating-point register and immediate formatting.

use crate::registers::{get_fp_reg_name, FpRegSize};
use core::fmt::Write;
use disarm64_defn::{defn, InsnClass, InsnFlags, InsnOperandKind, InsnOperandQualifier};

use super::bits::bit_range;
use super::qualifier::{immh_level, qualifier_to_fp_size, scalar_size_qualifier_idx};

/// Format a floating-point register operand.
pub(crate) fn format_fp_reg(
    f: &mut impl Write,
    bits: u32,
    operand: &defn::InsnOperand,
    definition: &defn::Insn,
) -> core::fmt::Result {
    let kind = operand.kind;

    let reg_no = if let Some(bit_filed) = operand.bit_fields.first() {
        bit_range(bits, bit_filed.lsb.into(), bit_filed.width.into())
    } else {
        return write!(f, ":{kind:?}:");
    };

    let fp_reg_name = match definition.class {
        InsnClass::LDST_IMM9
        | InsnClass::LDST_POS
        | InsnClass::LDST_REGOFF
        | InsnClass::LDST_UNSCALED => {
            let size = bit_range(bits, 30, 2);
            let opc = bit_range(bits, 22, 2);
            if opc == 0 || opc == 1 {
                let fp_size = match size {
                    0b00 => FpRegSize::B8,
                    0b01 => FpRegSize::H16,
                    0b10 => FpRegSize::S32,
                    0b11 => FpRegSize::D64,
                    _ => unreachable!(),
                };
                get_fp_reg_name(fp_size, reg_no as usize)
            } else if (opc == 0b10 || opc == 0b11) && size == 0 {
                get_fp_reg_name(FpRegSize::Q128, reg_no as usize)
            } else {
                return write!(f, "<undefined>");
            }
        }
        InsnClass::LDSTPAIR_OFF
        | InsnClass::LDSTNAPAIR_OFFS
        | InsnClass::LDSTPAIR_INDEXED
        | InsnClass::LOADLIT => {
            let opc = bit_range(bits, 30, 2);
            if opc == 0 {
                get_fp_reg_name(FpRegSize::S32, reg_no as usize)
            } else if opc == 1 {
                get_fp_reg_name(FpRegSize::D64, reg_no as usize)
            } else if opc == 2 {
                get_fp_reg_name(FpRegSize::Q128, reg_no as usize)
            } else {
                return write!(f, "<undefined>");
            }
        }
        InsnClass::BFLOAT16 => match kind {
            InsnOperandKind::Fd => get_fp_reg_name(FpRegSize::H16, reg_no as usize),
            InsnOperandKind::Fn => get_fp_reg_name(FpRegSize::S32, reg_no as usize),
            _ => {
                return write!(f, "<undefined>");
            }
        },
        InsnClass::ASIMDALL => {
            let size = bit_range(bits, 22, 2);
            let cross_lane = super::bits::bit_set(bits, 15);
            if cross_lane {
                match size {
                    0b00 => get_fp_reg_name(FpRegSize::B8, reg_no as usize),
                    0b01 => get_fp_reg_name(FpRegSize::H16, reg_no as usize),
                    0b10 => get_fp_reg_name(FpRegSize::S32, reg_no as usize),
                    0b11 => return write!(f, "<undefined>"),
                    _ => unreachable!(),
                }
            } else {
                match size {
                    0b00 => get_fp_reg_name(FpRegSize::H16, reg_no as usize),
                    0b01 => get_fp_reg_name(FpRegSize::S32, reg_no as usize),
                    0b10 => get_fp_reg_name(FpRegSize::D64, reg_no as usize),
                    0b11 => return write!(f, "<undefined>"),
                    _ => unreachable!(),
                }
            }
        }

        _ => {
            if definition.flags.contains(InsnFlags::HAS_FPTYPE_FIELD) {
                let fp_type = bit_range(bits, 22, 2);
                match fp_type {
                    0b00 => get_fp_reg_name(FpRegSize::S32, reg_no as usize),
                    0b01 => get_fp_reg_name(FpRegSize::D64, reg_no as usize),
                    0b10 => "<undefined>",
                    0b11 => get_fp_reg_name(FpRegSize::H16, reg_no as usize),
                    _ => unreachable!(),
                }
            } else if definition
                .flags
                .contains(InsnFlags::HAS_ADVSIMD_SCALAR_SIZE)
                && operand.qualifiers.len() > 1
            {
                // Scalar ASISD: size bits[23:22] index into qualifier list.
                // FP [S_S,S_D] with bit23 constrained: bit22 alone selects S/D.
                // Integer widening [S_H,S_S] or [S_S,S_D]: size-1 as index.
                let size = bit_range(bits, 22, 2) as usize;
                let fp_scalar = operand.qualifiers.len() == 2
                    && matches!(operand.qualifiers.first(), Some(InsnOperandQualifier::S_S))
                    && (definition.mask >> 23) & 1 != 0;
                let idx = if fp_scalar {
                    // FP: bit22=0→S(idx 0), bit22=1→D(idx 1)
                    Some(bit_range(bits, 22, 1) as usize)
                } else {
                    scalar_size_qualifier_idx(operand.qualifiers, size)
                };
                match idx
                    .and_then(|i| operand.qualifiers.get(i))
                    .and_then(qualifier_to_fp_size)
                {
                    Some(fp) => get_fp_reg_name(fp, reg_no as usize),
                    None => return write!(f, "<undefined>"),
                }
            } else if operand.qualifiers.len() > 1 {
                // Multi-qualifier without ADVSIMD_SCALAR_SIZE (e.g., ASISDSHF):
                // use immh level to index, offset by first qualifier's absolute level
                let level = match immh_level(bits) {
                    Some(l) => l,
                    None => return write!(f, "<undefined>"),
                };
                let base = match operand.qualifiers.first() {
                    Some(InsnOperandQualifier::S_B) => 0usize,
                    Some(InsnOperandQualifier::S_H) => 1,
                    Some(InsnOperandQualifier::S_S) => 2,
                    Some(InsnOperandQualifier::S_D) => 3,
                    _ => return write!(f, "<undefined>"),
                };
                // For len>=3 lists, idx=level (direct mapping).
                // For len=2 lists, idx=level-base (offset by first qualifier level).
                let idx = if operand.qualifiers.len() >= 3 {
                    level
                } else {
                    level.checked_sub(base).unwrap_or(0)
                };
                match operand.qualifiers.get(idx).and_then(qualifier_to_fp_size) {
                    Some(fp) => get_fp_reg_name(fp, reg_no as usize),
                    None => return write!(f, "<undefined>"),
                }
            } else if let Some(qual) = operand.qualifiers.first() {
                match qualifier_to_fp_size(qual) {
                    Some(fp) => get_fp_reg_name(fp, reg_no as usize),
                    None => return write!(f, "<undefined>"),
                }
            } else {
                return write!(f, ":{kind:?}:");
            }
        }
    };

    write!(f, "{fp_reg_name}")
}

/// Follows `bits(N) VFPExpandImm(bits(8) imm8, integer N)` in the A64 reference.
pub(crate) fn fp_expand_imm(size: i32, imm8: u32) -> Option<f64> {
    let imm8_7 = (imm8 >> 7) & 0x01; // imm8<7>
    let imm8_6_0 = imm8 & 0x7f; // imm8<6:0>
    let imm8_6 = imm8_6_0 >> 6; // imm8<6>
    let imm8_6_repl4 = (imm8_6 << 3) | (imm8_6 << 2) | (imm8_6 << 1) | imm8_6; // Replicate(imm8<6>,4)

    match size {
        8 => {
            // Double-precision
            let imm: u64 = ((imm8_7 as u64) << (63-32))    // imm8<7>
                | (((imm8_6 ^ 1) as u64) << (62-32)) // NOT(imm8<6>)
                | ((imm8_6_repl4 as u64) << (58-32))
                | ((imm8_6 as u64) << (57-32))
                | ((imm8_6 as u64) << (56-32))
                | ((imm8_6 as u64) << (55-32))      // Replicate(imm8<6>,7)
                | ((imm8_6_0 as u64) << (48-32)); // imm8<6>:imm8<5:0>
            Some(f64::from_bits(imm << 32))
        }
        4 | 2 => {
            // Single precision | Half-precision
            let imm = ((imm8_7 as u64) << 31)    // imm8<7>
                | (((imm8_6 ^ 1) as u64) << 30) // NOT(imm8<6>)
                | ((imm8_6_repl4 as u64) << 26) // Replicate(imm8<6>,4)
                | ((imm8_6_0 as u64) << 19); // imm8<6>:imm8<5:0>
            Some(f32::from_bits(imm as u32) as f64)
        }
        _ => None,
    }
}
