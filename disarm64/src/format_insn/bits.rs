//! Bit manipulation utilities for instruction decoding.

pub(crate) fn cond_name(cond: u32) -> &'static str {
    const COND: [&str; 16] = [
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al",
        "nv",
    ];
    COND[(cond & 0b1111) as usize]
}

pub(crate) fn bit_set(bits: u32, bit: u32) -> bool {
    bits & (1 << bit) != 0
}

pub(crate) fn bit_range(bits: u32, start: u32, width: u32) -> u32 {
    (bits >> start) & ((1 << width) - 1)
}

pub(crate) fn sign_extend(v: u32, n: u8) -> u64 {
    debug_assert!(n < 32);

    let v = v as u64;
    let mask = 1u64 << n;

    // Sign-extend by utilizing the fact that shifting into the sign bit replicates the bit.
    (v ^ mask).wrapping_sub(mask)
}

/// Decode a logical immediate value, N:immr:imms.
pub(crate) fn decode_limm(byte_count: u32, n: u32, mut immr: u32, mut imms: u32) -> Option<u64> {
    let mut imm;
    let mask;
    let bit_count: u32;

    if n != 0 {
        bit_count = 64;
        mask = !0;
    } else {
        bit_count = match imms {
            0x00..=0x1f => 32,
            0x20..=0x2f => {
                imms &= 0xf;
                16
            }
            0x30..=0x37 => {
                imms &= 0x7;
                8
            }
            0x38..=0x3b => {
                imms &= 0x3;
                4
            }
            0x3c..=0x3d => {
                imms &= 0x1;
                2
            }
            _ => return None,
        };
        mask = (1u64 << bit_count) - 1;
        immr &= bit_count - 1;
    }

    if bit_count > byte_count * 8 {
        return None;
    }

    if imms == bit_count - 1 {
        return None;
    }

    imm = (1u64 << (imms + 1)) - 1;
    if immr != 0 {
        imm = ((imm << (bit_count - immr)) & mask) | (imm >> immr);
    }

    let replicate: &[u64] = match bit_count {
        2 => &[2, 4, 8, 16, 32],
        4 => &[4, 8, 16, 32],
        8 => &[8, 16, 32],
        16 => &[16, 32],
        32 => &[32],
        64 => &[],
        _ => return None,
    };
    for &r in replicate {
        imm |= imm << r;
    }

    let limm = !0 << (byte_count * 4) << (byte_count * 4);
    let limm = imm & !limm;
    Some(limm)
}
