use crate::decision_tree;
use crate::decision_tree::DecisionTree;
use crate::decision_tree::DecisionTreeNode;
use disarm64_defn::deser::Insn;
use proc_macro2::Literal;
use proc_macro2::TokenStream;
use quote::format_ident;
use std::collections::HashMap;
use std::collections::HashSet;
use std::io::Write;
use std::rc::Rc;

fn write_prelude(_decision_tree: &DecisionTree, f: &mut impl Write) -> std::io::Result<()> {
    writeln!(
        f,
        r#"// Auto-generated.
// The changes will be LOST.
"#
    )?;
    writeln!(f, "{}", include_str!("c_defs.h"))?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
struct Mask(u32);

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
struct Opcode(u32);

fn write_insn_structs(
    decision_tree: &DecisionTree,
    f: &mut impl Write,
) -> std::io::Result<HashMap<(Opcode, Mask), String>> {
    fn collect_insns_recursive(decision_tree: &DecisionTree, insns: &mut Vec<Rc<Insn>>) {
        if decision_tree.is_none() {
            return;
        }

        match decision_tree.as_ref().unwrap().as_ref() {
            DecisionTreeNode::Leaf {
                insns: leaf_insns, ..
            } => {
                for leaf_insn in leaf_insns {
                    insns.push(leaf_insn.insn.clone());
                }
            }
            DecisionTreeNode::Branch { zero, one, .. } => {
                collect_insns_recursive(zero, insns);
                collect_insns_recursive(one, insns);
            }
        }
    }

    let mut insns = Vec::new();
    collect_insns_recursive(decision_tree, &mut insns);
    insns.sort_by_key(|insn| insn.mnemonic.clone());
    let mnemonics = insns
        .iter()
        .map(|x| x.mnemonic.clone().to_lowercase().replace('.', "_"))
        .collect::<HashSet<_>>();
    let mut mnemonics = Vec::from_iter(mnemonics);
    mnemonics.sort();
    let mnemonics = mnemonics
        .into_iter()
        .map(|x| format!("{x}"))
        .collect::<Vec<_>>();

    let mut struct_definitions = vec![];
    let mut struct_impls = vec![];

    let mut mnemonic_definitions = vec![];
    mnemonic_definitions.push("typedef enum DA64_Mnemonic DA64_Mnemonic;".to_owned());
    mnemonic_definitions.push("enum DA64_Mnemonic {".to_owned());
    mnemonic_definitions.extend(mnemonics.iter().map(|m| format!("    DA64_Mnemonic_{m},")));
    mnemonic_definitions.push("};".to_owned());

    struct_definitions.extend_from_slice(&mnemonic_definitions);

    let mut used_names = std::collections::HashSet::new();
    let mut opcode_to_used_name = std::collections::HashMap::new();
    let mut classes = HashMap::new();

    // Collect all struct names and their impl data for batched macro invocations
    let mut all_struct_names: Vec<proc_macro2::Ident> = Vec::new();

    for (_index, insn) in insns.iter().enumerate() {
        let mut opcode_struct_name = insn.mnemonic.to_string();
        opcode_struct_name.make_ascii_uppercase();

        let mut opcode_struct_name = opcode_struct_name.replace('.', "_");
        let base_opcode_struct_name = opcode_struct_name.clone();
        {
            for operand in insn.operands.iter() {
                opcode_struct_name.push_str(&format!("_{:?}", operand.kind));
            }

            if !used_names.contains(&opcode_struct_name) {
                used_names.insert(opcode_struct_name.clone());
            } else {
                opcode_struct_name.clone_from(&base_opcode_struct_name);
                for operand in insn.operands.iter() {
                    opcode_struct_name.push_str(&format!("_{:?}", operand.kind));
                    if !operand.qualifiers.is_empty() {
                        opcode_struct_name.push_str(&format!("_{:?}", operand.qualifiers[0]));
                    }
                }
                if !used_names.contains(&opcode_struct_name) {
                    used_names.insert(opcode_struct_name.clone());
                } else {
                    opcode_struct_name.push_str(&format!("_{:08x}", insn.opcode));
                    used_names.insert(opcode_struct_name.clone());
                }
            }
        }
        opcode_to_used_name.insert(
            (Opcode(insn.opcode), Mask(insn.mask)),
            opcode_struct_name.clone(),
        );

        if let std::collections::hash_map::Entry::Vacant(e) = classes.entry(insn.class) {
            e.insert(vec![opcode_struct_name.clone()]);
        } else {
            classes
                .get_mut(&insn.class)
                .unwrap()
                .push(opcode_struct_name.clone());
        }

        let opcode_struct_name_ident = format_ident!("{}", opcode_struct_name);
        let opcode_hex: TokenStream = format!("{:#08x}", insn.opcode).parse().unwrap();
        let mask_hex: TokenStream = format!("{:#08x}", insn.mask).parse().unwrap();
        let mnemonic = insn.mnemonic.as_str();
        let feature_set = format!("DA64_InsnFeatureSet_{}", insn.feature_set.to_string());
        let class = format_ident!("{}", insn.class.to_string());

        let mut insn_operands = Vec::new();
        for operand in insn.operands.iter() {
            let kind = format_ident!("{}", format!("{:?}", operand.kind));
            let class = format_ident!("{}", format!("{:?}", operand.class));
            let qualifiers: Vec<String> = operand
                .qualifiers
                .iter()
                .map(|q| format!("DA64_InsnOperandQualifier_{q:?}"))
                .collect();
            let bit_fields: Vec<String> = operand
                .bit_fields
                .iter()
                .map(|bf| {
                    let bf_name = format_ident!("{}", format!("{:?}", bf.bitfield));
                    let lsb = Literal::u8_unsuffixed(bf.lsb);
                    let width = Literal::u8_unsuffixed(bf.width);
                    format!(" {{ DA64_InsnBitField_{bf_name}, {lsb}, {width} }}")
                })
                .collect();

            let qualifier_count = qualifiers.len();
            let qualifiers_formatted = qualifiers.join(",");

            let bitfield_count = bit_fields.len();
            let bitfields_formatted = bit_fields.join(",");

            insn_operands.push(format!(
                "
            {{
                .kind = DA64_InsnOperandKind_{kind},
                .class = DA64_InsnOperandClass_{class},
                .qualifiers = (DA64_InsnOperandQualifier[]){{ {qualifiers_formatted} }},
                .qualifier_count = {qualifier_count},
                .bit_fields = (DA64_BitfieldSpec[]){{ {bitfields_formatted} }},
                .bit_field_count = {bitfield_count},
            }}"
            ));
        }

        // Serialize flags to STRING
        let mut flags = Vec::new();
        for flag in insn.flags.iter() {
            // TODO(yuraiz): use normal flag name
            let str_flag = format!("0x{flag:x}");
            flags.push(str_flag);
        }

        let flags: String = if flags.is_empty() {
            "DA64_InsnFlag_EMPTY".to_owned()
        } else {
            flags.join("|")
        };

        all_struct_names.push(opcode_struct_name_ident.clone());

        let mnemonic_ident = format!("DA64_Mnemonic_{}", mnemonic.replace('.', "_"));
        let mnemonic_len = mnemonic.len();

        let operands_formatted = insn_operands.join(",");
        let operand_count = insn_operands.len();

        struct_impls.push(format!(
            "
        
static const DA64_Insn {opcode_struct_name_ident}_DEFINITION = {{
    .mnemonic = {mnemonic:?},
    .mnemonic_size = {mnemonic_len},
    .aliases = 0,
    .alias_count = 0,
    .opcode = {opcode_hex},
    .mask = {mask_hex},
    .class = DA64_InsnClass_{class},
    .feature_set = {feature_set},
    .operands = (DA64_InsnOperand[]) {{ {operands_formatted} }},
    .operand_count = {operand_count},
    .flags = {flags},
}};


DA64_Opcode DA64_{opcode_struct_name_ident}_make_opcode(da64_u32 bits) {{
    DA64_Opcode result = {{
        .mnemonic = {mnemonic_ident},
        .operation = DA64_Operation_{class},
        .ident = DA64_InsnIdent_{opcode_struct_name},
        .definition = &{opcode_struct_name_ident}_DEFINITION,
        .bits = bits,
    }};
    return result;
}}        
        "
        ));
    }

    // Emit batched struct type definitions via macro

    struct_definitions.push(format!("typedef enum DA64_InsnIdent DA64_InsnIdent;"));
    struct_definitions.push(format!("enum DA64_InsnIdent {{"));
    struct_definitions.extend(
        all_struct_names
            .iter()
            .map(|name| format!("DA64_InsnIdent_{name},")),
    );

    struct_definitions.push(format!("}};"));

    // Emit batched impl blocks via macro (after enums are defined)

    let mut sorted_classes = classes.keys().collect::<Vec<_>>();
    sorted_classes.sort_by_key(|x| x.to_string());

    let classes_idents = sorted_classes
        .iter()
        .map(|class| format_ident!("{}", format!("{:?}", class)))
        .collect::<Vec<_>>();

    writeln!(f, "{}", struct_definitions.join("\n"))?;

    writeln!(f, "typedef enum DA64_Operation DA64_Operation;")?;
    writeln!(f, "enum DA64_Operation {{")?;
    for ident in classes_idents {
        writeln!(f, "DA64_Operation_{ident},")?;
    }
    writeln!(f, "}};")?;

    writeln!(
        f,
        "{}",
        "
typedef struct DA64_Opcode DA64_Opcode;
struct DA64_Opcode {
    DA64_Mnemonic    mnemonic;
    DA64_Operation   operation;
    DA64_InsnIdent   ident;
    const DA64_Insn *definition;
    da64_u32         bits;
};
    "
    )?;

    writeln!(f, "{}", struct_impls.join("\n"))?;

    Ok(opcode_to_used_name)
}

fn decision_tree_to_rust_recursive_conditionals(
    decision_tree: &DecisionTree,
    opcode_to_used_name: &HashMap<(Opcode, Mask), String>,
) -> Vec<String> {
    let mut tokens = vec![];
    if decision_tree.is_none() {
        return tokens;
    }

    match decision_tree.as_ref().unwrap().as_ref() {
        DecisionTreeNode::Leaf { insns, .. } => {
            for insn in insns {
                let opcode_hex = format!("{:#08x}", insn.insn.opcode);
                let mask_hex = format!("{:#08x}", insn.insn.mask);
                let opcode_type = format_ident!(
                    "{}",
                    opcode_to_used_name[&(Opcode(insn.insn.opcode), Mask(insn.insn.mask))]
                );

                if insn.insn.mask == !0 {
                    tokens.push(format!("if(insn == {opcode_hex}) {{"));
                    // tokens.push(format!("printf(\"{opcode_type}\\n\");"));
                    tokens.push(format!("return DA64_{opcode_type}_make_opcode(insn);"));
                    tokens.push(format!("}}"));
                } else {
                    tokens.push(format!("if((insn & {mask_hex}) == {opcode_hex}) {{"));
                    // tokens.push(format!("printf(\"{opcode_type}\\n\");"));
                    tokens.push(format!("return DA64_{opcode_type}_make_opcode(insn);"));
                    tokens.push(format!("}}"));
                }
            }

            tokens
        }
        DecisionTreeNode::Branch {
            decision_bit,
            zero,
            one,
            ..
        } => {
            let zero_branch =
                decision_tree_to_rust_recursive_conditionals(zero, opcode_to_used_name);
            let one_branch = decision_tree_to_rust_recursive_conditionals(one, opcode_to_used_name);
            let decision_mask_lit: TokenStream =
                format!("{:#08x}", 1 << *decision_bit).parse().unwrap();

            tokens.push(format!("if((insn & {decision_mask_lit}) == 0) {{"));
            tokens.extend(zero_branch);
            tokens.push(format!("}} else {{"));
            tokens.extend(one_branch);
            tokens.push(format!("}}"));
            tokens
        }
    }
}

pub fn decision_tree_to_c(
    decision_tree: &DecisionTree,
    decision_tree_indexing: decision_tree::DecisionTreeIndexing,
    f: &mut impl Write,
) -> std::io::Result<()> {
    let mut f = std::io::BufWriter::new(f);

    write_prelude(decision_tree, &mut f)?;

    let opcode_to_used_name = write_insn_structs(decision_tree, &mut f)?;
    let decoder = match decision_tree_indexing {
        decision_tree::DecisionTreeIndexing::None => {
            decision_tree_to_rust_recursive_conditionals(decision_tree, &opcode_to_used_name)
        }
        decision_tree::DecisionTreeIndexing::DFS | decision_tree::DecisionTreeIndexing::BFS => {
            unimplemented!();
        }
    };

    writeln!(
        f,
        "
DA64_Opcode da64_decode(da64_u32 insn) {{
    {}
    DA64_Opcode error = {{ 0 }};
    printf(\"Failed to decode %lx\\n\", insn);
    return error;
}}
",
        decoder.join("\n")
    )
}
