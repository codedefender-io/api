use bincode::{Decode, Encode};
use std::{
    collections::{HashMap, hash_map::Entry},
    io::Cursor,
};
use symbolic_common::Name;
use symbolic_demangle::{Demangle, DemangleOptions};
use pdb::FallibleIterator;

/// Info that is fed into decomposers. It is info about symbols within a binary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct DebugSymbolInfo {
    /// Address in the virtual mapping.
    pub address: u32,
    /// Yeah...
    pub name: String,
    /// Does this function not return?
    pub noreturn: bool,
}

pub fn parse_pdb(pdb_bytes: &[u8]) -> Option<Vec<u8>> {
    let Ok(funcs) = parse_pdb_impl(pdb_bytes) else {
        return None;
    };
    match bincode::encode_to_vec(&funcs, bincode::config::standard()) {
        Ok(serialized) => {
            // Compress the serialized bytes (level 3: balanced speed/compression)
            match zstd::encode_all(&*serialized, 3) {
                Ok(compressed) => Some(compressed),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

pub fn parse_pdb_impl(pdb_bytes: &[u8]) -> pdb::Result<Vec<DebugSymbolInfo>> {
    let pdb_cursor = Cursor::new(pdb_bytes);
    let mut pdb = pdb::PDB::open(pdb_cursor)?;
    // Use address-based map to collect unique functions, choosing min demangled name per address
    let mut functions: HashMap<u32, (String, bool)> = HashMap::default();
    let address_map = pdb.address_map()?;
    let debug_info = pdb.debug_information()?;
    let mut modules = debug_info.modules()?;
    while let Ok(Some(module)) = modules.next() {
        if let Some(info) = pdb.module_info(&module)? {
            let mut symbols = info.symbols()?;
            while let Ok(Some(sym)) = symbols.next() {
                match sym.parse() {
                    Ok(pdb::SymbolData::Procedure(data)) => {
                        if let Some(rva) = data.offset.to_rva(&address_map) {
                            let mangled = data.name.to_string().to_string();
                            let name_obj = Name::from(&mangled);
                            let demangled = name_obj
                                .try_demangle(DemangleOptions::complete())
                                .to_string();
                            match functions.entry(rva.0) {
                                Entry::Occupied(mut e) => {
                                    let (e_name, e_noreturn) = e.get_mut();
                                    if demangled < *e_name {
                                        *e_name = demangled;
                                    }
                                    *e_noreturn = *e_noreturn || data.flags.never;
                                }
                                Entry::Vacant(e) => {
                                    e.insert((demangled, data.flags.never));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    // Try and parse the public/global table now (for stripped PDB files)
    if let Ok(global_symbols) = pdb.global_symbols() {
        let mut symbols = global_symbols.iter();
        while let Ok(Some(symbol)) = symbols.next() {
            match symbol.parse() {
                Ok(pdb::SymbolData::Public(data)) if data.function => {
                    let rva = data.offset.to_rva(&address_map).unwrap_or_default();
                    let mangled = data.name.to_string().to_string();
                    let name_obj = Name::from(&mangled);
                    let demangled = name_obj
                        .try_demangle(DemangleOptions::complete())
                        .to_string();
                    match functions.entry(rva.0) {
                        Entry::Occupied(mut e) => {
                            let (e_name, _) = e.get_mut();
                            if demangled < *e_name {
                                *e_name = demangled;
                            }
                            // For globals, noreturn defaults to false, so no change needed
                        }
                        Entry::Vacant(e) => {
                            e.insert((demangled, false));
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Now handle name duplicates (same name, different addresses) with suffixes
    let mut name_counts: HashMap<String, u32> = HashMap::default();
    let mut funcs = Vec::with_capacity(functions.len());
    for (address, (name, noreturn)) in functions {
        let mut final_name = name.clone();
        match name_counts.entry(name) {
            Entry::Occupied(mut e) => {
                let count = *e.get();
                let new_count = count;
                *e.get_mut() += 1;
                final_name.push_str(&format!("_{:x}", new_count));
            }
            Entry::Vacant(e) => {
                e.insert(1); // Next duplicate starts at 0
            }
        }
        funcs.push(DebugSymbolInfo {
            address,
            name: final_name,
            noreturn,
        });
    }
    Ok(funcs)
}