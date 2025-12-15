//! `codedefender-config` provides the Rust data structures used for serializing and deserializing
//! CodeDefender YAML configuration files and analysis results. These structures are used by both
//! the CodeDefender CLI and its backend services.
//!
//! This crate is intended to be consumed by tools that integrate with or generate CodeDefender config files.

use serde::{Deserialize, Serialize};

/// Current supported YAML config version.
pub const YAML_CONFIG_VERSION: &str = "1.0.6";

/// Available SIMD extension types used by mutation engines.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MutationEngineExtension {
    /// All base instructions
    Generic,
    /// All base instructions + Legacy SSE instructions up until SSE3
    SSE3,
    /// All base instructions + Legacy SSE instructions up until SSE4.2
    SSE42,
}

/// Supported PE environments.
#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PeEnvironment {
    /// User-mode PE (exe, dll)
    UserMode,
    /// Kernel-mode PE (sys)
    KernelMode,
    /// UEFI firmware image
    UEFI,
}

/// Configuration settings for lifting x86 instructions into IR.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LifterSettings {
    /// Whether to lift calls into IR.
    pub lift_calls: bool,
    /// Calling convention used for lifting, only `WindowsAbi`, and `Conservative` are supported.
    pub calling_convention: String,
    /// Max stack copy size in bytes when lifting.
    pub max_stack_copy_size: u32,
    /// Fallback: split on calls if lifting fails.
    pub split_on_calls_fallback: bool,
}

/// IR optimization settings.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OptimizationSettings {
    /// Enable constant propagation.
    pub constant_propagation: bool,
    /// Enable instruction combining.
    pub instruction_combine: bool,
    /// Enable dead code elimination.
    pub dead_code_elim: bool,
    /// Enable pruning of unused block parameters.
    pub prune_useless_block_params: bool,
    /// Number of optimization iterations to run.
    pub iterations: u32,
}

/// Assembler-level codegen settings.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AssemblerSettings {
    /// Whether to shuffle basic blocks.
    pub shuffle_basic_blocks: bool,
    /// Instruction prefix to prepend to emitted instructions.
    pub instruction_prefix: String,
    /// Chance of randomly applying the prefix.
    pub random_prefix_chance: f64,
}

/// Compiler configuration (IR + codegen) for a profile.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CompilerSettings {
    /// Assembler settings.
    pub assembler_settings: AssemblerSettings,
    /// Optimization settings.
    pub optimization_settings: OptimizationSettings,
    /// IR lifter settings.
    pub lifter_settings: LifterSettings,
}

/// Fake PDB string settings to confuse debuggers.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct FakePdbString {
    /// Whether the fake PDB string is enabled.
    pub enabled: bool,
    /// Value to emit as the fake PDB string.
    pub value: String,
}

/// Custom `.text` section name override.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct CustomSectionName {
    /// Whether this feature is enabled.
    pub enabled: bool,
    /// Custom section name value.
    pub value: String,
}

/// Global obfuscation settings for the module.
#[derive(Debug, Serialize, Deserialize)]
pub struct ModuleSettings {
    /// Whether to crash the IDA decompiler intentionally.
    #[serde(default)]
    pub ida_crasher: bool,
    /// Whether to enable IAT/Import protection.
    #[serde(default)]
    pub import_protection: bool,
    /// Should the output file be packed/compressed? This option only works for usermode modules.
    #[serde(default)]
    pub pack_output_file: bool,
    /// Obscure the entry point of the module with anti tamper and anti debug tactics
    #[serde(default)]
    pub obscure_entry_point: bool,
    /// Clear unwind information. makes it harder for attackers to locate functions, however
    /// structured exception handling will not work.
    #[serde(default)]
    pub clear_unwind_info: bool,
    /// Fake PDB string settings.
    #[serde(default)]
    pub fake_pdb_string: FakePdbString,
    /// Custom PE section name settings.
    #[serde(default)]
    pub custom_section_name: CustomSectionName,
}

/// Instruction-level semantics used in transformations.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Semantics {
    #[serde(default)]
    pub add: bool,
    #[serde(default)]
    pub sub: bool,
    #[serde(default)]
    pub and: bool,
    #[serde(default)]
    pub xor: bool,
    #[serde(default)]
    pub or: bool,
    #[serde(default)]
    pub not: bool,
    #[serde(default)]
    pub neg: bool,
}

/// Bit widths to apply transformations to.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BitWidths {
    #[serde(default)]
    pub bit8: bool,
    #[serde(default)]
    pub bit16: bool,
    #[serde(default)]
    pub bit32: bool,
    #[serde(default)]
    pub bit64: bool,
}

/// The origin of SSA value from within the instruction.
/// Please refer to this documentation for more info:
/// https://docs.codedefender.io/features/ethnicity
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SsaOrigins {
    pub normal: bool,
    pub memop: bool,
    pub fp_based_memop: bool,
    pub sp_based_memop: bool,
}

/// Configuration for the Loop Encode Semantics pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LoopEncodeSemantics {
    /// Number of times to attempt transformation.
    pub iterations: u32,
    /// Percent chance to apply transformation (0–100).
    pub probability: u32,
    /// Instruction semantics to consider.
    pub semantics: Semantics,
    /// Bit widths to target.
    pub bitwidths: BitWidths,
    pub ethnicities: SsaOrigins,
}

/// Configuration for Mixed Boolean Arithmetic pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MixedBooleanArithmetic {
    pub iterations: u32,
    pub probability: u32,
    pub semantics: Semantics,
    pub bitwidths: BitWidths,
    pub ethnicities: SsaOrigins,
}

/// Configuration for Mutation Engine pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MutationEngine {
    pub iterations: u32,
    pub probability: u32,
    pub extension: MutationEngineExtension,
    pub semantics: Semantics,
    pub bitwidths: BitWidths,
    pub ethnicities: SsaOrigins,
}

/// Pass that crashes IDA’s decompiler.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IDADecompilerCrasher;

/// Suppress constants and prevent them from rematerializing at runtime.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuppressConstants {
    pub mba_enhance: bool,
    pub ethnicities: SsaOrigins,
}

/// Statically obscure constants, this does not prevent rematerialization at runtime.
/// Use the SuppressConstants pass in tandem with this!
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObscureConstants {
    pub mba_enhance: bool,
    pub probability: u32,
    pub iterations: u32,
    pub bitwidths: BitWidths,
    pub ethnicities: SsaOrigins,
}

/// Memory reference obfuscation pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObscureReferences {
    pub mba_enhance: bool,
}

/// Control-flow obfuscation pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ObscureControlFlow {
    pub mba_enhance: bool,
    pub probability: u32,
}

/// Tether extraction pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TetherExtraction {
    /// Min length of a sequence of instructions that should be extracted.
    /// Its a bad idea for this to be 1 usually because its easy to synthesize
    pub min_extract_len: usize,
    /// Tether server endpoint
    pub endpoint: String,
    /// Tether server port
    pub port: u16,
    /// Hex string of the servers public key. This is used for public key pinning.
    /// This needs to be length 64...
    pub server_public_key: String,
}

/// Opaque block duplication pass.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OpaqueBlockDuplication {
    /// Number of iterations to attempt transformation.
    pub iterations: u32,
    /// Percent chance to apply transformation (0–100).
    pub probability: u32,
}

/// Split block pass, used to create more control flow points for other passes to transform.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SplitBlockPass {
    /// The number of SSA values required to be within a block for it to be split into two seperate blocks.
    pub threshold: u32,
}

/// Encode immediate ssa values into lea's
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LeaEncodeImm {
    pub mba_enhance: bool,
    /// Number of iterations to attempt transformation.
    pub iterations: u32,
    /// Percent chance to apply transformation (0–100).
    pub probability: u32,
    pub ethnicities: SsaOrigins,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SigBreaker {
    pub shuffle_insts: bool,
    pub random_segment_selector: bool,
    /// Calling convention used for lifting, only `WindowsAbi`, and `Conservative` are supported.
    pub calling_convention: String,
    pub shuffle_opcodes: bool,
    pub instruction_substitution: bool,
}

/// All possible obfuscation passes.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum ObfuscationPass {
    LoopEncodeSemantics(LoopEncodeSemantics),
    MixedBooleanArithmetic(MixedBooleanArithmetic),
    MutationEngine(MutationEngine),
    TetherExtraction(TetherExtraction),
    SplitBlockPass(SplitBlockPass),
    OpaqueBlockDuplication(OpaqueBlockDuplication),
    ObscureControlFlow(ObscureControlFlow),
    LeaEncodeImm(LeaEncodeImm),
    ObscureConstants(ObscureConstants),
    SuppressConstants(SuppressConstants),
    ObscureReferences(ObscureReferences),
    SigBreaker(SigBreaker),
    IDADecompilerCrasher,
    AntiEmulator,
}

/// Profile definition used to apply passes to symbols.
#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Name of the profile.
    pub name: String,
    /// Obfuscation passes for this profile.
    pub passes: Vec<ObfuscationPass>,
    /// Compiler settings for this profile.
    pub compiler_settings: CompilerSettings,
    /// List of symbol RVAs this profile targets.
    pub symbols: Vec<u64>,
}

/// Top-level config file structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Module-wide settings.
    pub module_settings: ModuleSettings,
    /// All profiles to apply during obfuscation.
    pub profiles: Vec<Profile>,
}

/// Information about a single function found during analysis.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnalysisFunction {
    /// RVA of the function.
    pub rva: u64,
    /// Function name.
    pub symbol: String,
    /// Number of references to this function.
    pub ref_count: usize,
}

/// Reason why a function was rejected from analysis.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnalysisReject {
    /// RVA of the rejected function.
    pub rva: u64,
    /// Symbol name.
    pub symbol: String,
    /// Mnemonic reason string (e.g., internal enum).
    pub ty: String,
    /// Stringified reason (human-readable).
    pub reason: String,
}

/// Grouping of functions under a named macro profile.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnalysisMacroProfile {
    /// Name of the macro profile.
    pub name: String,
    /// List of function RVAs in this macro.
    pub rvas: Vec<u64>,
}

/// Results from binary analysis, returned to the frontend.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct AnalysisResult {
    /// Environment type (UserMode, KernelMode, UEFI).
    pub environment: PeEnvironment,
    /// Functions found during analysis.
    pub functions: Vec<AnalysisFunction>,
    /// Rejected functions and reasons.
    pub rejects: Vec<AnalysisReject>,
    /// Macro profiles generated from analysis.
    pub macros: Vec<AnalysisMacroProfile>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DisassemblySettings {
    pub allow_code_reads_and_writes: bool,
    pub allow_unknown_indirect_jumps: bool,
    pub allow_mismatched_branch_counts: bool,
    pub thunk_mismatched_branch_counts: bool,
    pub thunk_branch_target_identifiers: bool,
    pub thunk_no_prev_block: bool,
    pub thunk_data_references: bool,
    pub always_thunk_entry: bool,
    pub follow_faulting_instructions: bool,
    pub pass_interrupts: bool,
    pub pass_exceptions: bool,
    pub aggressive_pointer_analysis: bool,
    pub perform_relocation_analysis: bool,
    pub explore_catch_funclet_continuations: bool,
}

/// Symbol representation used in YAML: either name or RVA.
#[derive(Debug, Serialize, Deserialize)]
pub enum YamlSymbol {
    /// Symbol name
    Name(String),
    /// Symbol RVA.
    Rva(u64),
    /// All Symbols
    All,
}

/// Obfuscation profile for YAML configuration.
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlProfile {
    /// Profile name (referenced by source macros).
    pub name: String,
    /// Passes to apply to this profile.
    pub passes: Vec<ObfuscationPass>,
    /// Compiler configuration for this profile.
    pub compiler_settings: CompilerSettings,
    /// Symbols targeted by this profile.
    pub symbols: Vec<YamlSymbol>,
}

/// Root YAML config structure.
#[derive(Debug, Serialize, Deserialize)]
pub struct YamlConfig {
    /// Version of the config file format.
    pub version: String,
    /// The global disassembly settings.
    pub disassembly_settings: DisassemblySettings,
    /// Global module-wide obfuscation settings.
    pub module_settings: ModuleSettings,
    /// Obfuscation profiles to apply.
    pub profiles: Vec<YamlProfile>,
}
