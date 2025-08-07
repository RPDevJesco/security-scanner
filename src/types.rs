use serde::{Serialize, Deserialize};

/// Security test metadata structure embedded in binary
#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SecurityTestMetadata {
    pub function_name: &'static str,
    pub function_address: usize,
    pub test_config: SecurityTestConfig,
    pub magic: u64, // For scanner discovery: 0xDEADBEEFCAFEBABE
}

#[derive(Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SecurityTestConfig {
    pub sql_injection: bool,
    pub race_condition: bool,
    pub timing_attack: bool,
    pub integer_overflow: bool,
    pub buffer_overflow: bool,
    pub input_params: Vec<String>,
    pub threat_level: String,
    pub compliance_tags: Vec<String>,
}