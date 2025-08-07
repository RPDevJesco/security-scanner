//! # Security Scanner
//!
//! Embedded security testing framework for Rust applications.
//!
//! This crate provides the `#[security_test]` attribute macro that allows developers
//! to embed security test metadata directly in their functions. External security
//! scanners can then discover this metadata and perform targeted vulnerability testing.
//!
//! ## Example
//!
//! ```rust
//! use security_scanner::security_test;
//!
//! #[security_test(sql_injection, timing_attack, critical)]
//! fn authenticate_user(username: &str, password: &str) -> bool {
//!     // Potentially vulnerable authentication logic
//!     let query = format!("SELECT * FROM users WHERE username = '{}'", username);
//!     // ... rest of function
//!     true
//! }
//! ```

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Embeds security test metadata in Rust functions for automated vulnerability scanning.
///
/// This attribute macro allows developers to specify what types of security tests
/// should be performed on a function, along with the threat level.
///
/// ## Supported Test Types
///
/// - `sql_injection` - Tests for SQL injection vulnerabilities
/// - `race_condition` - Tests for race condition vulnerabilities
/// - `timing_attack` - Tests for timing side-channel attacks
/// - `buffer_overflow` - Tests for buffer overflow vulnerabilities
///
/// ## Threat Levels
///
/// - `critical` - Critical security function (authentication, payment, etc.)
/// - `high` - High-risk function (user data access, admin operations)
/// - `medium` - Medium-risk function (data processing, business logic)
/// - `low` - Low-risk function (logging, display, etc.)
///
/// ## Examples
///
/// ```rust
/// use security_scanner::security_test;
///
/// // Basic security testing
/// #[security_test]
/// fn process_data(data: &str) -> String {
///     data.to_string()
/// }
///
/// // Specific vulnerability tests
/// #[security_test(sql_injection)]
/// fn query_database(user_input: &str) -> Vec<String> {
///     // Potentially vulnerable to SQL injection
///     vec![]
/// }
///
/// // Multiple tests with threat level
/// #[security_test(sql_injection, timing_attack, critical)]
/// fn authenticate(username: &str, password: &str) -> bool {
///     // Critical authentication function
///     true
/// }
///
/// // Race condition testing
/// #[security_test(race_condition, high)]
/// fn transfer_funds(from: u64, to: u64, amount: f64) -> Result<(), String> {
///     // High-risk financial operation
///     Ok(())
/// }
/// ```
#[proc_macro_attribute]
pub fn security_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Convert attr to string for simple parsing
    let attr_str = attr.to_string();

    // Parse test types
    let sql_injection = if attr_str.contains("sql_injection") { 1u8 } else { 0u8 };
    let race_condition = if attr_str.contains("race_condition") { 1u8 } else { 0u8 };
    let timing_attack = if attr_str.contains("timing_attack") { 1u8 } else { 0u8 };
    let buffer_overflow = if attr_str.contains("buffer_overflow") { 1u8 } else { 0u8 };

    let threat_level = if attr_str.contains("critical") {
        3u8
    } else if attr_str.contains("high") {
        2u8
    } else if attr_str.contains("medium") {
        1u8
    } else {
        0u8 // low (default)
    };

    // Generate unique variable names for this function
    let metadata_var_name = quote::format_ident!(
        "__SEC_TEST_{}",
        fn_name.to_string().to_uppercase()
    );

    let name_var_name = quote::format_ident!(
        "__SEC_NAME_{}",
        fn_name.to_string().to_uppercase()
    );

    let fn_name_len = fn_name_str.len();

    let expanded = quote! {
        // Original function unchanged
        #input_fn

        // Embed raw security test metadata in binary sections
        #[cfg_attr(target_os = "linux", link_section = ".security_tests")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__sectests")]
        #[cfg_attr(target_os = "windows", link_section = ".sectests")]
        #[used]
        static #metadata_var_name: [u8; 64] = [
            // Magic bytes (8 bytes) - 0xDEADBEEFCAFEBABE
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
            // Function name length (1 byte)
            #fn_name_len as u8,
            // Test flags (4 bytes)
            #sql_injection, #race_condition, #timing_attack, #buffer_overflow,
            // Threat level (1 byte)
            #threat_level,
            // Padding to 64 bytes (fill rest with zeros)
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
            0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        ];

        // Also store the function name in a separate section for easy lookup
        #[cfg_attr(target_os = "linux", link_section = ".security_names")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__secnames")]
        #[cfg_attr(target_os = "windows", link_section = ".secnames")]
        #[used]
        static #name_var_name: &'static str = #fn_name_str;
    };

    TokenStream::from(expanded)
}