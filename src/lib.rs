// src/lib.rs - Proc-macro that generates structs inline
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// The main security_test attribute macro
#[proc_macro_attribute]
pub fn security_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Parse the security test configuration from attribute
    let test_config = parse_security_config(attr);

    // Generate unique identifier for this test
    let test_metadata_name = quote::format_ident!(
        "__SECURITY_TEST_METADATA_{}",
        fn_name.to_string().to_uppercase()
    );

    let expanded = quote! {
        // Keep the original function unchanged
        #input_fn

        // Define the structs inline (only once per compilation unit)
        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct __SecurityTestConfig {
            sql_injection: bool,
            race_condition: bool,
            timing_attack: bool,
            integer_overflow: bool,
            buffer_overflow: bool,
            threat_level: &'static str,
        }

        #[allow(non_camel_case_types)]
        #[repr(C)]
        struct __SecurityTestMetadata {
            function_name: &'static str,
            function_address: usize,
            test_config: __SecurityTestConfig,
            magic: u64,
        }

        // Embed security test metadata in a special section
        #[cfg_attr(target_os = "linux", link_section = ".security_tests")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__sec_tests")]
        #[cfg_attr(target_os = "windows", link_section = ".sectests")]
        #[used]
        static #test_metadata_name: __SecurityTestMetadata = __SecurityTestMetadata {
            function_name: #fn_name_str,
            function_address: #fn_name as *const fn() as usize,
            test_config: #test_config,
            magic: 0xDEADBEEFCAFEBABE,
        };
    };

    TokenStream::from(expanded)
}

fn parse_security_config(attr: TokenStream) -> proc_macro2::TokenStream {
    if attr.is_empty() {
        // Default configuration
        return quote! {
            __SecurityTestConfig {
                sql_injection: false,
                race_condition: false,
                timing_attack: false,
                integer_overflow: false,
                buffer_overflow: false,
                threat_level: "medium",
            }
        };
    }

    let attr_str = attr.to_string();

    // Simple string-based parsing
    let sql_injection = attr_str.contains("sql_injection");
    let race_condition = attr_str.contains("race_condition");
    let timing_attack = attr_str.contains("timing_attack");
    let integer_overflow = attr_str.contains("integer_overflow");
    let buffer_overflow = attr_str.contains("buffer_overflow");

    let threat_level = if attr_str.contains("critical") {
        "critical"
    } else if attr_str.contains("high") {
        "high"
    } else if attr_str.contains("low") {
        "low"
    } else {
        "medium"
    };

    quote! {
        __SecurityTestConfig {
            sql_injection: #sql_injection,
            race_condition: #race_condition,
            timing_attack: #timing_attack,
            integer_overflow: #integer_overflow,
            buffer_overflow: #buffer_overflow,
            threat_level: #threat_level,
        }
    }
}