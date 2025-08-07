use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// The security_test attribute macro
#[proc_macro_attribute]
pub fn security_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(item as ItemFn);
    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();

    // Convert attr to string for simple parsing
    let attr_str = attr.to_string();

    // Parse test types
    let sql_injection = attr_str.contains("sql_injection");
    let race_condition = attr_str.contains("race_condition");
    let timing_attack = attr_str.contains("timing_attack");
    let buffer_overflow = attr_str.contains("buffer_overflow");

    let threat_level = if attr_str.contains("critical") {
        "critical"
    } else if attr_str.contains("high") {
        "high"
    } else {
        "medium"
    };

    // Generate unique variable name
    let metadata_var_name = quote::format_ident!(
        "__SECURITY_TEST_METADATA_{}",
        fn_name.to_string().to_uppercase()
    );

    let expanded = quote! {
        #input_fn

        #[cfg_attr(target_os = "linux", link_section = ".security_tests")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__sectests")]
        #[cfg_attr(target_os = "windows", link_section = ".sectests")]
        #[used]
        static #metadata_var_name: [u8; 64] = [
            // Magic bytes (8 bytes)
            0xBE, 0xBA, 0xFE, 0xCA, 0xEF, 0xBE, 0xAD, 0xDE,
            // Function name length (1 byte)
            #fn_name_str.len() as u8,
            // Test flags (4 bytes)
            #sql_injection as u8,
            #race_condition as u8,
            #timing_attack as u8,
            #buffer_overflow as u8,
            // Threat level (1 byte: 0=low, 1=medium, 2=high, 3=critical)
            match #threat_level {
                "low" => 0u8,
                "medium" => 1u8,
                "high" => 2u8,
                "critical" => 3u8,
                _ => 1u8,
            },
            // Padding (remaining bytes zeroed)
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        // Also embed the function name as a separate static
        #[cfg_attr(target_os = "linux", link_section = ".security_names")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__secnames")]
        #[cfg_attr(target_os = "windows", link_section = ".secnames")]
        #[used]
        static #metadata_var_name _NAME: &'static str = #fn_name_str;
    };

    TokenStream::from(expanded)
}