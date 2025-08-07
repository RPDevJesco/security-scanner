use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

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
        0u8
    };

    // Generate unique variable names
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
        #input_fn

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

        //  store the function name in a separate section
        #[cfg_attr(target_os = "linux", link_section = ".security_names")]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__secnames")]
        #[cfg_attr(target_os = "windows", link_section = ".secnames")]
        #[used]
        static #name_var_name: &'static str = #fn_name_str;
    };

    TokenStream::from(expanded)
}