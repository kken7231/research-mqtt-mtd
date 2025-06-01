use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, TypePath};

#[proc_macro_derive(ToStringLines)]
pub fn to_string_lines_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let ast = parse_macro_input!(input as DeriveInput);

    // Get the name of the struct
    let name = &ast.ident;

    // Get the fields from the struct. We only support named fields for this macro.
    let fields = if let Data::Struct(data_struct) = &ast.data {
        if let Fields::Named(fields_named) = &data_struct.fields {
            &fields_named.named
        } else {
            // Error out if it's not a struct with named fields
            return syn::Error::new_spanned(
                ast.ident,
                "ToHashMapString can only be derived for structs with named fields",
            )
            .to_compile_error()
            .into();
        }
    } else {
        // Error out if it's not a struct
        return syn::Error::new_spanned(
            ast.ident,
            "ToHashMapString can only be derived for structs",
        )
        .to_compile_error()
        .into();
    };

    // Generate the `.insert()` calls for each field.
    // Assumes each field's type implements Debug so we can use format!("{:?}")
    let insert_calls = fields.iter().map(|field| {
        let field_name_ident = field
            .ident
            .as_ref()
            .expect("Named fields should have an identifier");
        let field_name_str = field_name_ident.to_string(); // "field_name"

        // Generates: map.insert("field_name".to_string(), format!("{:?}",
        // self.field_name));
        quote! {
            map.insert(#field_name_str.to_string(), format!("{:?}", self.#field_name_ident));
        }
    });

    // Generate the final implementation block for the struct
    let generated = quote! {
        impl #name {
            #[allow(dead_code)]
            pub(crate) fn to_string_lines(&self, title: impl std::fmt::Display) -> Vec<String> {
                let mut map = std::collections::HashMap::new();
                #(#insert_calls)*
                let max_key_str_len = map.keys().map(|k|k.chars().count()).max().unwrap_or(0);
                let mut lines = Vec::<String>::with_capacity(map.len() + 2);
                lines.push(format!("--- {} configuration ---", title));
                for entry in map.iter() {
                    lines.push(format!(
                        "  {:width$}: {:?}",
                        entry.0,
                        entry.1,
                        width = max_key_str_len
                    ));
                }
                lines.push("-".repeat(lines.get(0).unwrap().len()));

                lines
            }
        }
    };

    // Return the generated code as a TokenStream
    generated.into()
}