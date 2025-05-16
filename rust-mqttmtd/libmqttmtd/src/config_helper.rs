//! Defines a helper function to display config values.

use serde::Serialize;
use serde_yaml::Value;
use std::{collections::HashMap, fmt::Display};

pub fn display_config(
    title: impl Display,
    config: impl Serialize,
) -> Result<Vec<String>, serde_yaml::Error> {
    let mut fields_map: HashMap<String, Value> = HashMap::new();

    // Extract keys and values
    let value = serde_yaml::to_value(config)?;
    let mut max_key_str_len = 0usize;
    if let Value::Mapping(map) = value {
        for (key, val) in map {
            if let Some(key_str) = key.as_str() {
                // string key
                let key_str = key_str.to_string();
                let chars_count = key_str.chars().count();
                if max_key_str_len < chars_count {
                    max_key_str_len = chars_count;
                }
                fields_map.insert(key_str, val);
            }
        }
    }

    let mut lines = Vec::<String>::with_capacity(fields_map.len() + 2);
    lines.push(format!("--- {} configuration ---", title));
    for entry in fields_map.iter() {
        lines.push(format!(
            "  {:width$}: {:?}",
            entry.0,
            entry.1,
            width = max_key_str_len
        ));
    }
    lines.push("-".repeat(lines.get(0).unwrap().len()));

    Ok(lines)
}
