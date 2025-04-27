//! Defines Access Control List (ACL).

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Deserialize, PartialEq)]
pub enum AccessType {
    PubOnly,
    SubOnly,
    PubSub,
}

#[derive(Debug, Deserialize)]
pub struct HostnameEntry {
    pub topic: String,
    pub access: AccessType,
}

#[derive(Debug)]
pub struct AccessControlList {
    hostnames: HashMap<String, HashMap<String, AccessType>>,
}

impl AccessControlList {
    pub fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        let hostnames: HashMap<String, HashMap<String, AccessType>> =
            serde_yaml::from_str(&contents)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Self { hostnames })
    }

    pub fn check_if_allowed(
        &self,
        hostname: impl Into<String>,
        topic: impl Into<String>,
        access_is_pub: bool,
    ) -> bool {
        let expected_access_types = if access_is_pub {
            [AccessType::PubOnly, AccessType::PubSub]
        } else {
            [AccessType::SubOnly, AccessType::PubSub]
        };

        if let Some(topics) = self.hostnames.get(&hostname.into()) {
            if let Some(access_type) = topics.get(&topic.into()) {
                expected_access_types.contains(access_type)
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, create_dir_all};

    use tempfile::tempdir;

    use crate::acl::AccessControlList;

    #[test]
    fn load_pass() {
        // Create a sample YAML file
        let yaml_content = r#"
client_a:
    topic/*: PubOnly
    aa/#/aa: SubOnly
    topic_c/楠: PubSub
    another_topic: PubOnly
client_b:
    topic_a: PubOnly
    topic_b: SubOnly
    topic_c: PubSub
    another_topic: PubOnly
    "#;
        let temp_yaml = tempdir().expect("failed to create temp dir");
        let temp_yaml = temp_yaml.as_ref();
        if !temp_yaml.exists() {
            create_dir_all(&temp_yaml).expect("failed to create a parent directory");
        }
        let temp_yaml = temp_yaml.join("hostnames.yaml");
        assert!(fs::write(&temp_yaml, yaml_content).is_ok());

        // Load the hostnames from the YAML file
        let acl = AccessControlList::from_yaml(&temp_yaml);
        println!("{:?}", &acl);
        assert!(acl.is_ok());
        let acl = acl.unwrap();
        println!("Successfully loaded hostnames:");
        for hostname_map in acl.hostnames {
            println!("{:?}", hostname_map);
        }

        // Clean up the sample file
        assert!(fs::remove_file(&temp_yaml).is_ok());
    }

    #[test]
    fn allow_check_pass() {
        // Create a sample YAML file
        let yaml_content = r#"
client_a:
    topic/*: PubOnly
    aa/#/aa: SubOnly
    topic_c/楠: PubSub
    another_topic: PubOnly
client_b:
    topic_a: PubOnly
    topic_b: SubOnly
    topic_c: PubSub
    another_topic: PubOnly
    "#;
        let temp_yaml = tempdir().expect("failed to create temp dir");
        let temp_yaml = temp_yaml.as_ref();
        if !temp_yaml.exists() {
            create_dir_all(&temp_yaml).expect("failed to create a parent directory");
        }
        let temp_yaml = temp_yaml.join("hostnames.yaml");
        assert!(fs::write(&temp_yaml, yaml_content).is_ok());

        // Load the hostnames from the YAML file
        let acl = AccessControlList::from_yaml(&temp_yaml);
        println!("{:?}", &acl);
        assert!(acl.is_ok());
        let acl = acl.unwrap();

        assert_eq!(acl.check_if_allowed("client_a", "topic/*", true), true);
        assert_eq!(acl.check_if_allowed("client_a", "topic/*", false), false);
        assert_eq!(acl.check_if_allowed("client_a", "aa/#/aa", true), false);
        assert_eq!(acl.check_if_allowed("client_a", "aa/#/aa", false), true);
        assert_eq!(acl.check_if_allowed("client_a", "topic/mm", true), false);
        assert_eq!(acl.check_if_allowed("client_a", "topic_c/楠", true), true);

        // Clean up the sample file
        assert!(fs::remove_file(&temp_yaml).is_ok());
    }
}
