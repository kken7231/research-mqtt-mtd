//! Defines Access Control List (ACL).

use crate::error::ACLError;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};

/// Access type which can be granted
#[derive(Debug, Deserialize, PartialEq)]
pub(crate) enum AccessType {
    PubOnly,
    SubOnly,
    PubSub,
}

/// Access Control List. Manages the scope of Publish/Subscribe access per topic
/// per user.
#[derive(Debug)]
pub(crate) struct AccessControlList {
    /// {Hostname: {Topic: AccessType}}
    hostnames: HashMap<String, HashMap<String, AccessType>>,
}

static EXPECTED_ACCESS_TYPES_FOR_SUB: [AccessType; 2] = [AccessType::SubOnly, AccessType::PubSub];
static EXPECTED_ACCESS_TYPES_FOR_PUB: [AccessType; 2] = [AccessType::PubOnly, AccessType::PubSub];

impl AccessControlList {
    /// Reads a yaml file at the given path and returns deserialized instance.
    pub(crate) fn from_yaml<P: AsRef<Path>>(path: P) -> Result<Self, ACLError> {
        // Open file
        let contents = fs::File::open(path).map_err(|e| ACLError::OpenYamlFailedError(e))?;

        // Parse the file into a HashMap
        let hostnames: HashMap<String, HashMap<String, AccessType>> =
            serde_yaml::from_reader(contents).map_err(|e| ACLError::ParseYamlFailedError(e))?;

        Ok(Self { hostnames })
    }

    /// Checks if the given access kind is allowed. True if allowed.
    pub(crate) fn check_if_allowed(
        &self,
        hostname: impl Into<String>,
        topic: impl Into<String>,
        access_is_pub: bool,
    ) -> bool {
        // Get a static reference to the "expected_access_types"
        let expected_access_types = if access_is_pub {
            &EXPECTED_ACCESS_TYPES_FOR_PUB
        } else {
            &EXPECTED_ACCESS_TYPES_FOR_SUB
        };

        // Return check result if the matched entry is present, otherwise false
        self.hostnames
            .get(&hostname.into())
            .and_then(|topics| topics.get(&topic.into()))
            .map_or(false, |access_type| {
                println!("{:?}, {:?}", access_type, expected_access_types);
                expected_access_types.contains(access_type)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, create_dir_all},
        io::ErrorKind,
    };

    use tempfile::tempdir;

    use crate::{acl::AccessControlList, error::ACLError, proc_println};

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
        proc_println!("{:?}", &acl);
        assert!(acl.is_ok());
        let acl = acl.unwrap();
        proc_println!("Successfully loaded hostnames:");
        for hostname_map in acl.hostnames {
            proc_println!("{:?}", hostname_map);
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
        proc_println!("{:?}", &acl);
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

    #[tokio::test]
    async fn from_yaml_non_existent_file() {
        // Yaml file not exist
        let temp_dir = tempdir().expect("failed to create temp dir").into_path();
        let non_existent_path = temp_dir.join("non_existent.yaml");

        let acl = AccessControlList::from_yaml(&non_existent_path);
        assert!(acl.is_err());
        let err = acl.unwrap_err();
        match err {
            ACLError::OpenYamlFailedError(e) => assert_eq!(e.kind(), ErrorKind::NotFound),
            _ => panic!("error type invalid"),
        }
    }

    #[tokio::test]
    async fn from_yaml_invalid_yaml_syntax() {
        // Invalid YAML
        let yaml_content = r#"
     client_a:
         topic/*: PubOnly
         invalid yaml syntax here: -
             "#;
        let temp_dir = tempdir().expect("failed to create temp dir").into_path();
        let temp_yaml = temp_dir.join("invalid_syntax.yaml");
        fs::write(&temp_yaml, yaml_content).expect("failed to write temp yaml");

        let acl = AccessControlList::from_yaml(&temp_yaml);
        assert!(acl.is_err());
        let err = acl.unwrap_err();
        match err {
            ACLError::ParseYamlFailedError(_e) => assert!(true),
            _ => panic!("invalid err"),
        }

        fs::remove_file(&temp_yaml).expect("failed to remove temp yaml");
    }

    #[tokio::test]
    async fn from_yaml_invalid_data_structure() {
        // YAML is valid, but the structure doesn't match HashMap<String,
        // HashMap<String, AccessType>>
        let yaml_content = r#"
     client_a: "just a string"
             "#;
        let temp_dir = tempdir().expect("failed to create temp dir").into_path();
        let temp_yaml = temp_dir.join("invalid_structure.yaml");
        fs::write(&temp_yaml, yaml_content).expect("failed to write temp yaml");

        let acl = AccessControlList::from_yaml(&temp_yaml);
        assert!(acl.is_err());
        let err = acl.unwrap_err();
        match err {
            ACLError::ParseYamlFailedError(_e) => assert!(true),
            _ => panic!("invalid err"),
        }

        fs::remove_file(&temp_yaml).expect("failed to remove temp yaml");
    }

    #[tokio::test]
    async fn check_if_allowed_edge_cases() {
        let yaml_content = r#"
     client_a:
         topic/*: PubOnly
     client_with_empty_topics: {}
             "#;
        let temp_dir = tempdir().expect("failed to create temp dir").into_path();
        let temp_yaml = temp_dir.join("edge_cases.yaml");
        fs::write(&temp_yaml, yaml_content).expect("failed to write temp yaml");

        let acl = AccessControlList::from_yaml(&temp_yaml).expect("failed to load acl");

        // Non-existent hostname
        assert_eq!(
            acl.check_if_allowed("non_existent_client", "some_topic", true),
            false
        );
        assert_eq!(
            acl.check_if_allowed("non_existent_client", "some_topic", false),
            false
        );

        // Existing hostname, non-existent topic
        assert_eq!(
            acl.check_if_allowed("client_a", "non_existent_topic", true),
            false
        );
        assert_eq!(
            acl.check_if_allowed("client_a", "non_existent_topic", false),
            false
        );

        // Existing hostname with empty topics map
        assert_eq!(
            acl.check_if_allowed("client_with_empty_topics", "some_topic", true),
            false
        );
        assert_eq!(
            acl.check_if_allowed("client_with_empty_topics", "some_topic", false),
            false
        );

        // Empty hostname or topic strings (should not panic, return false)
        assert_eq!(acl.check_if_allowed("", "some_topic", true), false);
        assert_eq!(acl.check_if_allowed("client_a", "", true), false);
        assert_eq!(acl.check_if_allowed("", "", true), false);

        fs::remove_file(&temp_yaml).expect("failed to remove temp yaml");
    }
}
