use regex::Regex;
use std::collections::HashMap;

use once_cell::sync::Lazy;

static ANNOTATION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?P<key>\w+)\s*=\s*"(?P<value>[^"]*)""#).unwrap());

static NAMESPACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"namespace\s+\w+\s+(?P<namespace>[\w.]+)").unwrap());

//service
static SERVICE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"service\s+(?P<service_name>\w+)\s*\{(?P<service_body>[^}]*)\}").unwrap()
});

// method
static METHOD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?P<return_type>\w+)\s+(?P<method_name>\w+)\s*\([^)]*\)\s*(?:\(\s*(?P<annotations>[^)]*)\s*\))?").unwrap()
});

#[derive(Debug)]
pub struct MethodConfiguration {
    return_type: String,
    pub annotations: HashMap<String, String>,
}

type MethodName = String;
#[derive(Debug)]
pub struct Service {
    pub methods: HashMap<MethodName, MethodConfiguration>,
}

// Function to parse annotations from strings like `scope="read" role="chef"`
fn parse_annotations(annotation_str: &str) -> HashMap<String, String> {
    let mut annotations = HashMap::new();
    for cap in ANNOTATION_RE.captures_iter(annotation_str) {
        if let (Some(key), Some(value)) = (cap.name("key"), cap.name("value")) {
            annotations.insert(key.as_str().to_string(), value.as_str().to_string());
        }
    }
    annotations
}

// Parse the Thrift file contents, extracting services, methods, and annotations
pub fn parse_thrift(file_contents: &str) -> Result<HashMap<String, Service>, String> {
    let content = file_contents;

    // Remove comments starting with "//"
    let comment_re = Regex::new(r"//.*$").or_else(|e| Err("error building regex"));
    let content = comment_re?.replace_all(&content, "");

    // Extract namespace
    let namespace = NAMESPACE_RE
        .captures(&content)
        .and_then(|cap| cap.name("namespace").map(|m| m.as_str().to_string()));

    // If namespace is not found, return an error
    let namespace = namespace.ok_or_else(|| "Namespace not found".to_string())?;

    // Extract services and methods

    let mut services = HashMap::new();

    // Iterate over services in the file
    for service_cap in SERVICE_RE.captures_iter(&content) {
        let service_name = &service_cap
            .name("service_name")
            .ok_or("Service name not found")?
            .as_str();
        let service_body = &service_cap
            .name("service_body")
            .ok_or("Service body not found")?
            .as_str();
        let mut methods = HashMap::new();

        // Iterate over methods for each service
        for method_cap in METHOD_RE.captures_iter(service_body) {
            let return_type = method_cap
                .name("return_type")
                .ok_or("Return type not found")?
                .as_str()
                .to_string();
            let method_name = method_cap
                .name("method_name")
                .ok_or("Method name not found")?
                .as_str()
                .to_string();
            let annotations = match method_cap.name("annotations").map(|m| m.as_str()) {
                Some(annotations) => parse_annotations(annotations),
                None => HashMap::with_capacity(0),
            };

            methods.insert(
                method_name.clone(),
                MethodConfiguration {
                    return_type,
                    annotations,
                },
            );
        }

        // Insert the service into the final collection
        services.insert(
            format!("{}.{}", namespace, service_name),
            Service { methods },
        );
    }

    Ok(services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_annotations_basic() {
        let input = r#"scope="read" role="chef""#;
        let annotations = parse_annotations(input);
        assert_eq!(annotations.get("scope"), Some(&"read".to_string()));
        assert_eq!(annotations.get("role"), Some(&"chef".to_string()));
    }

    #[test]
    fn test_parse_thrift_potato_service() {
        let thrift_content = r#"
        namespace go my.potato

        service PotatoService {
            string getPotato(1:string id) (scope="read")
            void mashPotato(1:string id, 2:i32 level) (scope="write" role="chef")
        }
    "#;

        let services = parse_thrift(thrift_content).expect("Failed to parse Thrift content");
        println!("services: {:?}", services.keys().collect::<Vec<_>>());
        let service = services
            .get("my.potato.PotatoService")
            .expect("Service not found");

        let get_potato = service
            .methods
            .get("getPotato")
            .expect("Method getPotato not found");
        assert_eq!(get_potato.return_type, "string");
        assert_eq!(
            get_potato.annotations.get("scope"),
            Some(&"read".to_string())
        );

        let mash_potato = service
            .methods
            .get("mashPotato")
            .expect("Method mashPotato not found");
        assert_eq!(mash_potato.return_type, "void");
        assert_eq!(
            mash_potato.annotations.get("scope"),
            Some(&"write".to_string())
        );
        assert_eq!(
            mash_potato.annotations.get("role"),
            Some(&"chef".to_string())
        );
    }

    #[test]
    fn test_parse_thrift_multiline_annotations() {
        let thrift_content = r#"
            namespace go my.potato
            service PotatoService {
                void bakePotato(
                    1:string type,
                    2:i32 temp
                ) (
                    scope = "oven",
                    role = "baker"
                )
            }
        "#;

        let services = parse_thrift(thrift_content).unwrap();
        let service = services.get("my.potato.PotatoService").unwrap();
        let method = service.methods.get("bakePotato").unwrap();

        assert_eq!(method.return_type, "void");
        assert_eq!(method.annotations.get("scope"), Some(&"oven".to_string()));
        assert_eq!(method.annotations.get("role"), Some(&"baker".to_string()));
    }

    #[test]
    fn test_parse_thrift_invalid_annotation_format() {
        let thrift_content = r#"
            namespace go my.potato
            service PotatoService {
                void explodePotato(1:string reason) (this_is_invalid)
            }
        "#;

        let services = parse_thrift(thrift_content).unwrap();
        let service = services.get("my.potato.PotatoService").unwrap();
        let method = service.methods.get("explodePotato").unwrap();

        assert_eq!(method.return_type, "void");
        assert!(method.annotations.is_empty());
    }

    #[test]
    fn test_parse_thrift_no_annotations() {
        let thrift_content = r#"
            namespace go my.potato
            service PotatoService {
                i32 boilPotato(1:i32 duration)
            }
        "#;

        let services = parse_thrift(thrift_content).unwrap();
        let service = services.get("my.potato.PotatoService").unwrap();
        let method = service.methods.get("boilPotato").unwrap();

        assert_eq!(method.return_type, "i32");
        assert!(method.annotations.is_empty());
    }

    #[test]
    fn test_parse_thrift_missing_namespace() {
        let thrift_content = r#"
            service PotatoService {
                bool isHot() (temperature="high")
            }
        "#;

        let result = parse_thrift(thrift_content);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Namespace not found");
    }
}
