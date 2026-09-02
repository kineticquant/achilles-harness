//! CycloneDX 1.5 JSON from lockfile inventory. Offline.

use serde_json::{json, Value};

use crate::types::PackageRef;

pub fn cyclonedx(packages: &[PackageRef]) -> Value {
    let components: Vec<Value> = packages
        .iter()
        .take(400)
        .map(|pkg| {
            json!({
                "type": "library",
                "name": pkg.name,
                "version": pkg.version,
                "bom-ref": format!("{}:{}@{}", pkg.ecosystem, pkg.name, pkg.version),
                "properties": [
                    {"name": "achilles:ecosystem", "value": pkg.ecosystem},
                    {"name": "achilles:source", "value": pkg.source},
                ]
            })
        })
        .collect();
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"name": "achilles-harness", "vendor": "Achilles"}]
        },
        "components": components
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_components() {
        let bom = cyclonedx(&[PackageRef {
            name: "left-pad".into(),
            version: "1.0.0".into(),
            ecosystem: "npm".into(),
            source: "package-lock.json".into(),
        }]);
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["components"].as_array().unwrap().len(), 1);
    }
}
