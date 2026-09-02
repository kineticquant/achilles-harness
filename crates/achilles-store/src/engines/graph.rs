//! v0 evidence graph: deploy surfaces ↔ findings that sit on those files.

use serde_json::{json, Value};

use crate::engines::fingerprint::Fingerprint;
use crate::types::Finding;

pub fn from_scan(fp: &Fingerprint, findings: &[Finding]) -> Value {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    for surface in &fp.surfaces {
        nodes.push(json!({
            "id": format!("surface:{}", surface.id),
            "kind": "surface",
            "label": surface.label,
            "paths": surface.paths,
        }));
    }
    for finding in findings
        .iter()
        .filter(|f| f.state == "open" || f.state == "confirmed")
    {
        nodes.push(json!({
            "id": format!("finding:{}", finding.id),
            "kind": "finding",
            "label": finding.title,
            "severity": finding.severity,
            "category": finding.category,
            "path": finding.path,
        }));
        if let Some(path) = &finding.path {
            let tree_path = path
                .strip_prefix("git:")
                .and_then(|rest| rest.split_once('/').map(|(_, p)| p))
                .unwrap_or(path.as_str());
            for surface in &fp.surfaces {
                if surface
                    .paths
                    .iter()
                    .any(|p| p == tree_path || tree_path.starts_with(p))
                {
                    edges.push(json!({
                        "from": format!("surface:{}", surface.id),
                        "to": format!("finding:{}", finding.id),
                        "kind": "on-surface",
                    }));
                }
            }
        }
    }
    json!({
        "nodes": nodes,
        "edges": edges,
        "note": "v0 file-overlap graph. Not a dataflow or attack-path proof."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::fingerprint::DetectedSurface;
    use crate::types::Finding;

    #[test]
    fn links_finding_on_surface_path() {
        let fp = Fingerprint {
            surfaces: vec![DetectedSurface {
                id: "docker".into(),
                label: "Docker".into(),
                paths: vec!["Dockerfile".into()],
            }],
        };
        let finding = Finding {
            id: "f1".into(),
            engagement_id: "e".into(),
            assessment_id: "a".into(),
            last_seen_assessment_id: "a".into(),
            fingerprint: "fp".into(),
            state: "open".into(),
            severity: "high".into(),
            confidence: "high".into(),
            category: "surface".into(),
            rule_id: "docker-user-root".into(),
            title: "USER root".into(),
            description: "root".into(),
            path: Some("Dockerfile".into()),
            line_start: Some(1),
            line_end: Some(1),
            cwe_json: json!([]),
            cve_json: json!([]),
            evidence_json: json!({}),
            first_seen_at: "t".into(),
            last_seen_at: "t".into(),
            status_reason: None,
        };
        let g = from_scan(&fp, &[finding]);
        assert_eq!(g["edges"].as_array().unwrap().len(), 1);
    }
}
