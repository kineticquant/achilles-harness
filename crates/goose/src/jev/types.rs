//! Typed SystemOne API shapes (TypeSafe AI): questions, answers, usage.
//!
//! Mirrors the contract in <https://docs.typesafe.ai/api>. `Value` is used for
//! `state`, `instructions`, and `criteria` payloads because the API accepts
//! strings, objects, and arrays in those positions.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Request body for `POST {endpoint}`: unstructured `state` plus typed `questions`.
#[derive(Debug, Clone, Serialize)]
pub struct SystemOneRequest {
    pub state: Value,
    pub model: String,
    pub questions: BTreeMap<String, Question>,
}

/// One typed question. The key it is stored under is chosen by the caller and
/// is not sent to the model; answers come back under the same key.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Question {
    /// Pick one option from `criteria` (option -> rubric description).
    Choice {
        instructions: Value,
        criteria: BTreeMap<String, Value>,
    },
    /// Rate along ordered `criteria` levels.
    Score {
        instructions: Value,
        criteria: Vec<Value>,
    },
    /// Probability the statement in `instructions` is true.
    Noul { instructions: Value },
}

impl Question {
    /// `instructions` and rubric descriptions accept strings, objects, or arrays.
    pub fn choice(instructions: impl Into<Value>, criteria: BTreeMap<String, Value>) -> Self {
        Self::Choice {
            instructions: instructions.into(),
            criteria,
        }
    }

    /// `criteria` is an ordered list of level descriptions.
    pub fn score(instructions: impl Into<Value>, criteria: Vec<Value>) -> Self {
        Self::Score {
            instructions: instructions.into(),
            criteria,
        }
    }

    pub fn noul(instructions: impl Into<Value>) -> Self {
        Self::Noul {
            instructions: instructions.into(),
        }
    }
}

/// Response body: one typed answer per question, keyed by question id.
#[derive(Debug, Clone, Deserialize)]
pub struct SystemOneResponse {
    pub model: String,
    pub answers: BTreeMap<String, Answer>,
    pub usage: Usage,
}

/// Typed answer matching its question. Choice and Score carry the model's
/// calibrated `confidence`, derived from `probabilities`.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    Choice(ChoiceAnswer),
    Score(ScoreAnswer),
    Noul(NoulAnswer),
}

/// Answer to a [`Question::Choice`]: the winning option plus the full
/// distribution over every option.
#[derive(Debug, Clone, Deserialize)]
pub struct ChoiceAnswer {
    pub choice: String,
    pub probabilities: BTreeMap<String, f64>,
    pub confidence: f64,
}

/// Answer to a [`Question::Score`]: probability-weighted position across levels.
#[derive(Debug, Clone, Deserialize)]
pub struct ScoreAnswer {
    pub score: f64,
    pub legend: BTreeMap<String, String>,
    pub probabilities: BTreeMap<String, f64>,
    pub confidence: f64,
}

/// Answer to a [`Question::Noul`]: probability the statement is true.
#[derive(Debug, Clone, Deserialize)]
pub struct NoulAnswer {
    pub noul: f64,
}

/// Token usage for the request.
#[derive(Debug, Clone, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn serializes_mixed_questions_request() {
        let mut questions = BTreeMap::new();
        questions.insert(
            "department".to_string(),
            Question::choice(
                "Which team should handle this",
                BTreeMap::from([
                    (
                        "billing".to_string(),
                        json!("Payment or subscription issues"),
                    ),
                    (
                        "technical".to_string(),
                        json!("Bugs or integration problems"),
                    ),
                    ("sales".to_string(), json!("Pricing or account questions")),
                ]),
            ),
        );
        questions.insert(
            "frustration".to_string(),
            Question::score(
                "How frustrated the customer appears",
                vec![
                    json!("Calm, just stating facts"),
                    json!("Frustrated but civil"),
                    json!("Very angry, strong language"),
                ],
            ),
        );
        questions.insert(
            "is_urgent".to_string(),
            Question::noul("The message conveys urgency or time-sensitivity"),
        );

        let request = SystemOneRequest {
            state: json!(
                "Hi, I've been trying to connect my Stripe account for 3 days. Please help ASAP."
            ),
            model: "jev-latest".to_string(),
            questions,
        };

        let value = serde_json::to_value(&request).expect("request serializes");
        assert_eq!(value["model"], json!("jev-latest"));
        assert!(value["state"].is_string());
        assert_eq!(value["questions"]["department"]["type"], json!("choice"));
        assert_eq!(
            value["questions"]["department"]["criteria"]["technical"],
            json!("Bugs or integration problems")
        );
        assert_eq!(value["questions"]["frustration"]["type"], json!("score"));
        assert_eq!(
            value["questions"]["frustration"]["criteria"],
            json!([
                "Calm, just stating facts",
                "Frustrated but civil",
                "Very angry, strong language"
            ])
        );
        assert_eq!(value["questions"]["is_urgent"]["type"], json!("noul"));
        assert_eq!(
            value["questions"]["is_urgent"]["instructions"],
            json!("The message conveys urgency or time-sensitivity")
        );
    }

    #[test]
    fn parses_mixed_answers_response() {
        let body = json!({
            "model": "jev-1.13.0",
            "answers": {
                "department": {
                    "type": "choice",
                    "choice": "technical",
                    "confidence": 0.78,
                    "probabilities": {
                        "technical": 0.85,
                        "sales": 0.0,
                        "billing": 0.15
                    }
                },
                "frustration": {
                    "type": "score",
                    "score": 1.0,
                    "confidence": 1.0,
                    "legend": {
                        "0": "Calm, just stating facts",
                        "1": "Frustrated but civil",
                        "2": "Very angry, strong language"
                    },
                    "probabilities": {
                        "0": 0.0,
                        "1": 1.0,
                        "2": 0.0
                    }
                },
                "is_urgent": {
                    "type": "noul",
                    "noul": 1.0
                }
            },
            "usage": {
                "input_tokens": 392,
                "output_tokens": 65
            }
        });

        let response: SystemOneResponse = serde_json::from_value(body).expect("response parses");

        assert_eq!(response.model, "jev-1.13.0");
        assert_eq!(response.usage.input_tokens, 392);
        assert_eq!(response.usage.output_tokens, 65);

        let Some(Answer::Choice(department)) = response.answers.get("department") else {
            panic!("expected a choice answer for department");
        };
        assert_eq!(department.choice, "technical");
        assert!((department.confidence - 0.78).abs() < f64::EPSILON);
        assert_eq!(department.probabilities.get("technical"), Some(&0.85));

        let Some(Answer::Score(frustration)) = response.answers.get("frustration") else {
            panic!("expected a score answer for frustration");
        };
        assert!((frustration.score - 1.0).abs() < f64::EPSILON);
        assert_eq!(
            frustration.legend.get("1"),
            Some(&"Frustrated but civil".to_string())
        );

        let Some(Answer::Noul(is_urgent)) = response.answers.get("is_urgent") else {
            panic!("expected a noul answer for is_urgent");
        };
        assert!((is_urgent.noul - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rejects_unknown_answer_type() {
        let body = json!({
            "model": "jev-1.13.0",
            "answers": {
                "mystery": { "type": "telepathy", "confidence": 1.0 }
            },
            "usage": { "input_tokens": 1, "output_tokens": 0 }
        });

        let result = serde_json::from_value::<SystemOneResponse>(body);
        assert!(result.is_err(), "unknown answer types must not parse");
    }
}
