use r_nom::nom::bytes::complete::{tag, take_until};
use r_nom::nom::character::complete::{char, multispace0};
use r_nom::nom::sequence::tuple;
use r_nom::nom::Parser;
use serde::Deserialize;

// TODO: при необходимости переделать на Result
pub fn json_payload_extractor<'a, T: Deserialize<'a>>(
    mut input: &'a [u8],
    payload_key: &[u8],
) -> Option<T> {
    loop {
        input = take_until::<_, _, r_nom::ErrorTree>(payload_key)
            .parse(input)
            .ok()?
            .0;

        if input.is_empty() {
            break;
        }

        let res = tuple::<_, _, r_nom::ErrorTree, _>((
            tag(payload_key),
            char('"'),
            multispace0,
            char(':'),
            multispace0,
        ))
        .parse(input);

        if let Ok((rest, _)) = res {
            return T::deserialize(&mut serde_json::de::Deserializer::from_slice(rest)).ok();
        } else {
            input = &input[payload_key.len()..];
            continue;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_json() {
        assert_eq!(
            json_payload_extractor(br#"{"asd":123,"payload":"text"}"#, b"payload"),
            Some(String::from("text"))
        )
    }

    #[test]
    fn valid_json_whitespaces() {
        assert_eq!(
            json_payload_extractor(
                br#"{"asd":123,"payload"   :
                "text"}"#,
                b"payload"
            ),
            Some(String::from("text"))
        )
    }

    #[test]
    fn valid_json_object_payload() {
        assert_eq!(
            json_payload_extractor(
                br#"{"kappa": 213, "payload" : {"a": 1, "b": [1, 2, 3]}}"#,
                b"payload"
            ),
            Some(json!({ "a": 1, "b": [1, 2, 3] }))
        )
    }

    #[test]
    fn valid_json_key_with_suffix() {
        assert_eq!(
            json_payload_extractor(
                br#"{"asd":123,"payload1":"text123","payload":"text"}"#,
                b"payload"
            ),
            Some(String::from("text"))
        )
    }

    #[test]
    fn valid_json_structure_multiple_payloads() {
        assert_eq!(
            json_payload_extractor(
                br#""{ asd":123,"payload" : "first", "payload": "second" }"#,
                b"payload"
            ),
            Some(String::from("first"))
        )
    }

    #[test]
    fn invalid_json_structure() {
        assert_eq!(
            json_payload_extractor(br#""asd":123,"payload" : "text""#, b"payload"),
            Some(String::from("text"))
        )
    }

    #[test]
    fn valid_json_no_payload() {
        assert_eq!(
            json_payload_extractor::<String>(
                br#"{"asd":123,"payload1":"text123","payload123":"text"}"#,
                b"payload"
            ),
            None
        )
    }

    #[test]
    fn json_dynamic_type() {
        assert_eq!(
            json_payload_extractor(br#"{"payload" :"text123"}"#, b"payload"),
            Some(json!("text123"))
        );
        assert_eq!(
            json_payload_extractor(br#"{"payload": 123}"#, b"payload"),
            Some(json!(123))
        );
        assert_eq!(
            json_payload_extractor(br#"{"payload":   [1, 2, 3]}"#, b"payload"),
            Some(json!([1, 2, 3]))
        );
        assert_eq!(
            json_payload_extractor(br#"{"payload" : { "a": "b" }}"#, b"payload"),
            Some(json!({ "a": "b" }))
        );
    }
}
