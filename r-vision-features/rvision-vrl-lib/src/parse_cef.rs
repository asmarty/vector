use cef2map_nom::parse_cef_map;
use std::collections::BTreeMap;
use std::str;
use vrl::prelude::*;

fn parse_cef(value: Value) -> Resolved {
    let data = value.try_bytes()?;

    Ok(Value::Object(
        parse_cef_map(data, Value::Bytes)?
            .into_iter()
            .map(|(k, v)| (k.into(), v))
            .collect(),
    ))
}

#[derive(Clone, Copy, Debug)]
pub struct ParseCef;

impl Function for ParseCef {
    fn identifier(&self) -> &'static str {
        "rv_parse_cef"
    }

    fn summary(&self) -> &'static str {
        "parse a string in CEF format to a object type"
    }

    fn usage(&self) -> &'static str {
        indoc! {r#"
            Parses the provided `value` as CEF structure.
            CEF Object is returned.
        "#}
    }

    fn parameters(&self) -> &'static [Parameter] {
        &[Parameter {
            keyword: "value",
            kind: kind::BYTES,
            required: true,
        }]
    }

    fn examples(&self) -> &'static [Example] {
        &[Example {
            title: "object",
            source: r#"parse_cef_sense!(s'CEF:0|Microsoft|Microsoft Windows||Microsoft-Windows-Security-Auditing:4624|An account was successfully logged on.|Low| eventId=1013540004 externalId=4624')"#,
            result: Ok(
                r#"{ "deviceVendor": "Microsoft", "deviceProduct": "Microsoft Windows", "deviceVersion": "", "deviceEventClassId": "Microsoft-Windows-Security-Auditing:4624", "name": "An account was successfully logged on.", "severity": "Low", "eventId": "1013540004", "externalId": "4624" }"#,
            ),
        }]
    }

    fn compile(
        &self,
        _state: &state::TypeState,
        _ctx: &mut FunctionCompileContext,
        arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");

        Ok(ParseCefFn { value }.as_expr())
    }
}

#[derive(Debug, Clone)]
struct ParseCefFn {
    value: Box<dyn Expression>,
}

impl FunctionExpression for ParseCefFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let value = self.value.resolve(ctx)?;
        parse_cef(value)
    }

    fn type_def(&self, _: &state::TypeState) -> TypeDef {
        type_def()
    }
}

fn type_def() -> TypeDef {
    TypeDef::object(Collection::from_parts(
        BTreeMap::from([
            (Field::from("deviceVendor"), Kind::bytes()),
            (Field::from("deviceProduct"), Kind::bytes()),
            (Field::from("deviceVersion"), Kind::bytes()),
            (Field::from("deviceEventClassId"), Kind::bytes()),
            (Field::from("name"), Kind::bytes()),
            (Field::from("severity"), Kind::bytes()),
        ]),
        Kind::bytes(),
    ))
    .fallible()
}
