use std::collections::BTreeMap;

use crate::nom::bytes::complete::take_until;
use bytes::Bytes;
use r_nom::nom::branch::alt;
use r_nom::nom::character::complete::{char, digit1};
use r_nom::nom::combinator::{opt, peek};
use r_nom::nom::error::{ErrorKind, FromExternalError, ParseError};
use r_nom::nom::sequence::{preceded, tuple};
use r_nom::nom::Parser;
use r_nom::nom_supreme::tag::complete::tag;
use r_nom::nom_supreme::ParserExt;
use r_nom::{
    error::format_error, escape_transform_in_scratch, nom, trim_byte_slice, trim_bytes,
    utf8_string, ErrorTree, RefOrScratch,
};

#[cfg(test)]
mod tests;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SyslogData {
    pub syslog_facility: Option<String>,
    pub syslog_priority: Option<String>,
    pub syslog_severity: Option<String>,
    pub at: Option<String>,
    pub ahost: Option<String>,
}

#[derive(Default, Debug)]
pub struct CefMap<V = Bytes> {
    pub syslog: syslog::SyslogData,
    pub fields: BTreeMap<String, V>,
}

type Result<'a, T> = r_nom::Result<'a, T>;

fn cef_header_segment_in_scratch<'a, 'b>(
    scratch: &'b mut Vec<u8>,
) -> impl FnMut(&'a [u8]) -> Result<'a, RefOrScratch<'a>> + 'b {
    move |input: &[u8]| {
        escape_transform_in_scratch(
            |b: u8| b != b'|',
            b'\\',
            alt((tag(b"|".as_ref()), tag(b"\\".as_ref()))),
            scratch,
        )
        .terminated(char('|'))
        .parse(input)
    }
}

fn cef_header<'a, V, FB: FnMut(&[u8]) -> Bytes, FV: FnMut(Bytes) -> V>(
    input: &'a [u8],
    map: &'_ mut BTreeMap<String, V>,
    map_to_bytes: &mut FB,
    map_to_value: &mut FV,
    values_from_scratch: &mut Vec<(String, (usize, usize))>,
    scratch: &mut Vec<u8>,
) -> Result<'a, ()> {
    let (input, _) = char('|').parse(input)?;

    let mut handle = move |key: String, val: RefOrScratch| {
        match val {
            RefOrScratch::Ref(v) => {
                map.insert(key, map_to_value(map_to_bytes(v)));
            }
            RefOrScratch::Scratch(st, en) => {
                values_from_scratch.push((key, (st, en)));
            }
        };
    };

    let (input, device_vendor) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("deviceVendor".into(), device_vendor);

    let (input, device_product) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("deviceProduct".into(), device_product);

    let (input, device_version) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("deviceVersion".into(), device_version);

    let (input, signature_id) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("signatureId".into(), signature_id);

    let (input, name) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("name".into(), name);

    let (input, severity) = cef_header_segment_in_scratch(scratch).parse(input)?;
    handle("severity".into(), severity);

    Ok((input, ()))
}

fn extension_segment_in_scratch<'a, 'b>(
    scratch: &'b mut Vec<u8>,
) -> impl FnMut(&'a [u8]) -> Result<'a, RefOrScratch<'a>> + use<'a, 'b> {
    move |input: &[u8]| {
        escape_transform_in_scratch(
            |b| b != b'=',
            b'\\',
            alt((
                tag(b"|".as_ref()),
                tag(b"\\".as_ref()),
                tag(b"=".as_ref()),
                tag(b"r\\n".as_ref()).value(b"\n".as_ref()),
                tag(b"n\\r".as_ref()).value(b"\n".as_ref()),
                tag(b"r".as_ref()).value(b"\n".as_ref()),
                tag(b"n".as_ref()).value(b"\n".as_ref()),
            )),
            scratch,
        )
        .parse(input)
    }
}

fn cef_extensions<'a, V, FB, FV>(
    input: &'a [u8],
    map: &mut BTreeMap<String, V>,
    map_to_bytes: &mut FB,
    map_to_value: &mut FV,
    values_from_scratch: &mut Vec<(String, (usize, usize))>,
    scratch: &mut Vec<u8>,
) -> Result<'a, ()>
where
    FB: FnMut(&[u8]) -> Bytes,
    FV: FnMut(Bytes) -> V,
{
    let (mut input, key) = extension_segment_in_scratch(scratch).parse(input)?;
    let mut key = match key {
        RefOrScratch::Ref(v) => utf8_string(trim_byte_slice(v))?,
        RefOrScratch::Scratch(st, en) => utf8_string(trim_byte_slice(&scratch[st..en]))?,
    };

    while !input.is_empty() {
        let (rest_input, (_, value_and_next_key, has_key)) = tuple((
            char('='),
            extension_segment_in_scratch(scratch),
            peek(opt(char('=')).map(|v: Option<_>| v.is_some())),
        ))
        .parse(input)?;

        if has_key {
            let curr_key = key;
            match value_and_next_key {
                RefOrScratch::Ref(v) => {
                    let ind = v.iter().rposition(|b| *b == b' ').ok_or_else(|| {
                        nom::Err::Error(ErrorTree::from_external_error(
                            input,
                            ErrorKind::Fix,
                            "Key and value should be separated by space",
                        ))
                    })?;

                    key = utf8_string(trim_byte_slice(&v[ind + 1..]))?;

                    map.insert(
                        curr_key,
                        map_to_value(map_to_bytes(trim_byte_slice(&v[..ind]))),
                    );
                }
                RefOrScratch::Scratch(st, en) => {
                    let ind = scratch[st..en]
                        .iter()
                        .rposition(|b| *b == b' ')
                        .ok_or_else(|| {
                            nom::Err::Error(ErrorTree::from_external_error(
                                input,
                                ErrorKind::Fix,
                                "Key and value should be separated by space",
                            ))
                        })?;
                    let ind = ind + st;

                    key = utf8_string(trim_byte_slice(&scratch[ind + 1..en]))?;

                    values_from_scratch.push((curr_key, (st, ind)));
                }
            }
        } else {
            match value_and_next_key {
                RefOrScratch::Ref(v) => {
                    map.insert(key, map_to_value(map_to_bytes(trim_byte_slice(v))));
                }
                RefOrScratch::Scratch(st, en) => {
                    values_from_scratch.push((key, (st, en)));
                }
            }
            break;
        }

        input = rest_input;
    }

    Ok((input, ()))
}
/// eats whole prefix
fn split_by_cef_prefix(input: &'_ [u8]) -> Result<'_, (&'_ [u8], &'_ [u8])> {
    let mut curr_input = input;
    loop {
        let (input, header) = take_until("CEF:")(curr_input)?;

        let cef_header =
            tuple::<_, _, ErrorTree, _>((tag(b"CEF:"), digit1, opt(preceded(char('.'), digit1))))(
                input,
            );

        if let Ok((cef_body, _)) = cef_header {
            return Ok((b"", (header, cef_body)));
        } else if input.is_empty() {
            return Err(nom::Err::Error(ErrorTree::from_error_kind(
                input,
                ErrorKind::Fix,
            )));
        } else {
            curr_input = &input[1..];
        }
    }
}

fn cef<V, FB: FnMut(&'_ [u8]) -> Bytes, FV: FnMut(Bytes) -> V>(
    input: &'_ [u8],
    mut map_to_bytes: FB,
    mut map_to_value: FV,
) -> Result<'_, CefMap<V>> {
    let (_, (syslog_header, cef_body)) = split_by_cef_prefix(input)?;
    let (_, syslog) = opt(syslog::syslog)(syslog_header)?;

    let mut scratch = Vec::new();
    let mut cef_map = BTreeMap::new();
    let mut cef_values_from_scratch = Vec::new();

    let (input, _) = cef_header(
        cef_body,
        &mut cef_map,
        &mut map_to_bytes,
        &mut map_to_value,
        &mut cef_values_from_scratch,
        &mut scratch,
    )?;
    let (input, _) = cef_extensions(
        input,
        &mut cef_map,
        &mut map_to_bytes,
        &mut map_to_value,
        &mut cef_values_from_scratch,
        &mut scratch,
    )?;

    let scratch = Bytes::from(scratch);
    for (key, (st, en)) in cef_values_from_scratch {
        cef_map.insert(key, map_to_value(trim_bytes(scratch.slice(st..en))));
    }

    Ok((
        input,
        CefMap {
            syslog: syslog.unwrap_or_default(),
            fields: cef_map,
        },
    ))
}

fn cef_with_labels<V, FB, FV, FL>(
    input: &'_ [u8],
    map_to_bytes: FB,
    map_to_value: FV,
    mut map_label: FL,
) -> Result<'_, CefMap<V>>
where
    FB: FnMut(&'_ [u8]) -> Bytes,
    FV: FnMut(Bytes) -> V,
    FL: for<'a> FnMut(&'a V) -> &'a [u8],
{
    let (input, mut cef_map) = cef(input, map_to_bytes, map_to_value)?;

    let rename_keys = cef_map
        .fields
        .keys()
        .filter(|k| k.ends_with("Label") && cef_map.fields.contains_key(&k[..k.len() - 5]))
        .cloned()
        .collect::<Vec<_>>();

    for key in rename_keys {
        let k = cef_map.fields.remove(&key).unwrap();
        let new_key = utf8_string(map_label(&k))?;

        let value = cef_map.fields.remove(&key[..key.len() - 5]).unwrap();

        cef_map.fields.insert(new_key, value);
    }

    Ok((input, cef_map))
}

pub fn parse_cef(input: Bytes) -> std::result::Result<BTreeMap<String, Bytes>, String> {
    parse_cef_map(input, |v| v)
}

pub fn parse_cef_map<V, F: FnMut(Bytes) -> V>(
    input: Bytes,
    mut map_value: F,
) -> std::result::Result<BTreeMap<String, V>, String> {
    let (_, cef_map) =
        cef(&input, |v| input.slice_ref(v), &mut map_value).map_err(|v| match v {
            nom::Err::Error(e) | nom::Err::Failure(e) => format_error(&e),
            nom::Err::Incomplete(_) => {
                unreachable!("Error type used for streaming parsers, should be impossible")
            }
        })?;

    let mut map = cef_map.fields;
    if let Some(syslog_facility) = cef_map.syslog.syslog_facility {
        map.insert("syslog_facility".into(), map_value(syslog_facility.into()));
    }
    if let Some(syslog_priority) = cef_map.syslog.syslog_priority {
        map.insert("syslog_priority".into(), map_value(syslog_priority.into()));
    }
    if let Some(syslog_severity) = cef_map.syslog.syslog_severity {
        map.insert("syslog_severity".into(), map_value(syslog_severity.into()));
    }
    if let Some(at) = cef_map.syslog.at {
        map.insert("at".into(), map_value(at.into()));
    }
    if let Some(ahost) = cef_map.syslog.ahost {
        map.insert("ahost".into(), map_value(ahost.into()));
    }

    Ok(map)
}

pub fn parse_cef_with_labels(input: Bytes) -> std::result::Result<BTreeMap<String, Bytes>, String> {
    parse_cef_map_with_labels(input, |v| v, |v| v)
}

pub fn parse_cef_map_with_labels<V, FV, FL>(
    input: Bytes,
    mut map_value: FV,
    map_label: FL,
) -> std::result::Result<BTreeMap<String, V>, String>
where
    FV: FnMut(Bytes) -> V,
    FL: for<'a> FnMut(&'a V) -> &'a [u8],
{
    let (_, cef_map) = cef_with_labels(&input, |v| input.slice_ref(v), &mut map_value, map_label)
        .map_err(|v| match v {
        nom::Err::Error(e) | nom::Err::Failure(e) => format_error(&e),
        nom::Err::Incomplete(_) => {
            unreachable!("Error type used for streaming parsers, should be impossible")
        }
    })?;

    let mut map = cef_map.fields;
    if let Some(syslog_facility) = cef_map.syslog.syslog_facility {
        map.insert("syslog_facility".into(), map_value(syslog_facility.into()));
    }
    if let Some(syslog_priority) = cef_map.syslog.syslog_priority {
        map.insert("syslog_priority".into(), map_value(syslog_priority.into()));
    }
    if let Some(syslog_severity) = cef_map.syslog.syslog_severity {
        map.insert("syslog_severity".into(), map_value(syslog_severity.into()));
    }
    if let Some(at) = cef_map.syslog.at {
        map.insert("at".into(), map_value(at.into()));
    }
    if let Some(ahost) = cef_map.syslog.ahost {
        map.insert("ahost".into(), map_value(ahost.into()));
    }

    Ok(map)
}
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_split_by_prefix() {
        assert_eq!(
            split_by_cef_prefix(b"asdasd CEF:123.123|wqeqwe").unwrap().1,
            (b"asdasd ".as_ref(), b"|wqeqwe".as_ref())
        )
    }
}
