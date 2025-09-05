use crate::{decode_hex_digit, LeefLine, Separator};
use bytes::Bytes;
use r_nom::nom::branch::alt;
use r_nom::nom::bytes::complete::*;
use r_nom::nom::character::complete::char;
use r_nom::nom::character::is_hex_digit;
use r_nom::nom::combinator::{all_consuming, map, opt, rest};
use r_nom::nom::multi::fold_many0;
use r_nom::nom::sequence::{separated_pair, tuple};
use r_nom::nom::Parser;
use r_nom::nom_supreme::ParserExt;
use r_nom::{trim_byte_slice, utf8_string, Result};
use std::collections::BTreeMap;
use syslog::syslog;

fn single<F: Fn(u8) -> bool>(predicate: F) -> impl Fn(&[u8]) -> Result<u8> {
    move |input: &[u8]| {
        take(1usize)
            .map(|v: &[u8]| v[0])
            .verify(|v: &u8| predicate(*v))
            .parse(input)
    }
}

fn separator(input: &[u8]) -> Result<Separator> {
    alt((
        single(|b| b != b'|')
            .terminated(tag(b"|"))
            .map(Separator::Single),
        tuple((opt(tag(b"0")), tag(b"x")))
            .precedes(take_while_m_n(1, 4, is_hex_digit))
            .terminated(char('|'))
            .map(|sep: &[u8]| {
                let mut res = 0u16;
                for (i, b) in sep.iter().enumerate() {
                    res |= (decode_hex_digit(*b).unwrap() as u16) << ((sep.len() - i - 1) * 4);
                }
                if sep.len() > 2 {
                    Separator::Double((res >> 8) as u8, res as u8)
                } else {
                    Separator::Single(res as u8)
                }
            }),
    ))(input)
}

fn leef<V, F: Fn(&[u8]) -> V>(input: &[u8], map_fn: F) -> Result<BTreeMap<String, V>> {
    fn leef_header_segment(input: &[u8]) -> Result<&[u8]> {
        take_till1(|v| v == b'|').terminated(char('|')).parse(input)
    }

    let (input, (mut leef_map, sep)) = map(
        tuple((
            tag(b"LEEF:"),
            leef_header_segment,
            leef_header_segment,
            leef_header_segment,
            leef_header_segment,
            leef_header_segment,
            opt(separator),
        )),
        |(_, _version, vendor, product_name, product_version, event_name, leef_delimiter)| {
            let mut leef_map = BTreeMap::<String, V>::new();
            leef_map.insert("deviceVendor".into(), map_fn(vendor));
            leef_map.insert("productName".into(), map_fn(product_name));
            leef_map.insert("productVersion".into(), map_fn(product_version));
            leef_map.insert("eventName".into(), map_fn(event_name));
            (leef_map, leef_delimiter.unwrap_or(Separator::Single(b'\t')))
        },
    )(input)?;

    let mut err = None;

    let leef_body = move |input, sep: &[u8]| {
        all_consuming(fold_many0(
            separated_pair(
                take_while1(|b| b != b'=').map(trim_byte_slice),
                char('='),
                alt((take_until(sep), rest)).map(trim_byte_slice),
            )
            .terminated(opt(tag(sep))),
            || {},
            |_, (key, value): (&[u8], &[u8])| {
                if err.is_some() {
                    return;
                }
                let key = utf8_string(key);
                let value = map_fn(value);
                match key {
                    Ok(key) => {
                        leef_map.insert(key, value);
                    }
                    Err(e) => {
                        err = Some(e);
                    }
                }
            },
        ))(input)?;

        if let Some(e) = err {
            Err(e)
        } else {
            Ok((input, leef_map))
        }
    };

    match sep {
        Separator::Single(sep) => leef_body(input, &[sep]),
        Separator::Double(sep1, sep2) => leef_body(input, &[sep1, sep2]),
    }
}

pub fn parse_leef(data: &[u8]) -> Result<LeefLine> {
    parse_leef_map(data, Bytes::copy_from_slice)
}

pub fn parse_leef_map<V, F: Fn(&[u8]) -> V>(data: &[u8], map_fn: F) -> Result<LeefLine<V>> {
    let (leef_data, syslog_data) = take_until("LEEF:")(data)?;

    let (_, syslog) = map(opt(syslog), |v| v.unwrap_or_default())(syslog_data)?;
    let (rest, leef) = leef(leef_data, map_fn)?;

    Ok((
        rest,
        LeefLine {
            syslog,
            leef_components: leef,
        },
    ))
}
