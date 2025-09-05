use r_nom::nom::branch::alt;
use r_nom::nom::bytes::complete::{tag, take_while1, take_while_m_n};
use r_nom::nom::character::complete::{char, digit1, satisfy, space1};
use r_nom::nom::combinator::{opt, recognize};
use r_nom::nom::sequence::{delimited, pair, tuple};
use r_nom::nom::Parser;
use r_nom::nom_supreme::ParserExt;
use r_nom::Result;
use std::num::ParseIntError;

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct SyslogData {
    pub syslog_facility: Option<String>,
    pub syslog_priority: Option<String>,
    pub syslog_severity: Option<String>,
    pub at: Option<String>,
    pub ahost: Option<String>,
}

fn version(input: &[u8]) -> Result<u8> {
    satisfy(|v| v.is_ascii_digit())
        .map(|v| v.to_digit(10).unwrap() as u8)
        .parse(input)
}

fn syslog_pri(input: &[u8]) -> Result<&[u8]> {
    delimited(
        tag(b"<"),
        take_while1(|v: u8| v.is_ascii_digit()),
        tag(b">"),
    )
    .parse(input)
}

fn single_space(input: &[u8]) -> Result<char> {
    satisfy(|v| v == ' ').parse(input)
}

fn syslog_segment(input: &[u8]) -> Result<&[u8]> {
    take_while1(|v| v != b' ')(input)
}

fn rfc_31644_timestamp(input: &[u8]) -> Result<String> {
    fn double_digit(input: &[u8]) -> Result<u8> {
        digit1
            .verify(|digits: &&[u8]| digits.len() == 2)
            // SAFETY: digit1 esures valid utf8 characters
            .map(|digits| {
                unsafe { std::str::from_utf8_unchecked(digits) }
                    .parse::<u8>()
                    .unwrap()
            })
            .parse(input)
    }

    tuple((
        alt((
            tag(b"Jan"),
            tag(b"Feb"),
            tag(b"Mar"),
            tag(b"Apr"),
            tag(b"May"),
            tag(b"Jun"),
            tag(b"Jul"),
            tag(b"Aug"),
            tag(b"Sep"),
            tag(b"Oct"),
            tag(b"Nov"),
            tag(b"Dec"),
        ))
        .terminated(space1),
        recognize(
            take_while_m_n(1, 2, |b: u8| b.is_ascii_digit())
                // SAFETY: take_while_m_n ensures valid ascii digits
                .map(|date| {
                    unsafe { std::str::from_utf8_unchecked(date) }
                        .parse::<u8>()
                        .unwrap()
                })
                .verify(|date| *date > 0 && *date <= 31),
        )
        .terminated(space1),
        recognize(tuple((
            double_digit.verify(|hours| *hours <= 23),
            char(':'),
            double_digit.verify(|minutes| *minutes <= 59),
            char(':'),
            double_digit.verify(|minutes| *minutes <= 59),
        ))),
    ))
    .map(|timestamp| {
        let mut time =
            String::with_capacity(timestamp.0.len() + timestamp.1.len() + timestamp.2.len() + 2);
        time.push_str(std::str::from_utf8(timestamp.0).unwrap());
        time.push(' ');
        time.push_str(std::str::from_utf8(timestamp.1).unwrap());
        time.push(' ');
        time.push_str(std::str::from_utf8(timestamp.2).unwrap());
        time
    })
    .parse(input)
}

fn syslog_rfc3164(input: &[u8]) -> Result<SyslogData> {
    fn syslog_header(input: &[u8]) -> Result<(String, &[u8])> {
        pair(
            rfc_31644_timestamp.terminated(space1),
            syslog_segment.terminated(space1),
        )
        .parse(input)
    }

    alt((
        pair(syslog_pri.map(Some), opt(syslog_header)),
        syslog_header.map(|v| (None, Some(v))),
    ))
    .map_res::<_, _, ParseIntError>(|(pri, time_and_host)| {
        // SAFETY: take_while1 ensures correct ascii bytes
        let pri_str = pri.map(|pri| unsafe { std::str::from_utf8_unchecked(pri) });
        let pri_val = pri_str.map(|v| v.parse::<u16>()).transpose()?;
        let (time, host) = time_and_host
            .map(|(time, host)| {
                (
                    Some(time),
                    Some(String::from_utf8(host.to_owned()).unwrap()),
                )
            })
            .unwrap_or_default();

        Ok(SyslogData {
            syslog_priority: pri_str.map(|s| s.to_owned()),
            syslog_facility: pri_val.map(|v| (v / 8).to_string()),
            syslog_severity: pri_val.map(|v| (v % 8).to_string()),
            at: time,
            ahost: host,
        })
    })
    .parse(input)
}

fn syslog_rfc5424(input: &[u8]) -> Result<SyslogData> {
    tuple((
        delimited(
            tag(b"<"),
            take_while1(|v: u8| v.is_ascii_digit()),
            tag(b">"),
        )
        .terminated(version),
        single_space,
        syslog_segment,
        single_space,
        syslog_segment,
    ))
    .map_res::<_, _, ParseIntError>(|(pri, _, timestamp, _, host)| {
        // SAFETY: safe because take_while1 ensures correct bytes (only ascii digits)
        let pri_str = unsafe { std::str::from_utf8_unchecked(pri) };
        let pri_val = pri_str.parse::<u16>()?;

        Ok(SyslogData {
            syslog_priority: Some(pri_str.to_owned()),
            syslog_facility: Some((pri_val / 8).to_string()),
            syslog_severity: Some((pri_val % 8).to_string()),
            at: Some(String::from_utf8(timestamp.to_owned()).unwrap()),
            ahost: Some(String::from_utf8(host.to_owned()).unwrap()),
        })
    })
    .parse(input)
}

pub fn syslog(input: &[u8]) -> Result<SyslogData> {
    alt((syslog_rfc5424, syslog_rfc3164))(input)
}
