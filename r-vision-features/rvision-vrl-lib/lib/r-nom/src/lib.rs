use bytes::{Buf, Bytes};
use nom::{IResult, Offset, Parser};
use std::borrow::Cow;
// use nom_supreme::error::{BaseErrorKind, Expectation, GenericErrorTree, StackContext};

pub mod error;

pub use nom;
use nom::error::{ErrorKind, FromExternalError};
pub use nom_supreme;
use std::result::Result as StdResult;

// pub type ErrorTree<'a> = GenericErrorTree<&'a [u8], &'a [u8], ParserContext, Box<dyn Error + Send + Sync + 'static>>;
pub type ErrorTree<'a> = nom::error::Error<&'a [u8]>;
pub type Result<'a, T> = IResult<&'a [u8], T, ErrorTree<'a>>;

#[allow(clippy::print_stderr)]
pub fn dbg_dump<'a, 'b, T, P: Parser<&'a [u8], T, ErrorTree<'a>>>(
    p: &'b mut P,
    ctx: &'static str,
) -> impl FnMut(&'a [u8]) -> Result<'a, T> + 'b {
    move |input| {
        if let Ok(input) = std::str::from_utf8(input) {
            eprintln!("{}: {}", ctx, input);
        } else {
            eprintln!("{}: {:?}", ctx, input);
        }
        p.parse(input)
    }
}

pub fn utf8_string(input: &[u8]) -> StdResult<String, nom::Err<ErrorTree<'static>>> {
    // TODO: Может использовать from_utf8_lossy
    String::from_utf8(input.into()).map_err(|_e| {
        nom::Err::Error(ErrorTree::from_external_error(
            b"<invalid_utf8>",
            ErrorKind::Fix,
            "Non-UTF8 string encountered",
        ))
    })
}

pub fn trim_byte_slice(v: &[u8]) -> &[u8] {
    if v.is_empty() {
        return v;
    }
    let mut start_ind = 0;
    let mut end_ind = v.len();

    while start_ind < v.len() - 1 && v[start_ind].is_ascii_whitespace() {
        start_ind += 1;
    }

    while end_ind > start_ind && v[end_ind - 1].is_ascii_whitespace() {
        end_ind -= 1;
    }

    &v[start_ind..end_ind]
}

pub fn trim_bytes(mut v: Bytes) -> Bytes {
    if v.is_empty() {
        return v;
    }
    let mut start_ind = 0;
    let mut end_ind = v.len();

    while start_ind < v.len() - 1 && v[start_ind].is_ascii_whitespace() {
        start_ind += 1;
    }

    while end_ind > start_ind && v[end_ind - 1].is_ascii_whitespace() {
        end_ind -= 1;
    }

    v.advance(start_ind);
    v.truncate(end_ind - start_ind);

    v
}

/// Деэкранирует строку, аллоцирует новую только если встретилась escape последовательность
/// Берет символы пока take_while возвращает true, как только встречает control_char (обычно '\\') применяет transform
///
/// ```
///# use std::borrow::Cow;
///# use nom::branch::alt;
///# use nom::bytes::complete::tag;
///# use nom::character::complete::char;
///# use nom_supreme::ParserExt;
///# use r_nom::escape_transform;
/// let res = escape_transform(|b| b != b' ', b'\\', alt((
///   tag(b"r\\n".as_ref()).value(b"\n".as_ref()),
///   char('n').value(b"\n".as_ref()),
///   char('r').value(b"\n".as_ref()),
///   tag(b" ".as_ref())
/// )))(br#"asda\n\r\n\ sd asdasd"#).unwrap();
///
/// assert_eq!(res, (b" asdasd".as_ref(), Cow::Owned(b"asda\n\n sd".to_vec())))
/// ```
///
/// ```
///# use std::borrow::Cow;
///# use nom::branch::alt;
///# use nom::character::complete::char;
///# use nom_supreme::ParserExt;
///# use r_nom::escape_transform;
/// let res = escape_transform(|b| b != b' ', b'\\', alt((
///   char('n').value(b"\n".as_ref()),
///   char('r').value(b"\r".as_ref()),
/// )))(b"asdasd asdasd").unwrap();
///
/// assert_eq!(res, (b" asdasd".as_ref(), Cow::Borrowed(b"asdasd".as_ref())))
/// ```
pub fn escape_transform<'a, F, Transform>(
    mut take_while: F,
    control_char: u8,
    mut transform: Transform,
) -> impl FnMut(&'a [u8]) -> Result<'a, Cow<'a, [u8]>>
where
    F: FnMut(u8) -> bool,
    Transform: Parser<&'a [u8], &'a [u8], ErrorTree<'a>>,
{
    move |input| {
        let mut vec = Vec::new();

        match escape_impl(
            input,
            &mut take_while,
            control_char,
            &mut transform,
            &mut vec,
        )? {
            (input, RefOrScratch::Ref(v)) => Ok((input, Cow::Borrowed(v))),
            (input, RefOrScratch::Scratch(..)) => Ok((input, Cow::Owned(vec))),
        }
    }
}

/// Деэкранирует строку, использует существующий scratch что позволяет избежать повторных аллокаций при использовании несколько раз подряд
/// Сбрасывает scratch
pub fn escape_transform_with_scratch<'b, 'a: 'b, F, Transform>(
    mut take_while: F,
    control_char: u8,
    mut transform: Transform,
    scratch: &'b mut Vec<u8>,
) -> impl (FnMut(&'a [u8]) -> Result<'a, Cow<'a, [u8]>>) + 'b
where
    F: FnMut(u8) -> bool + 'b,
    Transform: Parser<&'a [u8], &'a [u8], ErrorTree<'a>> + 'b,
{
    move |input| match escape_impl(
        input,
        &mut take_while,
        control_char,
        &mut transform,
        scratch,
    )? {
        (input, RefOrScratch::Ref(v)) => Ok((input, Cow::Borrowed(v))),
        (input, RefOrScratch::Scratch(st, en)) => {
            let v = &scratch[st..en];
            let res = Cow::Owned(v.to_vec());
            scratch.truncate(0);
            Ok((input, res))
        }
    }
}

pub enum RefOrScratch<'a> {
    Ref(&'a [u8]),
    Scratch(usize, usize),
}

/// Деэкранирует строку, использует существующий scratch, если были встречены escape последовательности вернет RefOrScratch::Scratch(start, end), индексы внутри scratch.
/// Не сбрасывает scratch
pub fn escape_transform_in_scratch<'a, 'b, F, Transform>(
    mut take_while: F,
    control_char: u8,
    mut transform: Transform,
    scratch: &'b mut Vec<u8>,
) -> impl (FnMut(&'a [u8]) -> Result<'a, RefOrScratch<'a>>) + 'b
where
    F: FnMut(u8) -> bool + 'b,
    Transform: Parser<&'a [u8], &'a [u8], ErrorTree<'a>> + 'b,
{
    move |input| {
        escape_impl(
            input,
            &mut take_while,
            control_char,
            &mut transform,
            scratch,
        )
    }
}

fn escape_impl<'a, F, Transform>(
    input: &'a [u8],
    take_while: &mut F,
    control_char: u8,
    transform: &mut Transform,
    scratch: &mut Vec<u8>,
) -> Result<'a, RefOrScratch<'a>>
where
    F: FnMut(u8) -> bool,
    Transform: Parser<&'a [u8], &'a [u8], ErrorTree<'a>>,
{
    let mut ind = 0;
    let mut copy_ind = 0;
    let mut escaped = false;
    let start_ind = scratch.len();
    while ind < input.len() {
        if input[ind] == control_char {
            escaped = true;
            scratch.extend_from_slice(&input[copy_ind..ind]);

            ind += 1;

            let (leftover, unescaped) = transform.parse(&input[ind..])?;
            scratch.extend_from_slice(unescaped);

            ind += input.offset(leftover) - ind;
            copy_ind = ind;

            continue;
        } else if !take_while(input[ind]) {
            if !escaped {
                return Ok((&input[ind..], RefOrScratch::Ref(&input[..ind])));
            } else {
                scratch.extend_from_slice(&input[copy_ind..ind]);
                return Ok((
                    &input[ind..],
                    RefOrScratch::Scratch(start_ind, scratch.len()),
                ));
            }
        }

        ind += 1;
    }

    if !escaped {
        Ok((b"", RefOrScratch::Ref(input)))
    } else {
        scratch.extend_from_slice(&input[copy_ind..]);
        Ok((b"", RefOrScratch::Scratch(start_ind, scratch.len())))
    }
}

#[cfg(test)]
mod tests {
    use crate::escape_transform;
    use nom::branch::alt;
    use nom::Parser;
    use nom_supreme::tag::complete::tag;

    #[test]
    fn escape_stuff() {
        let (input, v) = escape_transform(
            |b| b != b'|',
            b'\\',
            alt((tag(b"|".as_ref()), tag(b"\\".as_ref()))),
        )
        .parse(br#""#)
        .unwrap();

        assert!(input.is_empty());
        assert!(v.is_empty());
    }
}
