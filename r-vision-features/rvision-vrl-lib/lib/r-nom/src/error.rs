use crate::ErrorTree;
use std::borrow::Cow;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone)]
pub struct ParserContext {
    pub location: &'static str,
    pub msg: Cow<'static, str>,
}

impl Display for ParserContext {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.location)?;
        f.write_str(" parsing \"")?;
        f.write_str(&self.msg)?;
        f.write_str("\"")?;
        Ok(())
    }
}

impl From<&'static str> for ParserContext {
    fn from(msg: &'static str) -> Self {
        ParserContext {
            location: "",
            msg: Cow::Borrowed(msg),
        }
    }
}

#[macro_export]
macro_rules! ctx {
    ($e:expr) => {
        $crate::error::ParserContext {
            location: concat!("[", file!(), ":", line!(), "]"),
            msg: $e.into(),
        }
    };
}

pub fn format_error(err: &ErrorTree) -> String {
    if let Ok(s) = std::str::from_utf8(err.input) {
        format!("error {} at \"{}\"", err.code.description(), s)
    } else {
        format!("error {} at {:x?}", err.code.description(), err.input)
    }
}
