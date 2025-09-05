use r_nom::nom::bytes::complete::take_while;
use r_nom::nom::character::complete::char;
use r_nom::nom::multi::separated_list1;
use r_nom::nom::sequence::separated_pair;
use r_nom::nom::Parser;

/// acc and domain
pub fn extract_from_dit(v: &str) -> Result<(String, String), String> {
    let (_, val) = separated_list1::<_, (&str, &str), _, r_nom::nom::error::Error<&str>, _, _>(
        char(','),
        separated_pair(
            take_while(|c: char| c != '='),
            char('='),
            take_while(|c: char| c != ','),
        ),
    )
    .parse(v)
    .map_err(|e| e.to_string())?;

    let mut cn = None;
    let mut domain = String::new();
    for (k, v) in val.into_iter() {
        if k == "CN" && cn.is_none() {
            cn = Some(v.to_lowercase())
        }

        if k == "DC" {
            if !domain.is_empty() {
                domain.push('.');
            }

            domain.push_str(v);
        }
    }

    domain = domain.to_lowercase();

    Ok((cn.unwrap_or_default(), domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kappa() {
        assert_eq!(
            extract_from_dit("CN=Dev-India,OU=Distribution Groups,DC=gp,DC=gl,DC=google,DC=com")
                .unwrap(),
            ("dev-india".to_string(), "gp.gl.google.com".to_string())
        );
    }
}
