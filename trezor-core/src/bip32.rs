//! Minimal BIP32 path parsing for custom / alternative derivation
//! paths. The host (iOS) passes a human path string ("m/44'/501'/0'")
//! when a wallet was added at a non-standard path; we parse it into the
//! `address_n` vector the trezor-common messages want. Hardened levels
//! use `'` or `h`/`H`; the high bit (0x8000_0000) is set on hardened
//! components.

use crate::error::TrezorError;

/// Parse a BIP32 path string into `address_n`. Accepts an optional
/// leading `m/` (or `M/`); an empty path (`m` / `m/`) yields an empty
/// vector. Rejects malformed components and out-of-range indices.
pub(crate) fn parse_path(input: &str) -> Result<Vec<u32>, TrezorError> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix("m/")
        .or_else(|| trimmed.strip_prefix("M/"))
        .unwrap_or(trimmed);
    if body.is_empty() || body == "m" || body == "M" {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for raw in body.split('/') {
        let comp = raw.trim();
        if comp.is_empty() {
            return Err(TrezorError::thp(format!(
                "invalid derivation path '{input}': empty component"
            )));
        }
        let (digits, hardened) = match comp
            .strip_suffix('\'')
            .or_else(|| comp.strip_suffix('h'))
            .or_else(|| comp.strip_suffix('H'))
        {
            Some(d) => (d, true),
            None => (comp, false),
        };
        let idx: u32 = digits.parse().map_err(|_| {
            TrezorError::thp(format!(
                "invalid derivation path '{input}': bad component '{comp}'"
            ))
        })?;
        if idx >= 0x8000_0000 {
            return Err(TrezorError::thp(format!(
                "invalid derivation path '{input}': index '{comp}' out of range"
            )));
        }
        out.push(if hardened { idx | 0x8000_0000 } else { idx });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hardened_and_unhardened() {
        assert_eq!(
            parse_path("m/44'/501'/0'/0'").unwrap(),
            vec![
                0x8000_0000 + 44,
                0x8000_0000 + 501,
                0x8000_0000,
                0x8000_0000
            ]
        );
        // mixed: ETH standard m/44'/60'/0'/0/0
        assert_eq!(
            parse_path("m/44'/60'/0'/0/0").unwrap(),
            vec![0x8000_0000 + 44, 0x8000_0000 + 60, 0x8000_0000, 0, 0]
        );
    }

    #[test]
    fn accepts_h_suffix_and_no_m_prefix() {
        assert_eq!(
            parse_path("44h/195h/2h").unwrap(),
            vec![0x8000_0000 + 44, 0x8000_0000 + 195, 0x8000_0000 + 2]
        );
    }

    #[test]
    fn empty_path_is_empty_vec() {
        assert_eq!(parse_path("m").unwrap(), Vec::<u32>::new());
        assert_eq!(parse_path("m/").unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_path("m/44'/xx/0").is_err());
        assert!(parse_path("m/44'//0").is_err());
        assert!(parse_path("m/4294967296").is_err()); // >= 2^31 after... actually > u32 max parse
    }
}
