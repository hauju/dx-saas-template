//! Waitlist input validation, shared by the form and the server function.

/// The RFC 5321 limit on a forward path.
const MAX_EMAIL_LEN: usize = 254;

/// Trim, lowercase and shallowly check an address.
///
/// Deliberately shallow. The only thing that proves an address works is
/// sending to it, and a strict grammar here would reject deliverable addresses
/// (quoted local parts, new TLDs, unicode domains) to catch typos it cannot
/// catch anyway. This rejects what is obviously not an address and lets the
/// rest through.
///
/// Lowercasing is what makes the primary key do its job: `Ada@example.com` and
/// `ada@example.com` are one person on every mail host that matters, and
/// storing both would put them in the queue twice.
pub fn validate_email(raw: &str) -> Result<String, String> {
    let email = raw.trim().to_lowercase();

    if email.is_empty() {
        return Err("email is required".into());
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err("that address is too long".into());
    }

    let looks_like_one = match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.contains('@')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && domain.contains('.')
                && !email.contains(char::is_whitespace)
        }
        None => false,
    };

    if !looks_like_one {
        return Err("that does not look like an email address".into());
    }

    Ok(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_normalized_before_it_is_stored() {
        // Both halves matter: the trim is why a pasted address with a trailing
        // space is not a second row, the lowercase is why a capitalized one
        // is not either.
        assert_eq!(
            validate_email("  Ada@Example.COM ").unwrap(),
            "ada@example.com"
        );
    }

    #[test]
    fn obvious_non_addresses_are_rejected() {
        for bad in [
            "",
            "   ",
            "ada",
            "@example.com",
            "ada@example",
            "ada@.com",
            "ada@example.",
            "ada@one@two.com",
            "ada name@example.com",
        ] {
            assert!(
                validate_email(bad).is_err(),
                "{bad:?} should not pass as an address"
            );
        }
    }

    #[test]
    fn plausible_addresses_are_left_alone() {
        for good in [
            "ada@example.com",
            "ada+waitlist@example.co.uk",
            "a.b-c_d@sub.example.eu",
        ] {
            assert_eq!(validate_email(good).unwrap(), good);
        }
    }
}
