/// Length of an extension or component ID.
pub const CRX_ID_LEN: usize = 32;

/// Whether `id` is a well-formed extension or component ID: 32 characters
/// from `a` to `p`, as produced by `crx_file::id_util::GenerateId`.
pub fn is_valid_crx_id(id: &str) -> bool {
    id.len() == CRX_ID_LEN && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ids() {
        assert!(is_valid_crx_id("jpignaibiiemhngfjkcpokkamffknabf"));
        assert!(is_valid_crx_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(is_valid_crx_id("pppppppppppppppppppppppppppppppp"));
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(!is_valid_crx_id(""));
        assert!(!is_valid_crx_id("jpignaibiiemhngfjkcpokkamffknab"));
        assert!(!is_valid_crx_id("jpignaibiiemhngfjkcpokkamffknabfa"));
        assert!(!is_valid_crx_id("qpignaibiiemhngfjkcpokkamffknabf"));
        assert!(!is_valid_crx_id("JPIGNAIBIIEMHNGFJKCPOKKAMFFKNABF"));
    }
}
