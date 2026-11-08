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

/// An application ID: an extension or component ID, or a GUID-style ID for
/// installed software such as a browser. Non-empty printable ASCII.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AppId(String);

impl AppId {
    pub fn new(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        (!id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic())).then_some(AppId(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is an extension or component ID.
    pub fn is_crx_id(&self) -> bool {
        is_valid_crx_id(&self.0)
    }
}

impl std::fmt::Display for AppId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod app_id_tests {
    use super::AppId;

    #[test]
    fn validates() {
        assert!(
            AppId::new("jpignaibiiemhngfjkcpokkamffknabf")
                .unwrap()
                .is_crx_id()
        );
        assert!(
            !AppId::new("{8A69D345-D564-463C-AFF1-A69D9E530F96}")
                .unwrap()
                .is_crx_id()
        );
        for bad in ["", "a b", "a\nb", "é"] {
            assert_eq!(AppId::new(bad), None, "{bad:?}");
        }
    }
}
