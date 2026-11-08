use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

/// A dotted version number with the parsing, ordering and equality rules of
/// Chromium's `base::Version`: missing trailing components count as zero, so
/// `1.0 == 1`.
#[derive(Clone, Debug)]
pub struct Version(Vec<u32>);

/// Returned for a string that isn't dot-separated decimal `u32`s, or whose
/// first component has a leading zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseVersionError;

impl fmt::Display for ParseVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid version")
    }
}

impl std::error::Error for ParseVersionError {}

impl Version {
    /// The numbers between the dots, as parsed: `1.0` gives `[1, 0]`.
    pub fn components(&self) -> &[u32] {
        &self.0
    }

    /// Whether this is valid as an extension's manifest version, which
    /// allows at most four components.
    pub fn is_valid_extension_version(&self) -> bool {
        self.0.len() <= 4
    }
}

impl FromStr for Version {
    type Err = ParseVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = Vec::new();
        for (i, part) in s.split('.').enumerate() {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ParseVersionError);
            }

            let n: u32 = part.parse().map_err(|_| ParseVersionError)?;
            // base::Version rejects leading zeros in the first component only.
            if i == 0 && n.to_string() != part {
                return Err(ParseVersionError);
            }

            components.push(n);
        }
        Ok(Version(components))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, n) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }

            write!(f, "{n}")?;
        }
        Ok(())
    }
}

impl Ord for Version {
    /// Missing trailing components count as zero, so `1.0` equals `1`.
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.0.len().max(other.0.len());
        (0..len)
            .map(|i| {
                let a = self.0.get(i).copied().unwrap_or(0);
                let b = other.0.get(i).copied().unwrap_or(0);
                a.cmp(&b)
            })
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let significant = self.0.iter().rposition(|&n| n != 0).map_or(0, |i| i + 1);
        self.0[..significant].hash(state);
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        s.parse().unwrap()
    }

    #[test]
    fn parses() {
        assert_eq!(v("1.2.3.4").components(), &[1, 2, 3, 4]);
        assert_eq!(v("0").components(), &[0]);
        assert_eq!(v("1.02").components(), &[1, 2]);
        assert_eq!(v("4294967295").components(), &[u32::MAX]);
    }

    #[test]
    fn rejects() {
        for s in [
            "",
            ".",
            "1.",
            ".1",
            "1..2",
            "01",
            "+1",
            "-1",
            "1.+2",
            "1.a",
            " 1",
            "4294967296",
        ] {
            assert!(s.parse::<Version>().is_err(), "{s:?}");
        }
    }

    #[test]
    fn orders() {
        assert!(v("1.0.0.1") > v("1"));
        assert!(v("1.10") > v("1.9"));
        assert!(v("2") > v("1.99.99.99"));
        assert_eq!(v("1.0").cmp(&v("1")), Ordering::Equal);
    }

    #[test]
    fn equality_matches_ordering() {
        use std::collections::HashSet;
        assert_eq!(v("1.0"), v("1"));
        assert_eq!(v("0.0.0.0"), v("0"));
        assert_ne!(v("1.0.1"), v("1"));
        let set: HashSet<_> = [v("1"), v("1.0"), v("1.0.0.0"), v("1.0.0.1")]
            .into_iter()
            .collect();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn extension_version_limit() {
        assert!(v("1.2.3.4").is_valid_extension_version());
        assert!(!v("1.2.3.4.5").is_valid_extension_version());
    }

    #[test]
    fn displays() {
        assert_eq!(v("1.02.3").to_string(), "1.2.3");
    }
}
