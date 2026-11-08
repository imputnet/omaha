//! Differential updates for Chromium's update protocol.

/// A SHA-256 hash of a full payload.
pub type Hash = [u8; 32];

/// Patch formats Chromium's update client can apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    Puffin,
    Zucchini,
}

impl Format {
    /// The operation `type` in an Omaha 4 pipeline.
    pub fn operation_type(self) -> &'static str {
        match self {
            Format::Puffin => "puff",
            Format::Zucchini => "zucc",
        }
    }
}

/// A patch that turns the payload `from` into the payload `to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Patch {
    pub format: Format,
    pub from: Hash,
    pub to: Hash,
    pub size: u64,
}

/// Picks the smallest patch to `to` from any payload the client has cached.
/// Returns `None` if the client needs the full payload.
pub fn select<'a>(patches: &'a [Patch], cached: &[Hash], to: &Hash) -> Option<&'a Patch> {
    patches
        .iter()
        .filter(|p| &p.to == to && cached.contains(&p.from))
        .min_by_key(|p| p.size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(format: Format, from: u8, to: u8, size: u64) -> Patch {
        Patch {
            format,
            from: [from; 32],
            to: [to; 32],
            size,
        }
    }

    #[test]
    fn selects_smallest_applicable() {
        let patches = [
            patch(Format::Puffin, 1, 3, 100),
            patch(Format::Zucchini, 2, 3, 50),
            patch(Format::Puffin, 2, 4, 10),
        ];
        assert_eq!(select(&patches, &[[1; 32]], &[3; 32]), Some(&patches[0]));
        assert_eq!(
            select(&patches, &[[1; 32], [2; 32]], &[3; 32]),
            Some(&patches[1])
        );
        assert_eq!(select(&patches, &[[9; 32]], &[3; 32]), None);
        assert_eq!(select(&patches, &[], &[3; 32]), None);
    }

    #[test]
    fn operation_types() {
        assert_eq!(Format::Puffin.operation_type(), "puff");
        assert_eq!(Format::Zucchini.operation_type(), "zucc");
    }
}
