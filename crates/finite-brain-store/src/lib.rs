//! FiniteBrain SQLite store and transaction boundary.

/// Returns the crate name used in workspace status surfaces.
pub fn crate_name() -> &'static str {
    "finite-brain-store"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_store_crate_name() {
        assert_eq!(crate_name(), "finite-brain-store");
    }
}
