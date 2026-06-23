//! FiniteBrain Portable v1 core domain and validation logic.

/// Returns the crate name used in workspace status surfaces.
pub fn crate_name() -> &'static str {
    "finite-brain-core"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_core_crate_name() {
        assert_eq!(crate_name(), "finite-brain-core");
    }
}
