pub const BOOTSTRAP_PACKAGE: &str = "com.rasp.runtime.bootstrap";
pub const BOOTSTRAP_PROVIDER_CLASS: &str = "com.rasp.runtime.bootstrap.RaspInitProvider";

pub fn next_dex_name(existing_dex_count: usize) -> String {
    match existing_dex_count {
        0 | 1 => "classes2.dex".to_string(),
        count => format!("classes{}.dex", count + 1),
    }
}

pub fn next_dex_name_for_paths<'a>(paths: impl IntoIterator<Item = &'a String>) -> String {
    let max_index = paths
        .into_iter()
        .filter_map(|path| dex_index(path))
        .max()
        .unwrap_or(1);
    format!("classes{}.dex", max_index + 1)
}

fn dex_index(path: &str) -> Option<usize> {
    if path == "classes.dex" {
        return Some(1);
    }

    path.strip_prefix("classes")
        .and_then(|value| value.strip_suffix(".dex"))
        .filter(|value| !value.is_empty())
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::{next_dex_name, next_dex_name_for_paths};

    #[test]
    fn selects_next_multidex_name() {
        assert_eq!(next_dex_name(1), "classes2.dex");
        assert_eq!(next_dex_name(2), "classes3.dex");
    }

    #[test]
    fn selects_next_dex_name_from_existing_paths() {
        let paths = vec![
            "classes.dex".to_string(),
            "classes2.dex".to_string(),
            "classes10.dex".to_string(),
            "assets/classes999.dex".to_string(),
        ];

        assert_eq!(next_dex_name_for_paths(&paths), "classes11.dex");
    }
}
