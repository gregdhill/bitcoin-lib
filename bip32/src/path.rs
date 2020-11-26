const MASTER_SYMBOL: &str = "m";
const SEPARATOR: &str = "/";
const HARDENED_SYMBOLS: [&str; 2] = ["H", "'"];

#[derive(Debug, Eq, PartialEq)]
pub struct Path(Vec<Index>);

#[derive(Debug, Eq, PartialEq)]
pub enum Index {
    Normal(u32),
    Hardened(u32),
}

impl From<String> for Path {
    fn from(path: String) -> Self {
        Path(
            path.split(SEPARATOR)
                .filter(|path| *path != MASTER_SYMBOL)
                .map(|path| {
                    if path.contains(HARDENED_SYMBOLS[0]) || path.contains(HARDENED_SYMBOLS[1]) {
                        Index::Hardened(path[..path.len() - 1].parse::<u32>().unwrap())
                    } else {
                        Index::Normal(path.parse::<u32>().unwrap())
                    }
                })
                .collect::<Vec<Index>>(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path() {
        assert_eq!(Path::from("m/0".to_string()).0, vec![Index::Normal(0)]);
        assert_eq!(Path::from("m/0'".to_string()).0, vec![Index::Hardened(0)]);
        assert_eq!(Path::from("m/0H".to_string()).0, vec![Index::Hardened(0)]);
        assert_eq!(
            Path::from("m/0'/0".to_string()).0,
            vec![Index::Hardened(0), Index::Normal(0)]
        );
    }
}
