//! Derivation path module.
use std::fmt::Write;

/// BIP32 derivation path.
#[derive(Debug)]
pub struct DerivationPath(Vec<Child>);

impl DerivationPath {
    pub fn new(value: &str) -> Result<Self, Error> {
        let mut segments = value.split('/');
        match segments.next() {
            Some(m) if m == "m" => (),
            _ => return Err(Error::InvalidFormat),
        }

        let children = segments
            .map(Child::from_str)
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        if children.len() > 12 {
            return Err(Error::TooDeep);
        }

        Ok(Self(children))
    }

    pub fn children(&self) -> &[Child] {
        &self.0
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_char('m')?;
        for child in self.0.iter() {
            f.write_fmt(format_args!("/{}", child))?;
        }
        Ok(())
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self(Default::default())
    }
}

/// Derivation path child segment.
#[derive(Debug, PartialEq, Eq)]
pub enum Child {
    Normal(u32),
    Hardened(u32),
}

impl Child {
    pub fn from_str(c: &str) -> Result<Self, Error> {
        let is_hardened = c.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        let i: u32 = (if is_hardened { &c[0..c.len() - 1] } else { c })
            .parse()
            .map_err(|_| Error::InvalidChild)?;

        if i & (1 << 31) == 0 {
            if is_hardened {
                Ok(Child::Hardened(i))
            } else {
                Ok(Child::Normal(i))
            }
        } else {
            Err(Error::InvalidChild)
        }
    }

    pub fn value(&self) -> u32 {
        match self {
            Child::Normal(i) => *i,
            Child::Hardened(i) => i | (1 << 31),
        }
    }
}

impl std::fmt::Display for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Child::Normal(i) => std::fmt::Display::fmt(&i, f),
            Child::Hardened(i) => {
                std::fmt::Display::fmt(&i, f)?;
                f.write_char('\'')
            }
        }
    }
}

/// Derivation path error.
#[derive(Debug)]
pub enum Error {
    InvalidChild,
    InvalidFormat,
    TooDeep,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse() {
        let path = DerivationPath::new("m/44'/1'/2'/3/4").unwrap();
        let mut path = path.0.iter();
        assert_eq!(Some(&Child::Hardened(44)), path.next());
        assert_eq!(Some(&Child::Hardened(1)), path.next());
        assert_eq!(Some(&Child::Hardened(2)), path.next());
        assert_eq!(Some(&Child::Normal(3)), path.next());
        assert_eq!(Some(&Child::Normal(4)), path.next());
        assert_eq!(None, path.next());
    }
}
