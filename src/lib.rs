use bytes::Bytes;
use ring::digest;
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Debug)]
pub enum Error {
    DigestMismatch(/* want */ Vec<u8>, /* have */ Vec<u8>),
    NotFound(Vec<u8>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DigestMismatch(want, have) => write!(
                f,
                "digest mismatch; want {:?}, have {:?}",
                hex::encode(&want),
                hex::encode(&have)
            ),
            Error::NotFound(digest) => write!(
                f,
                "cannot find data or a way to construct {}",
                hex::encode(digest)
            ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Leaf {
    digest: Vec<u8>,
    data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AppendEdge {
    digest: Vec<u8>,
    left: Vec<u8>,
    right: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Node {
    Raw(Leaf),
    Append(AppendEdge),
}

pub struct Hippo {
    graph: HashMap<Vec<u8>, Node>,
}

impl Hippo {
    pub fn new() -> Self {
        Hippo {
            graph: HashMap::new(),
        }
    }

    pub fn add(&mut self, node: Node) {
        let dig = match &node {
            Node::Raw(leaf) => leaf.digest.clone(),
            Node::Append(edge) => edge.digest.clone(),
        };
        self.graph.insert(dig.clone(), node);
    }

    pub fn check(&self, want: &Vec<u8>) -> bool {
        self.graph.contains_key(want)
    }

    pub fn get(&self, want: &Vec<u8>) -> Result<Bytes, Error> {
        let node = match self.graph.get(want) {
            None => {
                return Err(Error::NotFound(want.clone()));
            }
            Some(node) => node,
        };
        let digest = match node {
            Node::Raw(leaf) => &leaf.digest,
            Node::Append(edge) => &edge.digest,
        };
        if *want != *digest {
            panic!(
                "Map retrieved the wrong node. This is a bug. Expected {}, got {}",
                hex::encode(want),
                hex::encode(digest)
            );
        }

        let content = match node {
            Node::Raw(leaf) => Bytes::from(leaf.data.clone()),
            Node::Append(edge) => {
                let left = self.get(&edge.left)?;
                let right = self.get(&edge.right)?;
                Bytes::from([&left[..], &right[..]].concat())
            }
        };
        let computed_digest = sha256(&content);
        if computed_digest != *want {
            return Err(Error::DigestMismatch(want.clone(), computed_digest));
        }
        return Ok(content);
    }
}

pub fn raw(content: &[u8]) -> Leaf {
    let dig = digest::digest(&digest::SHA256, content);
    Leaf {
        digest: Vec::from(dig.as_ref()),
        data: Vec::from(content),
    }
}
fn sha256(bytes: &[u8]) -> Vec<u8> {
    return Vec::from(digest::digest(&digest::SHA256, bytes).as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;

    mod raw {
        use super::*;
        #[test]
        fn ok() -> Result<(), Error> {
            let want = raw(b"abc" as &[u8]);
            let mut hippo = Hippo::new();
            hippo.add(Node::Raw(want.clone()));

            let have = hippo.get(&want.digest)?;
            assert_eq!(want.data, have.as_ref());
            Ok(())
        }

        #[test]
        fn corrupted() {
            let want = Leaf {
                digest: Vec::from(b"badhash" as &[u8]),
                data: Vec::from(b"abc" as &[u8]),
            };
            let mut hippo = Hippo::new();
            hippo.add(Node::Raw(want.clone()));

            let have = hippo.get(&want.digest);
            match have {
                Ok(_) => panic!("failed to catch digest mismatch"),
                Err(e) => match e {
                    Error::DigestMismatch(_, _) => {}
                    _ => panic!("DigestMismatch expected; got {}", e),
                },
            }
        }
    }

    mod append {
        use super::*;

        #[test]
        fn ok_balanced() -> Result<(), Error> {
            let a = raw(b"a");
            let b = raw(b"b");
            let c = raw(b"c");
            let d = raw(b"d");

            let ab = AppendEdge {
                digest: sha256(b"ab"),
                left: a.digest.clone(),
                right: b.digest.clone(),
            };

            let cd = AppendEdge {
                digest: sha256(b"cd"),
                left: c.digest.clone(),
                right: d.digest.clone(),
            };

            let abcd = AppendEdge {
                digest: sha256(b"abcd"),
                left: ab.digest.clone(),
                right: cd.digest.clone(),
            };
            let mut hippo = Hippo::new();

            hippo.add(Node::Raw(a));
            hippo.add(Node::Raw(b));
            hippo.add(Node::Raw(c));
            hippo.add(Node::Raw(d));

            hippo.add(Node::Append(ab));
            hippo.add(Node::Append(cd));
            hippo.add(Node::Append(abcd));

            let want = Bytes::from(b"abcd" as &[u8]);
            let have = hippo.get(&sha256(b"abcd"))?;
            assert_eq!(want, have);
            Ok(())
        }

        #[test]
        fn ok_unbalanced() -> Result<(), Error> {
            let a = raw(b"a");
            let b = raw(b"b");
            let c = raw(b"c");
            let d = raw(b"d");

            let bc = AppendEdge {
                digest: sha256(b"bc"),
                left: b.digest.clone(),
                right: c.digest.clone(),
            };

            let bcd = AppendEdge {
                digest: sha256(b"bcd"),
                left: bc.digest.clone(),
                right: d.digest.clone(),
            };

            let abcd = AppendEdge {
                digest: sha256(b"abcd"),
                left: a.digest.clone(),
                right: bcd.digest.clone(),
            };
            let mut hippo = Hippo::new();

            hippo.add(Node::Raw(a));
            hippo.add(Node::Raw(b));
            hippo.add(Node::Raw(c));
            hippo.add(Node::Raw(d));

            hippo.add(Node::Append(bc));
            hippo.add(Node::Append(bcd));
            hippo.add(Node::Append(abcd));

            let want = Bytes::from(b"abcd" as &[u8]);
            match hippo.get(&sha256(b"abcd")) {
                Ok(have) => assert_eq!(want, have),
                Err(err) => panic!("unexpected error {}", err),
            };
            Ok(())
        }
    }
}
