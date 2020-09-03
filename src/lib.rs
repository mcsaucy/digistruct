use bytes::Bytes;
use ring::digest;
use std::collections::HashMap;
use std::rc::Rc;
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

pub struct Digistructor {
    graph: HashMap<Vec<u8>, Node>,
}

impl Digistructor {
    pub fn new() -> Self {
        Digistructor {
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
            let mut ds = Digistructor::new();
            ds.add(Node::Raw(want.clone()));

            let have = ds.get(&want.digest)?;
            assert_eq!(want.data, have.as_ref());
            Ok(())
        }

        #[test]
        fn corrupted() {
            let want = Leaf {
                digest: Vec::from(b"badhash" as &[u8]),
                data: Vec::from(b"abc" as &[u8]),
            };
            let mut ds = Digistructor::new();
            ds.add(Node::Raw(want.clone()));

            let have = ds.get(&want.digest);
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
            let mut ds = Digistructor::new();

            ds.add(Node::Raw(a));
            ds.add(Node::Raw(b));
            ds.add(Node::Raw(c));
            ds.add(Node::Raw(d));

            ds.add(Node::Append(ab));
            ds.add(Node::Append(cd));
            ds.add(Node::Append(abcd));

            let want = Bytes::from(b"abcd" as &[u8]);
            let have = ds.get(&sha256(b"abcd"))?;
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
            let mut ds = Digistructor::new();

            ds.add(Node::Raw(a));
            ds.add(Node::Raw(b));
            ds.add(Node::Raw(c));
            ds.add(Node::Raw(d));

            ds.add(Node::Append(bc));
            ds.add(Node::Append(bcd));
            ds.add(Node::Append(abcd));

            let want = Bytes::from(b"abcd" as &[u8]);
            match ds.get(&sha256(b"abcd")) {
                Ok(have) => assert_eq!(want, have),
                Err(err) => panic!("unexpected error {}", err),
            };
            Ok(())
        }
    }
    mod sqlite {
        use super::*;

        fn mkdb() -> rusqlite::Connection {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            conn.execute(
                "CREATE TABLE data_leaves (
                    digest  BLOB PRIMARY KEY,
                    data BLOB NOT NULL
                );",
                rusqlite::NO_PARAMS,
            )
            .unwrap();
            conn.execute(
                "CREATE TABLE append_edges (
                    digest BLOB NOT NULL,
                    left BLOB NOT NULL,
                    right BLOB NOT NULL,
                    PRIMARY KEY(digest, left, right)
                );
                --CREATE TABLE patch_edges (
                --    digest BLOB PRIMARY_KEY,
                --    basis BLOB PRIMARY KEY,
                --    patch BLOB PRIMARY KEY,
                --);",
                rusqlite::NO_PARAMS,
            )
            .unwrap();
            return conn;
        }

        fn insert_dataleaf(conn: &rusqlite::Connection, leaf: &Leaf) -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO data_leaves (digest, data) VALUES (?1, ?2);",
                &[&leaf.digest, &leaf.data],
            )?;
            Ok(())
        }
        fn insert_appendedge(
            conn: &rusqlite::Connection,
            edge: &AppendEdge,
        ) -> rusqlite::Result<()> {
            conn.execute(
                "INSERT INTO append_edges (digest, left, right) VALUES (?1, ?2, ?3);",
                &[&edge.digest, &edge.left, &edge.right],
            )?;
            Ok(())
        }

        #[test]
        fn sqlite() -> Result<(), rusqlite::Error> {
            let conn = mkdb();
            let a = raw(b"a");
            let b = raw(b"b");
            let c = raw(b"c");
            let d = raw(b"d");

            insert_dataleaf(&conn, &a)?;
            insert_dataleaf(&conn, &b)?;
            insert_dataleaf(&conn, &c)?;
            insert_dataleaf(&conn, &d)?;

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

            insert_appendedge(&conn, &bc)?;
            insert_appendedge(&conn, &bcd)?;
            insert_appendedge(&conn, &abcd)?;

            /*
             * OK, so this is gonna suck. We need a scalable way to construct trees from more than
             * just raw and append nodes. All trees end with raw data leaves (which is nice), but
             * shit breaks down really quickly when we start thinking about adding new types of
             * nodes. Presently, we query for all edges and strip out all nodes we know may be
             * satisfied by a leaf instead (it's cheaper, after all). We could try to do the same
             * things with a new type (let's call it a patch node), but things break down if we do
             * append(raw, patch(raw, append(raw, raw))). We'd need to bridge the gap in append
             * node processing caused by the switch to patch-typed nodes.

             * A possible approach would be to throw everything into a single table with a "kind"
             * column that we used to determine which columns we would inspect. Something like:
             * (composite_id, digest, kind, data, left, right, basis, patch)
             * "composite_id" is the SHA256(data) or SHA256(left + right) or SHA256(basis, patch),
             * depending upon the kind, for use in constructing a primary key.
            */
            conn.execute(
                "CREATE TEMPORARY TABLE edges AS

                WITH RECURSIVE branches (digest, left, right) AS (
                    SELECT digest, left, right
                    FROM append_edges
                    WHERE digest = ?1
                        -- drop if a cheaper way exists
                        AND digest NOT IN (SELECT digest FROM data_leaves)

                    UNION ALL

                    SELECT child.digest, child.left, child.right
                    FROM append_edges child
                    JOIN branches parent
                    ON child.digest IN (parent.left, parent.right)
                    WHERE
                        -- drop if a cheaper way exists
                        parent.digest NOT IN (SELECT digest FROM data_leaves)
                )
                SELECT * FROM branches;",
                rusqlite::params![sha256(b"abcd")],
            )?;

            let mut edge_stmt = conn.prepare("SELECT * FROM edges")?;
            let edges = edge_stmt.query_map(rusqlite::NO_PARAMS, |row| {
                let edge = AppendEdge {
                    digest: row.get(0)?,
                    left: row.get(1)?,
                    right: row.get(2)?,
                };
                Ok(edge)
            })?;

            let mut ds = Digistructor::new();
            let mut digs = std::collections::HashSet::new();

            for n in edges {
                let edge = n?;

                digs.insert(edge.digest.clone());
                digs.insert(edge.left.clone());
                digs.insert(edge.right.clone());

                ds.add(Node::Append(edge));
            }
            let values = Rc::new(
                digs.iter()
                    .filter(|d| ds.check(d))
                    .cloned()
                    .map(rusqlite::types::Value::from)
                    .collect::<Vec<rusqlite::types::Value>>(),
            );

            let mut find_leaves = conn.prepare(
                "SELECT digest, data FROM data_leaves
                WHERE
                    digest IN (SELECT digest FROM edges)
                    OR digest IN (SELECT left FROM edges)
                    OR digest IN (SELECT right FROM edges);",
            )?;
            let leaves = find_leaves.query_map(rusqlite::NO_PARAMS, |row| {
                let leaf = Leaf {
                    digest: row.get(0)?,
                    data: row.get(1)?,
                };
                Ok(leaf)
            })?;

            for n in leaves {
                ds.add(Node::Raw(n?));
            }

            let want = Bytes::from(b"abcd" as &[u8]);
            let have = ds.get(&sha256(b"abcd")).expect("failed to get abcd");
            assert_eq!(want, have);

            Ok(())
        }
    }
}
