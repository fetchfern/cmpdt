use std::fs::{self as fs_sync, File};
#[cfg(feature = "unix")]
use std::os::unix::fs::MetadataExt;
use std::ffi::OsString;
use std::path::PathBuf;
use std::io::{self, Read};
use std::collections::HashMap;

use sha2::Sha256;
use sha2::digest::Digest;

/// A directory diff node.  
///
/// A [`File`](DiffNode::File) variant corresponds to a file. The [`Leaf`] value refers to the original file
/// while the [`Delta`] value is a view on the difference between the compared file vs original
/// file, see [`Delta`] documentation.
#[derive(Debug)]
pub enum DiffNode {
    File(Leaf, Delta),
    Dir(DiffDir),
}

/// Describes a difference between an original and compared file.  
///
/// [`Missing`](Delta::Missing): The file is missing.  
/// [`NoMatch`](Delta::NoMatch): Some file metadata doesn't match, such as file content or mode (on
/// Unix).  
/// [`Excess`](Delta::Excess): The file isn't present in the original file tree, but exists in the
/// compared file tree. In this case, an attached [`Leaf`] alongside this delta will likely
/// refer to the excess file.  
/// [`Ok`](Delta::Ok): The file is present and equal.  
#[derive(Debug, Clone)]
pub enum Delta {
    Missing,
    NoMatch {
        cmp: Leaf,
    },
    Ok,
    Excess,
}

/// Metadata about a file.  
///
/// With the `unix` feature enabled, the `mode` field is present.
#[derive(Debug, Clone)]
pub struct Leaf {
    #[cfg(feature = "unix")]
    pub mode: u32,
    pub contents_sha256_str: String,
}

impl Leaf {
    /// Compares `self` as an original leaf with another leaf.  
    pub fn versus(&self, rhs: Leaf) -> Delta {
        #[cfg(feature = "unix")]
        let lhs = self.mode != rhs.mode;
        #[cfg(not(feature = "unix"))]
        let lhs = false;

        if lhs || self.contents_sha256_str != rhs.contents_sha256_str {
            Delta::NoMatch { cmp: rhs }
        } else {
            Delta::Ok
        }
   }
}

/// A directory node.  
#[derive(Debug, Default)]
pub struct DiffDir {
    pub children: HashMap<OsString, DiffNode>,
}

/// Compares two directory trees.  
///
/// # Errors
/// In the case of some unexpected IO errors, such as a the `truth` and `cmp` paths not existing
/// or other unexpected errors, returns [`Err`](std::result::Result::Err).
pub fn cmp_dtree(truth: PathBuf, cmp: PathBuf) -> io::Result<DiffDir> {
    let mut root = DiffDir::default();
    mk_tree(truth, &mut root, &Delta::Missing)?;
    resolv_diff(cmp, &mut root)?;

    Ok(root)
}

fn mk_tree(from: PathBuf, node: &mut DiffDir, mark_leaves: &Delta) -> io::Result<()> {     
    // from here, `from` should've been obtained from a `readdir` call, so it very likely exists
    let readdir = fs_sync::read_dir(&from)?;

    for dirent_r in readdir {
        let dirent = dirent_r?;
        let ftype = dirent.file_type()?;

        if ftype.is_dir() {
            let mut diff_dir = DiffDir::default();
            mk_tree(dirent.path(), &mut diff_dir, mark_leaves)?;

            node.children.insert(dirent.file_name(), DiffNode::Dir(diff_dir));
        } else if ftype.is_file() {
            let path = dirent.path();
            #[cfg(feature = "unix")]
            let mode = dirent.metadata()?.mode();

            let mut file = File::open(&path)?;

            let mut read_buf = vec![0; 4096];
            let mut sha256 = Sha256::new();

            loop {
                match file.read(&mut read_buf) {
                    Ok(0) => break,
                    Ok(read) => {
                        let portion = &read_buf[..read];
                        sha256.update(portion);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            let digest = hex::encode(&sha256.finalize()[..]);

            let leaf = Leaf {
                #[cfg(feature = "unix")]
                mode,
                contents_sha256_str: digest,
            };

            node.children.insert(dirent.file_name(), DiffNode::File(leaf, mark_leaves.clone()));
        }
    }

    Ok(())
}

fn resolv_diff(cmp: PathBuf, node: &mut DiffDir) -> io::Result<()> {     
    // from here, `cmp` should've been obtained from a `readdir` call, so it very likely exists
    let readdir = fs_sync::read_dir(&cmp)?;

    for dirent_r in readdir {
        let dirent = dirent_r?;
        let ftype = dirent.file_type()?;

        let file_name = dirent.file_name();
        let cmp_against = node.children.get_mut(&file_name);

        match cmp_against {
            Some(DiffNode::Dir(ref mut against_dir)) => {
                if ftype.is_dir() {
                    resolv_diff(dirent.path(), against_dir)?;
                } else {
                    set_missing_deep(against_dir);
                }
            }

            Some(DiffNode::File(ref original, ref mut delta)) => {
                if ftype.is_file() {
                    match File::open(dirent.path()) {
                        Ok(mut f) => {
                            let digest = compute_digest256(&mut f)?;
                            #[cfg(feature = "unix")]
                            let mode = dirent.metadata()?.mode();
                            let new_delta = original.versus(Leaf {
                                #[cfg(feature = "unix")]
                                mode,
                                contents_sha256_str: digest
                            });
                            *delta = new_delta;
                        }

                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            *delta = Delta::Missing;
                        }

                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }

            None => {
                if ftype.is_dir() {
                    // theres a whole directory tree that's in excess, recursively mark
                    let mut diff_dir = DiffDir::default();
                    mk_tree(dirent.path(), &mut diff_dir, &Delta::Excess)?;
                    node.children.insert(dirent.file_name(), DiffNode::Dir(diff_dir));
                } else if ftype.is_file() {
                    // theres a single files in excess

                    match File::open(dirent.path()) {
                        Ok(mut f) => {
                            #[cfg(feature = "unix")]
                            let mode = dirent.metadata()?.mode(); 
                            let digest = compute_digest256(&mut f)?;

                            let leaf = Leaf {
                                #[cfg(feature = "unix")]
                                mode,
                                contents_sha256_str: digest,
                            };
                            node.children.insert(dirent.file_name(), DiffNode::File(leaf, Delta::Excess));
                        },

                        Err(e) if e.kind() == io::ErrorKind::NotFound => {},
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    Ok(())
}

fn set_missing_deep(dir: &mut DiffDir) {
    for child in dir.children.values_mut() {
        match child {
            DiffNode::Dir(ref mut child) => set_missing_deep(child),
            DiffNode::File(_, ref mut d) => *d = Delta::Missing,
        }
    }
}

/// Compute's the file's sha256 digests and returns is hex-encoded. This uses
/// its own heap allocation.
fn compute_digest256(f: &mut File) -> io::Result<String> {
    let mut read_buf = vec![0; 4096];
    let mut sha256 = Sha256::new();

    loop {
        match f.read(&mut read_buf) {
            Ok(0) => break,
            Ok(read) => {
                let portion = &read_buf[..read];
                sha256.update(portion);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let digest = hex::encode(&sha256.finalize()[..]);
    Ok(digest)
}

