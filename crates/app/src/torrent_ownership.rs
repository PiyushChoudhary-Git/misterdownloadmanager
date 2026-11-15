//! Deletion authority is a receipt for an object we created, not a torrent path.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub index: usize,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ownership {
    pub token: String,
    pub files: Vec<Claim>,
}

/// The ledger's format. A newer one than this build knows is read as "keep everything".
const LEDGER_VERSION: u32 = 1;

/// Volume or device, file index or inode, and creation time (see `win32.rs`, `unix.rs`).
type Identity = [u64; 3];

#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    token: String,
    /// Files MDM never deletes: present when the torrent was added (the person agreed to use
    /// them), or whose identity could not be had.
    #[serde(default)]
    protected: Vec<usize>,
    #[serde(default)]
    files: Vec<Receipt>,
    #[serde(default)]
    directories: Vec<Receipt>,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    index: usize,
    path: PathBuf,
    identity: Identity,
}

#[cfg(unix)]
use crate::unix::{
    remove_owned_torrent_file, torrent_file_identity as identity,
    torrent_file_identity_at as identity_at,
};
#[cfg(windows)]
use crate::win32::{
    remove_owned_torrent_file, torrent_file_identity as identity,
    torrent_file_identity_at as identity_at,
};

/// Resolve existing ancestors too, so aliases and case differences cannot evade a claim.
pub fn key(path: &Path) -> PathBuf {
    let mut ancestor = path.to_owned();
    let mut tail = Vec::new();
    while !ancestor.exists() {
        let Some(name) = ancestor.file_name().map(|s| s.to_owned()) else {
            break;
        };
        tail.push(name);
        if !ancestor.pop() {
            break;
        }
    }
    let mut resolved = ancestor.canonicalize().unwrap_or(ancestor);
    for name in tail.into_iter().rev() {
        resolved.push(name);
    }
    #[cfg(any(windows, target_os = "macos"))]
    {
        resolved = PathBuf::from(resolved.to_string_lossy().to_lowercase());
    }
    resolved
}

fn claimed(set: &BTreeSet<PathBuf>, path: &Path) -> bool {
    path.ancestors().any(|p| set.contains(p))
        || set
            .range(path.to_owned()..)
            .next()
            .is_some_and(|p| p.starts_with(path))
}

/// The drive or filesystem root a path starts on, for comparing without touching the disk.
fn root_of(path: &Path) -> Option<String> {
    path.components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
}

pub fn conflicts(paths: &[PathBuf], claims: &[PathBuf], canonical: bool) -> Vec<PathBuf> {
    let normalize = |path: &PathBuf| {
        if canonical {
            return key(path);
        }
        #[cfg(any(windows, target_os = "macos"))]
        {
            PathBuf::from(path.to_string_lossy().to_lowercase())
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            path.clone()
        }
    };
    // Looking at a claim means opening it: leave alone those on another drive than any of the
    // paths asked about, so a sleeping USB stick or a network share is not woken for nothing.
    let roots: std::collections::HashSet<_> = paths.iter().filter_map(|p| root_of(p)).collect();
    let near: Vec<&PathBuf> = claims
        .iter()
        .filter(|c| !canonical || root_of(c).is_some_and(|r| roots.contains(&r)))
        .collect();
    let set: BTreeSet<_> = near.iter().map(|p| normalize(p)).collect();
    let identities: std::collections::HashSet<_> = if canonical {
        near.iter().filter_map(|p| identity_at(p).ok()).collect()
    } else {
        Default::default()
    };
    paths
        .iter()
        .filter(|p| {
            claimed(&set, &normalize(p))
                || (canonical && identity_at(p).is_ok_and(|id| identities.contains(&id)))
        })
        .cloned()
        .collect()
}

impl Ownership {
    pub fn validate(&self, bytes: &[u8], hash: &str) -> io::Result<()> {
        let meta = mdm_torrent::librqbit::torrent_from_bytes(bytes).map_err(io::Error::other)?;
        let files = mdm_torrent::files_from_bytes(bytes).map_err(io::Error::other)?;
        let count = files.iter().filter(|f| !f.padding).count();
        if !meta.info_hash.as_string().eq_ignore_ascii_case(hash)
            || count != self.files.len()
            || self.files.iter().any(|claim| {
                files
                    .get(claim.index)
                    .is_none_or(|f| f.padding || (count != 1 && f.path != claim.path))
            })
        {
            return Err(io::Error::other(crate::i18n::t(
                // i18n: error when the saved record of a torrent's files differs from the .torrent file
                "The torrent ownership record does not match its file list",
            )));
        }
        Ok(())
    }
    pub fn new(meta: &mdm_torrent::Meta) -> Self {
        Self {
            token: mdm_ipc::random_token(),
            files: meta
                .files
                .iter()
                .enumerate()
                .filter(|(_, f)| !f.padding)
                .map(|(index, f)| Claim {
                    index,
                    path: f.path.clone(),
                })
                .collect(),
        }
    }

    pub fn paths(&self, folder: &Path, dest: &Path) -> Vec<PathBuf> {
        self.files
            .iter()
            .map(|f| {
                if self.files.len() == 1 {
                    dest.to_owned()
                } else {
                    folder.join(&f.path)
                }
            })
            .collect()
    }

    fn ledger_path(&self, data: &Path) -> PathBuf {
        data.join("ownership").join(format!("{}.json", self.token))
    }

    pub fn forget(&self, data: &Path) -> io::Result<()> {
        self.check_token()?;
        match std::fs::remove_file(self.ledger_path(data)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    pub fn initialize(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        existing: &[PathBuf],
    ) -> io::Result<()> {
        let paths = self.paths(folder, dest);
        let existing: BTreeSet<_> = existing.iter().map(|p| key(p)).collect();
        let protected = self
            .files
            .iter()
            .zip(paths)
            .filter_map(|(file, path)| {
                (path.symlink_metadata().is_ok() || existing.contains(&key(&path)))
                    .then_some(file.index)
            })
            .collect();
        self.save(
            data,
            &Ledger {
                version: LEDGER_VERSION,
                token: self.token.clone(),
                protected,
                ..Default::default()
            },
        )
    }

    /// What the ledger says. A ledger that is missing (a crash between saving the list and
    /// writing it, a list restored without its `ownership` folder), unreadable, from a newer
    /// version or for another token proves nothing, so every file is kept and the download
    /// still starts and finishes.
    fn load(&self, data: &Path) -> io::Result<Ledger> {
        self.check_token()?;
        let keep_everything = || Ledger {
            version: LEDGER_VERSION,
            token: self.token.clone(),
            protected: self.files.iter().map(|f| f.index).collect(),
            ..Default::default()
        };
        let bytes = match std::fs::read(self.ledger_path(data)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(keep_everything()),
            Err(e) => return Err(e),
        };
        Ok(match serde_json::from_slice::<Ledger>(&bytes) {
            Ok(ledger) if ledger.token == self.token && ledger.version <= LEDGER_VERSION => ledger,
            _ => keep_everything(),
        })
    }

    fn save(&self, data: &Path, ledger: &Ledger) -> io::Result<()> {
        self.check_token()?;
        let path = self.ledger_path(data);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let temp = path.with_extension("tmp");
        let mut file = std::fs::File::create(&temp)?;
        file.write_all(&serde_json::to_vec(ledger).map_err(io::Error::other)?)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(temp, path)
    }

    fn check_token(&self) -> io::Result<()> {
        if self.token.len() != 64 || !self.token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(io::Error::other(crate::i18n::t(
                // i18n: error when the saved record of a torrent's files cannot be read as one
                "The torrent ownership record is invalid",
            )));
        }
        Ok(())
    }

    /// Make every file of the torrent ours before the engine gets the storage: each one is
    /// created here, empty, with `create_new`, and its identity recorded. The engine opens
    /// whatever is at a path for writing and sets its length, so a file that is neither ours
    /// nor agreed to at Add (one saved there since, or replaced while the torrent was stopped)
    /// stops the start: it would be cut and filled with torrent data. Unticked files count:
    /// the engine opens them too and writes the parts of pieces they share.
    pub fn prepare(&self, data: &Path, folder: &Path, dest: &Path) -> io::Result<()> {
        let mut ledger = self.load(data)?;
        let single = self.files.len() == 1;
        let result = (|| {
            let mut paths = Vec::new();
            // Every path is checked before anything is created, junctions included.
            for claim in &self.files {
                mdm_torrent::check_relative_path(&claim.path).map_err(|_| {
                    io::Error::other(crate::i18n::t(
                        // i18n: error when the saved record of a torrent's files holds a path that leaves its folder
                        "The torrent ownership record contains an unsafe path",
                    ))
                })?;
                // Where it is now if we made it already (a finished file may have moved), else
                // where the engine writes it.
                let path = if single && ledger.files.iter().any(|r| r.index == claim.index) {
                    dest.to_owned()
                } else {
                    folder.join(&claim.path)
                };
                if !single && !key(path.parent().unwrap()).starts_with(key(folder)) {
                    return Err(io::Error::other(crate::i18n::t(
                        // i18n: error when a folder inside a torrent's destination leads somewhere else (a junction or link)
                        "A torrent file's folder points outside its destination",
                    )));
                }
                paths.push(path);
            }
            for (claim, path) in self.files.iter().zip(paths) {
                if ledger.protected.contains(&claim.index) {
                    continue;
                }
                if let Ok(metadata) = path.symlink_metadata() {
                    let ours = !metadata.file_type().is_symlink()
                        && ledger.files.iter().any(|r| {
                            r.index == claim.index && identity_at(&path).ok() == Some(r.identity)
                        });
                    if ours {
                        continue;
                    }
                    return Err(not_the_torrents(&path));
                }
                Self::mkdirs(folder, path.parent().unwrap(), &mut ledger)?;
                match std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                {
                    Ok(file) => {
                        let Ok(id) = identity(&file) else {
                            // Downloads still work on filesystems without reliable identities;
                            // these objects are never eligible for automatic deletion.
                            ledger.protected.push(claim.index);
                            continue;
                        };
                        ledger.files.retain(|r| r.index != claim.index);
                        ledger.files.push(Receipt {
                            index: claim.index,
                            path: claim.path.clone(),
                            identity: id,
                        });
                    }
                    // Something took the name between the check and the create.
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        return Err(not_the_torrents(&path));
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        })();
        self.save(data, &ledger)?;
        result
    }

    fn mkdirs(root: &Path, path: &Path, ledger: &mut Ledger) -> io::Result<()> {
        if path.exists() {
            return Ok(());
        }
        if path != root {
            let parent = path.parent().ok_or_else(|| {
                io::Error::other(crate::i18n::t(
                    // i18n: error when a torrent's output folder path cannot be used
                    "The output folder is invalid",
                ))
            })?;
            Self::mkdirs(root, parent, ledger)?;
        }
        match std::fs::create_dir(path) {
            Ok(()) => {
                if let Ok(id) = identity_at(path) {
                    ledger.directories.push(Receipt {
                        index: usize::MAX,
                        path: path
                            .strip_prefix(root)
                            .map_err(io::Error::other)?
                            .to_owned(),
                        identity: id,
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Delete what this torrent made: the files whose identity still matches their receipt
    /// (all of the torrent's files were made here, ticked or not), then the folders it made,
    /// when empty. Anything else, and anything another download claims, stays.
    pub fn delete(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        keep_root: bool,
        protected: &[PathBuf],
    ) -> io::Result<()> {
        let ledger = self.load(data)?;
        let reserved: BTreeSet<_> = protected.iter().map(|p| key(p)).collect();
        let identities: std::collections::HashSet<_> = protected
            .iter()
            .filter_map(|p| identity_at(p).ok())
            .collect();
        let mut failure = None;
        for receipt in &ledger.files {
            if ledger.protected.contains(&receipt.index) {
                continue;
            }
            mdm_torrent::check_relative_path(&receipt.path).map_err(|_| {
                io::Error::other(crate::i18n::t(
                    // i18n: error when the saved record of a torrent's files holds a path that leaves its folder
                    "The torrent ownership record contains an unsafe path",
                ))
            })?;
            let path = if self.files.len() == 1 {
                dest.to_owned()
            } else {
                folder.join(&receipt.path)
            };
            if path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            if claimed(&reserved, &key(&path)) || identities.contains(&receipt.identity) {
                continue;
            }
            let Some(parent) = path.parent() else {
                continue;
            };
            if self.files.len() != 1 && !key(parent).starts_with(key(folder)) {
                continue;
            }
            match identity_at(&path) {
                Ok(id) if id == receipt.identity => {
                    if let Err(e) = remove_owned_torrent_file(&path, receipt.identity) {
                        failure.get_or_insert(e);
                    }
                }
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    failure.get_or_insert(e);
                }
                _ => {}
            }
        }
        let mut dirs: Vec<_> = ledger.directories.iter().collect();
        dirs.sort_by_key(|r| std::cmp::Reverse(r.path.components().count()));
        for receipt in dirs {
            if receipt.path.as_os_str().is_empty() && (keep_root || self.files.len() == 1) {
                continue;
            }
            if !receipt.path.as_os_str().is_empty()
                && mdm_torrent::check_relative_path(&receipt.path).is_err()
            {
                continue;
            }
            let path = folder.join(&receipt.path);
            if path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            if claimed(&reserved, &key(&path)) {
                continue;
            }
            if identity_at(&path).ok() == Some(receipt.identity) {
                match std::fs::remove_dir(path) {
                    Err(e)
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                        ) =>
                    {
                        failure.get_or_insert(e);
                    }
                    _ => {}
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn not_the_torrents(path: &Path) -> io::Error {
    io::Error::other(crate::i18n::fmt(
        // i18n: error starting a torrent: a file that is not the torrent's is at a path the torrent writes, and would be overwritten; {file} is its path
        crate::i18n::t(
            "{file} was saved there, or replaced, after this torrent was added, so it was not started: it would be overwritten. Move the file away and start again.",
        ),
        &[("file", &crate::i18n::isolate(&path.display().to_string()))],
    ))
}

/// Delete a torrent added before ownership records, which has its own outer folder (the one
/// MDM made for it): its files that are regular files in that folder, and the folders
/// that empty, as deleting a torrent always did. Links, other downloads' files and anything
/// that is not one of the torrent's stay.
pub fn delete_outer_folder(bytes: &[u8], folder: &Path, protected: &[PathBuf]) -> io::Result<()> {
    let files = mdm_torrent::files_from_bytes(bytes).map_err(io::Error::other)?;
    let reserved: BTreeSet<_> = protected.iter().map(|p| key(p)).collect();
    let root = key(folder);
    let mut dirs = BTreeSet::new();
    let mut failure = None;
    for file in files.iter().filter(|f| !f.padding) {
        if mdm_torrent::check_relative_path(&file.path).is_err() {
            continue;
        }
        let path = folder.join(&file.path);
        let regular = path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_file());
        let inside = path.parent().is_some_and(|p| key(p).starts_with(&root));
        if !regular || !inside || claimed(&reserved, &key(&path)) {
            continue;
        }
        if let Err(e) = std::fs::remove_file(&path) {
            failure.get_or_insert(e);
        }
        for dir in path.ancestors().skip(1) {
            dirs.insert(dir.to_owned());
            if dir == folder {
                break;
            }
        }
    }
    let mut dirs: Vec<_> = dirs.into_iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for dir in dirs {
        let linked = dir
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink());
        if linked || claimed(&reserved, &key(&dir)) {
            continue;
        }
        match std::fs::remove_dir(&dir) {
            Err(e)
                if !matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                failure.get_or_insert(e);
            }
            _ => {}
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(paths: &[&str]) -> Ownership {
        Ownership {
            token: mdm_ipc::random_token(),
            files: paths
                .iter()
                .enumerate()
                .map(|(index, path)| Claim {
                    index,
                    path: PathBuf::from(path),
                })
                .collect(),
        }
    }

    #[test]
    fn direct_preexisting_files_replaced_files_and_preexisting_directories_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(root.join("existing")).unwrap();
        std::fs::write(
            root.join("README.txt"),
            b"already here; user consented to reuse",
        )
        .unwrap();
        let own = owner(&["README.txt", "existing/a.bin", "unticked.txt", "new/b.bin"]);
        own.initialize(&data, &root, &root, &[root.join("README.txt")])
            .unwrap();
        own.prepare(&data, &root, &root).unwrap();
        // The person saves their own file over one of the torrent's (a new object).
        std::fs::rename(root.join("unticked.txt"), tmp.path().join("moved-away")).unwrap();
        std::fs::write(root.join("unticked.txt"), b"user put this here after Add").unwrap();
        own.delete(&data, &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"already here; user consented to reuse"
        );
        assert_eq!(
            std::fs::read(root.join("unticked.txt")).unwrap(),
            b"user put this here after Add"
        );
        assert!(root.join("existing").is_dir());
        assert!(!root.join("existing/a.bin").exists());
        assert!(!root.join("new").exists());
    }

    #[test]
    fn direct_owned_objects_claimed_by_another_download_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "Sample/a.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let protected = vec![root.join("README.txt"), root.join("Sample")];
        own.delete(tmp.path(), &root, &root, true, &protected)
            .unwrap();
        assert!(root.join("README.txt").is_file());
        assert!(root.join("Sample/a.bin").is_file());
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(!root.join("README.txt").exists());
        assert!(!root.join("Sample").exists());
        assert!(root.is_dir());
    }

    #[test]
    fn direct_replacement_file_is_not_the_object_the_torrent_created() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        std::fs::rename(root.join("README.txt"), root.join("old-object.txt")).unwrap();
        std::fs::write(root.join("README.txt"), b"user replacement").unwrap();
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"user replacement"
        );
        assert!(!root.join("b.bin").exists());
    }

    #[test]
    fn direct_single_file_delete_uses_current_dest_after_move_and_rename() {
        for move_to_another_folder in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("output");
            std::fs::create_dir(&root).unwrap();
            let own = owner(&["original.bin"]);
            let original = root.join("original.bin");
            own.initialize(tmp.path(), &root, &original, &[]).unwrap();
            own.prepare(tmp.path(), &root, &original).unwrap();
            let parent = if move_to_another_folder {
                tmp.path().join("moved")
            } else {
                root.clone()
            };
            std::fs::create_dir_all(&parent).unwrap();
            let current = parent.join("completion-name.bin");
            std::fs::rename(&original, &current).unwrap();
            std::fs::write(&original, b"not the torrent's file").unwrap();
            let reloaded: Ownership =
                serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
            reloaded
                .delete(tmp.path(), &root, &current, false, &[])
                .unwrap();
            assert!(!current.exists());
            assert_eq!(std::fs::read(&original).unwrap(), b"not the torrent's file");
            assert!(root.is_dir());
            assert!(parent.is_dir());
        }
    }

    #[test]
    fn direct_file_appearing_while_queued_is_never_written_to() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("README.txt"), b"arrived after Later").unwrap();
        // The engine would open it, cut it to the torrent's size and fill it: the start stops.
        let error = own.prepare(tmp.path(), &root, &root).unwrap_err();
        assert!(error.to_string().contains("README.txt"), "{error}");
        assert!(!root.join("b.bin").exists(), "nothing else is set up");
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert_eq!(
            std::fs::read(root.join("README.txt")).unwrap(),
            b"arrived after Later"
        );
    }

    #[test]
    fn direct_ownership_and_created_directory_receipts_survive_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("owned-root");
        let own = owner(&["a.bin", "nested/b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, false, &[])
            .unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn direct_queued_claims_cover_internal_paths_and_file_directory_prefixes() {
        let tmp = tempfile::tempdir().unwrap();
        let claimed_paths = vec![
            tmp.path().join("README.txt"),
            tmp.path().join("Sample/a.bin"),
        ];
        let candidates = vec![
            tmp.path().join("README.txt"),
            tmp.path().join("Sample"),
            tmp.path().join("free.bin"),
        ];
        assert_eq!(
            conflicts(&candidates, &claimed_paths, true),
            candidates[..2]
        );
        #[cfg(windows)]
        assert_eq!(
            conflicts(&[tmp.path().join("readme.TXT")], &claimed_paths, false).len(),
            1
        );
    }

    #[test]
    fn direct_ownership_rejects_escaping_paths_and_invalid_tokens() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["../outside.bin", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert!(!tmp.path().join("outside.bin").exists());
        let mut invalid = owner(&["a.bin"]);
        invalid.token = "../../escape".into();
        assert!(invalid.initialize(tmp.path(), &root, &root, &[]).is_err());
    }

    #[tokio::test]
    async fn direct_ownership_is_checked_against_the_saved_torrent_file_list_and_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.bin"), b"ownership a").unwrap();
        std::fs::write(source.join("nested/b.bin"), b"ownership b").unwrap();
        let spawner = mdm_torrent::librqbit::spawn_utils::BlockingSpawner::new(1);
        let made = mdm_torrent::librqbit::create_torrent(
            &source,
            mdm_torrent::librqbit::CreateTorrentOptions {
                name: Some("ownership-validation"),
                trackers: Vec::new(),
                piece_length: Some(16384),
            },
            &spawner,
        )
        .await
        .unwrap();
        let bytes = made.as_bytes().unwrap().to_vec();
        let hash = mdm_torrent::librqbit::torrent_from_bytes(&bytes)
            .unwrap()
            .info_hash
            .as_string();
        let mut own = Ownership {
            token: mdm_ipc::random_token(),
            files: mdm_torrent::files_from_bytes(&bytes)
                .unwrap()
                .into_iter()
                .enumerate()
                .map(|(index, f)| Claim {
                    index,
                    path: f.path,
                })
                .collect(),
        };
        own.validate(&bytes, &hash).unwrap();
        assert!(own.validate(&bytes, &"0".repeat(40)).is_err());
        own.files[0].path = "not-the-torrent.txt".into();
        assert!(own.validate(&bytes, &hash).is_err());
    }

    #[test]
    fn direct_refused_preparation_keeps_receipts_for_what_it_already_made() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "later.txt"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("later.txt"), b"user file").unwrap();
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert!(root.join("a.bin").exists());
        own.delete(tmp.path(), &root, &root, false, &[]).unwrap();
        assert!(!root.join("a.bin").exists());
        assert_eq!(std::fs::read(root.join("later.txt")).unwrap(), b"user file");
        assert!(root.is_dir(), "the pre-existing empty root is not owned");
    }

    #[test]
    fn direct_unticked_files_are_made_here_first_so_ticking_one_later_needs_no_guess() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["selected.bin", "unticked.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        assert!(root.join("unticked.bin").is_file());
        // The engine writes into what is there, without replacing it.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(root.join("unticked.bin"))
                .unwrap();
            f.write_all(b"part of a shared piece").unwrap();
        }
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded.prepare(tmp.path(), &root, &root).unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, true, &[])
            .unwrap();
        assert!(!root.join("selected.bin").exists());
        assert!(!root.join("unticked.bin").exists(), "no empty leftovers");
    }

    #[test]
    fn direct_a_replaced_file_stops_the_start_and_is_never_deleted() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["edited.bin", "other.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        let path = root.join("edited.bin");
        std::fs::rename(&path, tmp.path().join("original-object")).unwrap();
        std::fs::write(&path, b"saved by an editor").unwrap();
        // A resume would let the engine check its pieces against this file and rewrite it.
        assert!(own.prepare(tmp.path(), &root, &root).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"saved by an editor");
        own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
        assert!(path.exists());
        assert!(!root.join("other.bin").exists());
    }

    #[test]
    fn direct_a_missing_unreadable_or_newer_ledger_keeps_every_file_and_still_starts() {
        for damage in ["missing", "garbage", "newer", "other token"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("output");
            std::fs::create_dir(&root).unwrap();
            std::fs::write(root.join("a.bin"), b"torrent data so far").unwrap();
            let own = owner(&["a.bin", "b.bin"]);
            own.initialize(tmp.path(), &root, &root, &[]).unwrap();
            let ledger = own.ledger_path(tmp.path());
            match damage {
                "missing" => std::fs::remove_file(&ledger).unwrap(),
                "garbage" => std::fs::write(&ledger, b"{not json").unwrap(),
                "newer" => std::fs::write(
                    &ledger,
                    format!(r#"{{"version":99,"token":"{}"}}"#, own.token),
                )
                .unwrap(),
                _ => std::fs::write(
                    &ledger,
                    format!(r#"{{"version":1,"token":"{}"}}"#, "0".repeat(64)),
                )
                .unwrap(),
            }
            own.prepare(tmp.path(), &root, &root)
                .unwrap_or_else(|e| panic!("{damage}: {e}"));
            own.delete(tmp.path(), &root, &root, true, &[]).unwrap();
            assert!(root.join("a.bin").exists(), "{damage}");
        }
    }

    #[test]
    fn direct_a_ledger_written_by_an_earlier_build_without_a_version_still_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "b.bin"]);
        std::fs::create_dir_all(tmp.path().join("ownership")).unwrap();
        std::fs::write(
            own.ledger_path(tmp.path()),
            format!(r#"{{"token":"{}","protected":[1]}}"#, own.token),
        )
        .unwrap();
        own.prepare(tmp.path(), &root, &root).unwrap();
        assert!(root.join("a.bin").exists());
        assert!(
            !root.join("b.bin").exists(),
            "protected: left to the engine"
        );
    }

    #[test]
    fn direct_identity_has_a_creation_time_so_a_file_that_took_the_name_later_differs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cover.jpg");
        std::fs::write(&path, b"one").unwrap();
        let first = identity_at(&path).expect("this filesystem gives an identity");
        assert_ne!(first[2], 0, "a creation time is part of it");
        assert_eq!(identity_at(&path).unwrap(), first);
    }

    #[tokio::test]
    async fn direct_an_older_download_with_its_own_folder_still_deletes_its_files_only() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::write(source.join("a.bin"), b"ownership a").unwrap();
        std::fs::write(source.join("nested/b.bin"), b"ownership b").unwrap();
        let spawner = mdm_torrent::librqbit::spawn_utils::BlockingSpawner::new(1);
        let made = mdm_torrent::librqbit::create_torrent(
            &source,
            mdm_torrent::librqbit::CreateTorrentOptions {
                name: Some("Set"),
                trackers: Vec::new(),
                piece_length: Some(16384),
            },
            &spawner,
        )
        .await
        .unwrap();
        let bytes = made.as_bytes().unwrap().to_vec();
        let folder = tmp.path().join("Downloads/Set");
        std::fs::create_dir_all(folder.join("nested")).unwrap();
        std::fs::write(folder.join("a.bin"), b"torrent").unwrap();
        std::fs::write(folder.join("nested/b.bin"), b"torrent").unwrap();
        std::fs::write(folder.join("notes.txt"), b"the person's own note").unwrap();
        delete_outer_folder(&bytes, &folder, &[]).unwrap();
        assert!(!folder.join("a.bin").exists());
        assert!(!folder.join("nested").exists());
        assert_eq!(
            std::fs::read(folder.join("notes.txt")).unwrap(),
            b"the person's own note"
        );
        assert!(folder.is_dir(), "a folder with something else in it stays");
        // Another download's file stays too.
        std::fs::write(folder.join("a.bin"), b"claimed").unwrap();
        delete_outer_folder(&bytes, &folder, &[folder.join("a.bin")]).unwrap();
        assert!(folder.join("a.bin").exists());
    }
}
