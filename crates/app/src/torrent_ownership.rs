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

#[derive(Default, Serialize, Deserialize)]
struct Ledger {
    token: String,
    protected: Vec<usize>,
    files: Vec<Receipt>,
    directories: Vec<Receipt>,
}

#[derive(Serialize, Deserialize)]
struct Receipt {
    index: usize,
    path: PathBuf,
    identity: [u64; 2],
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
    #[cfg(windows)]
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

pub fn conflicts(paths: &[PathBuf], claims: &[PathBuf], canonical: bool) -> Vec<PathBuf> {
    let normalize = |path: &PathBuf| {
        if canonical {
            return key(path);
        }
        #[cfg(windows)]
        {
            PathBuf::from(path.to_string_lossy().to_lowercase())
        }
        #[cfg(not(windows))]
        {
            path.clone()
        }
    };
    let set: BTreeSet<_> = claims.iter().map(&normalize).collect();
    let identities: std::collections::HashSet<_> = if canonical {
        claims.iter().filter_map(|p| identity_at(p).ok()).collect()
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
                token: self.token.clone(),
                protected,
                ..Default::default()
            },
        )
    }

    fn load(&self, data: &Path) -> io::Result<Ledger> {
        self.check_token()?;
        let bytes = std::fs::read(self.ledger_path(data))?;
        let ledger: Ledger = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if ledger.token != self.token {
            return Err(io::Error::other(crate::i18n::t(
                "The torrent ownership record belongs to another download",
            )));
        }
        Ok(ledger)
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
                "The torrent ownership record is invalid",
            )));
        }
        Ok(())
    }

    /// Claim only files we exclusively create before giving storage to the engine.
    /// Unticked files are deliberately never claimed, even if an overlapping piece writes them.
    pub fn prepare(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        selected: Option<&[usize]>,
    ) -> io::Result<()> {
        let mut ledger = self.load(data)?;
        let result = (|| {
            for (claim, path) in self.files.iter().zip(self.paths(folder, dest)) {
                mdm_torrent::check_relative_path(&claim.path).map_err(|_| {
                    io::Error::other(crate::i18n::t(
                        "The torrent ownership record contains an unsafe path",
                    ))
                })?;
                if selected.is_some_and(|s| !s.contains(&claim.index))
                    || ledger.protected.contains(&claim.index)
                {
                    continue;
                }
                if let Ok(metadata) = path.symlink_metadata() {
                    if ledger.files.iter().any(|r| {
                        !metadata.file_type().is_symlink()
                            && r.index == claim.index
                            && identity_at(&path).ok() == Some(r.identity)
                    }) {
                        continue;
                    }
                    // Storage creates unticked files too, and an editor may replace an
                    // owned file while the torrent is stopped. Neither object gives us
                    // deletion authority. Preserve it without blocking resume/seeding.
                    ledger.protected.push(claim.index);
                    ledger.files.retain(|r| r.index != claim.index);
                    continue;
                }
                if self.files.len() != 1 && !key(path.parent().unwrap()).starts_with(key(folder)) {
                    return Err(io::Error::other(crate::i18n::t(
                        "A torrent file's folder points outside its destination",
                    )));
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
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        // An object appeared between the metadata check and create_new.
                        // It belongs to somebody else; never take ownership of it.
                        ledger.protected.push(claim.index);
                        ledger.files.retain(|r| r.index != claim.index);
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
            let parent = path
                .parent()
                .ok_or_else(|| io::Error::other(crate::i18n::t("The output folder is invalid")))?;
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

    pub fn delete(
        &self,
        data: &Path,
        folder: &Path,
        dest: &Path,
        selected: Option<&[usize]>,
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
            if selected.is_some_and(|s| !s.contains(&receipt.index))
                || ledger.protected.contains(&receipt.index)
            {
                continue;
            }
            mdm_torrent::check_relative_path(&receipt.path).map_err(|_| {
                io::Error::other(crate::i18n::t(
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
    fn direct_preexisting_and_unticked_files_and_preexisting_directories_are_kept() {
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
        own.prepare(&data, &root, &root, Some(&[0, 1, 3])).unwrap();
        std::fs::write(root.join("unticked.txt"), b"user put this here after Add").unwrap();
        own.delete(&data, &root, &root, Some(&[0, 1, 3]), true, &[])
            .unwrap();
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
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        let protected = vec![root.join("README.txt"), root.join("Sample")];
        own.delete(tmp.path(), &root, &root, None, true, &protected)
            .unwrap();
        assert!(root.join("README.txt").is_file());
        assert!(root.join("Sample/a.bin").is_file());
        own.delete(tmp.path(), &root, &root, None, true, &[])
            .unwrap();
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
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        std::fs::rename(root.join("README.txt"), root.join("old-object.txt")).unwrap();
        std::fs::write(root.join("README.txt"), b"user replacement").unwrap();
        own.delete(tmp.path(), &root, &root, None, true, &[])
            .unwrap();
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
            own.prepare(tmp.path(), &root, &original, None).unwrap();
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
                .delete(tmp.path(), &root, &current, None, false, &[])
                .unwrap();
            assert!(!current.exists());
            assert_eq!(std::fs::read(&original).unwrap(), b"not the torrent's file");
            assert!(root.is_dir());
            assert!(parent.is_dir());
        }
    }

    #[test]
    fn direct_file_appearing_while_queued_is_protected_without_blocking_prepare() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["README.txt", "b.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("README.txt"), b"arrived after Later").unwrap();
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        own.delete(tmp.path(), &root, &root, None, true, &[])
            .unwrap();
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
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded.prepare(tmp.path(), &root, &root, None).unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, None, false, &[])
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
        assert!(own.prepare(tmp.path(), &root, &root, None).is_err());
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
    fn direct_preparation_keeps_created_receipts_and_protects_unowned_later_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["a.bin", "later.txt"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        std::fs::write(root.join("later.txt"), b"user file").unwrap();
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        assert!(root.join("a.bin").exists());
        own.delete(tmp.path(), &root, &root, None, false, &[])
            .unwrap();
        assert!(!root.join("a.bin").exists());
        assert_eq!(std::fs::read(root.join("later.txt")).unwrap(), b"user file");
        assert!(root.is_dir(), "the pre-existing empty root is not owned");
    }

    #[test]
    fn direct_ticking_an_engine_created_file_resumes_without_claiming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["selected.bin", "unticked.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root, Some(&[0])).unwrap();
        // The engine allocates storage for unticked files as well as selected ones.
        std::fs::write(root.join("unticked.bin"), b"engine-created storage").unwrap();
        let reloaded: Ownership =
            serde_json::from_str(&serde_json::to_string(&own).unwrap()).unwrap();
        reloaded
            .prepare(tmp.path(), &root, &root, Some(&[0, 1]))
            .unwrap();
        reloaded
            .prepare(tmp.path(), &root, &root, Some(&[0, 1]))
            .unwrap();
        reloaded
            .delete(tmp.path(), &root, &root, Some(&[0, 1]), true, &[])
            .unwrap();
        assert!(!root.join("selected.bin").exists());
        assert_eq!(
            std::fs::read(root.join("unticked.bin")).unwrap(),
            b"engine-created storage"
        );
    }

    #[test]
    fn direct_editor_replacement_resumes_and_permanently_loses_deletion_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("output");
        std::fs::create_dir(&root).unwrap();
        let own = owner(&["edited.bin", "other.bin"]);
        own.initialize(tmp.path(), &root, &root, &[]).unwrap();
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        let path = root.join("edited.bin");
        let original = tmp.path().join("original-object");
        std::fs::rename(&path, &original).unwrap();
        std::fs::write(&path, b"saved by an editor").unwrap();
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&original, &path).unwrap();
        own.prepare(tmp.path(), &root, &root, None).unwrap();
        own.delete(tmp.path(), &root, &root, None, true, &[])
            .unwrap();
        assert!(
            path.exists(),
            "protection is durable even if the old object returns"
        );
        assert!(!root.join("other.bin").exists());
    }
}
