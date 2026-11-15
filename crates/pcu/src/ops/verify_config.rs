//! Policy for `pcu verify-signatures`: an allow list of identities accepted
//! without being collaborators, and a hard stop for everyone else.
//!
//! The policy lives in `pcu.toml` under `[verify_signatures]`:
//!
//! ```toml
//! [verify_signatures]
//! fail_on_external = true
//!
//! [[verify_signatures.allow]]
//! email = "29139614+renovate[bot]@users.noreply.github.com"
//! keys = ["B5690EEEBB952194"]          # GitHub's web-flow key
//! description = "Renovate (committed and signed by GitHub)"
//! ```
//!
//! # The file is read from the base ref, never the branch under review
//!
//! A pull request can edit any file it contains. If the policy were read from
//! the working tree, a PR could add its own author to the allow list, or turn
//! the hard stop off, and pass its own check. The policy is therefore read
//! from the git object at `--base` (for example `origin/main`), so a change to
//! it only takes effect once it has been merged.
//!
//! # Entries must name signing keys
//!
//! An author email is self-declared: anyone can write `renovate[bot]@…` into a
//! commit. An email-only entry would allow-list whoever forges it, so every
//! entry must list the key(s) its commits are signed with, and a commit only
//! matches when its signature is good and made with one of them.

use std::path::Path;

use git2::{ErrorCode, Repository};
use serde::Deserialize;

use super::git_signature_ops::resolve_reference;
use crate::Error;

/// Path of the policy file, relative to the repository root.
pub const POLICY_PATH: &str = "pcu.toml";

/// Shortest key ID accepted. A 16-hex-digit long ID is what git reports for a
/// signature; shorter IDs collide too easily to be a safe match.
const MIN_KEY_ID_LEN: usize = 16;

/// The verification policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyConfig {
    /// Fail verification for any commit from an author who is neither a
    /// trusted identity nor on the allow list.
    pub fail_on_external: bool,
    /// Identities accepted without being collaborators.
    pub allow: Vec<AllowEntry>,
}

/// One allow-listed identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    /// Author email, lowercase.
    pub email: String,
    /// Key IDs (or fingerprints) its commits must be signed with, uppercase.
    pub keys: Vec<String>,
    /// Why the identity is allowed: a note for whoever reads the policy.
    pub description: Option<String>,
}

impl VerifyConfig {
    /// The allow-list entry for an author email, ignoring case and
    /// surrounding whitespace.
    pub fn allow_entry(&self, author_email: &str) -> Option<&AllowEntry> {
        let wanted = author_email.trim().to_lowercase();
        self.allow.iter().find(|entry| entry.email == wanted)
    }

    /// Parse the policy from the text of a `pcu.toml`.
    pub fn from_toml(text: &str) -> Result<Self, Error> {
        let file: RawFile =
            toml::from_str(text).map_err(|e| Error::VerifyConfig(format!("{POLICY_PATH}: {e}")))?;
        let raw = file.verify_signatures;

        let mut allow: Vec<AllowEntry> = Vec::new();
        for (index, entry) in raw.allow.into_iter().enumerate() {
            let entry = AllowEntry::from_raw(entry, index + 1)?;
            if allow.iter().any(|known| known.email == entry.email) {
                return Err(Error::VerifyConfig(format!(
                    "allow entry {} repeats an email already allow-listed; list all of an \
                     identity's keys in one entry",
                    index + 1
                )));
            }
            allow.push(entry);
        }

        Ok(Self {
            fail_on_external: raw.fail_on_external,
            allow,
        })
    }

    /// Read the policy from `pcu.toml` at `base_ref`. A missing file is the
    /// default policy; a file that exists but is invalid is an error, so a
    /// typo can never silently weaken the gate.
    pub fn load_from_ref(repo: &Repository, base_ref: &str) -> Result<Self, Error> {
        let oid = resolve_reference(repo, base_ref)?;
        let tree = repo.find_commit(oid)?.tree()?;

        let entry = match tree.get_path(Path::new(POLICY_PATH)) {
            Ok(entry) => entry,
            Err(e) if e.code() == ErrorCode::NotFound => {
                log::debug!("No {POLICY_PATH} at {base_ref}; using the default policy");
                return Ok(Self::default());
            }
            Err(e) => return Err(e.into()),
        };

        let blob = repo.find_blob(entry.id())?;
        let text = std::str::from_utf8(blob.content())
            .map_err(|_| Error::VerifyConfig(format!("{POLICY_PATH} is not valid UTF-8")))?;
        Self::from_toml(text)
    }
}

impl AllowEntry {
    /// Whether `key_id` (from a commit's signature) is one of this entry's
    /// keys. A long key ID matches the tail of a fingerprint, either way
    /// round.
    pub fn approves(&self, key_id: &str) -> bool {
        let key_id = key_id.trim().to_uppercase();
        !key_id.is_empty()
            && self
                .keys
                .iter()
                .any(|k| key_id.ends_with(k.as_str()) || k.ends_with(key_id.as_str()))
    }

    fn from_raw(raw: RawAllow, position: usize) -> Result<Self, Error> {
        let email = raw.email.trim().to_lowercase();
        if email.is_empty() || !email.contains('@') {
            return Err(Error::VerifyConfig(format!(
                "allow entry {position}: `email` must be an email address"
            )));
        }

        if raw.keys.is_empty() {
            return Err(Error::VerifyConfig(format!(
                "allow entry {position}: `keys` is required. An email alone is self-declared \
                 and can be forged, so an entry must name the key(s) its commits are signed with"
            )));
        }
        let keys = raw
            .keys
            .iter()
            .map(|key| normalise_key_id(key, position))
            .collect::<Result<Vec<_>, _>>()?;

        let description = raw
            .description
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty());

        Ok(Self {
            email,
            keys,
            description,
        })
    }
}

/// Uppercase, drop spaces and a leading `0x`, and require enough hex digits.
fn normalise_key_id(raw: &str, position: usize) -> Result<String, Error> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let digits = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact)
        .to_uppercase();

    if digits.len() < MIN_KEY_ID_LEN
        || digits.len() > 40
        || !digits.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(Error::VerifyConfig(format!(
            "allow entry {position}: key `{raw}` must be {MIN_KEY_ID_LEN} to 40 hex digits \
             (a long key ID or a fingerprint)"
        )));
    }
    Ok(digits)
}

/// The whole `pcu.toml`: only `[verify_signatures]` is ours; the other
/// settings in the file belong to other pcu commands and are ignored here.
#[derive(Debug, Deserialize)]
struct RawFile {
    #[serde(default)]
    verify_signatures: RawVerify,
}

/// Unknown keys are an error: a misspelt `fail_on_external` must not silently
/// leave the hard stop off.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVerify {
    #[serde(default)]
    fail_on_external: bool,
    #[serde(default)]
    allow: Vec<RawAllow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllow {
    email: String,
    #[serde(default)]
    keys: Vec<String>,
    description: Option<String>,
}

#[cfg(test)]
mod tests {
    use git2::{Oid, Signature};
    use tempfile::TempDir;

    use super::*;

    const RENOVATE: &str = "29139614+renovate[bot]@users.noreply.github.com";
    const WEB_FLOW: &str = "B5690EEEBB952194";

    fn renovate_policy() -> String {
        format!(
            r#"
            prlog = "PRLOG.md"

            [verify_signatures]
            fail_on_external = true

            [[verify_signatures.allow]]
            email = "{RENOVATE}"
            keys = ["{WEB_FLOW}"]
            description = "Renovate (committed and signed by GitHub)"
            "#
        )
    }

    fn err(text: &str) -> String {
        VerifyConfig::from_toml(text).unwrap_err().to_string()
    }

    #[test]
    fn default_policy_changes_nothing() {
        let config = VerifyConfig::default();

        assert!(!config.fail_on_external);
        assert!(config.allow.is_empty());
    }

    #[test]
    fn a_file_without_the_section_is_the_default_policy() {
        let config = VerifyConfig::from_toml("prlog = \"PRLOG.md\"\nbranch = \"main\"\n").unwrap();

        assert_eq!(config, VerifyConfig::default());
        assert_eq!(
            VerifyConfig::from_toml("").unwrap(),
            VerifyConfig::default()
        );
    }

    #[test]
    fn parses_the_renovate_example() {
        let config = VerifyConfig::from_toml(&renovate_policy()).unwrap();

        assert!(config.fail_on_external);
        assert_eq!(config.allow.len(), 1);
        assert_eq!(config.allow[0].email, RENOVATE.to_lowercase());
        assert_eq!(config.allow[0].keys, vec![WEB_FLOW.to_string()]);
        assert_eq!(
            config.allow[0].description.as_deref(),
            Some("Renovate (committed and signed by GitHub)")
        );
    }

    #[test]
    fn an_entry_without_keys_is_refused() {
        let message = err(r#"
            [[verify_signatures.allow]]
            email = "renovate[bot]@users.noreply.github.com"
            "#);

        assert!(message.contains("`keys` is required"), "got: {message}");
        assert!(message.contains("forged"), "got: {message}");
    }

    #[test]
    fn an_entry_with_an_empty_key_list_is_refused() {
        let message = err(r#"
            [[verify_signatures.allow]]
            email = "a@example.test"
            keys = []
            "#);

        assert!(message.contains("`keys` is required"), "got: {message}");
    }

    #[test]
    fn misspelt_settings_are_errors_not_silent_no_ops() {
        let message = err("[verify_signatures]\nfail_on_extrenal = true\n");
        assert!(message.contains("fail_on_extrenal"), "got: {message}");

        let message = err(r#"
            [[verify_signatures.allow]]
            email = "a@example.test"
            keys = ["B5690EEEBB952194"]
            kyes = ["B5690EEEBB952194"]
            "#);
        assert!(message.contains("kyes"), "got: {message}");
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(err("[verify_signatures\n").contains(POLICY_PATH));
    }

    #[test]
    fn bad_emails_are_refused() {
        for email in ["", "   ", "not-an-email"] {
            let message = err(&format!(
                "[[verify_signatures.allow]]\nemail = \"{email}\"\nkeys = [\"{WEB_FLOW}\"]\n"
            ));
            assert!(message.contains("`email`"), "{email:?}: {message}");
        }
    }

    #[test]
    fn short_or_non_hex_keys_are_refused() {
        for key in [
            "B5690EEE",
            "not-a-key-id-at-all",
            "B5690EEEBB95219G",
            &"A".repeat(41),
        ] {
            let message = err(&format!(
                "[[verify_signatures.allow]]\nemail = \"a@example.test\"\nkeys = [\"{key}\"]\n"
            ));
            assert!(message.contains("hex digits"), "{key:?}: {message}");
        }
    }

    #[test]
    fn keys_and_emails_are_normalised() {
        let config = VerifyConfig::from_toml(
            r#"
            [[verify_signatures.allow]]
            email = "  Renovate@Example.Test "
            keys = ["0xb5690eeebb952194", "b569 0eee bb95 2194"]
            "#,
        )
        .unwrap();

        assert_eq!(config.allow[0].email, "renovate@example.test");
        assert_eq!(
            config.allow[0].keys,
            vec![WEB_FLOW.to_string(), WEB_FLOW.to_string()]
        );
    }

    #[test]
    fn a_repeated_email_is_refused() {
        let message = err(&format!(
            r#"
            [[verify_signatures.allow]]
            email = "a@example.test"
            keys = ["{WEB_FLOW}"]
            [[verify_signatures.allow]]
            email = "A@Example.Test"
            keys = ["{WEB_FLOW}"]
            "#
        ));

        assert!(message.contains("repeats an email"), "got: {message}");
    }

    #[test]
    fn allow_entry_lookup_ignores_case_and_whitespace() {
        let config = VerifyConfig::from_toml(&renovate_policy()).unwrap();

        assert!(config.allow_entry(RENOVATE).is_some());
        assert!(config.allow_entry(&RENOVATE.to_uppercase()).is_some());
        assert!(config.allow_entry(&format!("  {RENOVATE}\n")).is_some());
        assert!(config.allow_entry("someone-else@example.test").is_none());
    }

    #[test]
    fn approves_matches_a_long_id_against_a_fingerprint_either_way_round() {
        let config = VerifyConfig::from_toml(&renovate_policy()).unwrap();
        let entry = &config.allow[0];
        let fingerprint = format!("{}{WEB_FLOW}", "A".repeat(24));

        assert!(entry.approves(WEB_FLOW));
        assert!(entry.approves(&WEB_FLOW.to_lowercase()));
        assert!(entry.approves(&fingerprint), "fingerprint ending in the ID");
        assert!(!entry.approves("0000000000000000"));
        assert!(!entry.approves(""));
        assert!(!entry.approves("   "));
    }

    #[test]
    fn approves_a_fingerprint_entry_from_a_long_id() {
        let fingerprint = format!("{}{WEB_FLOW}", "A".repeat(24));
        let config = VerifyConfig::from_toml(&format!(
            "[[verify_signatures.allow]]\nemail = \"a@example.test\"\nkeys = [\"{fingerprint}\"]\n"
        ))
        .unwrap();

        assert!(config.allow[0].approves(WEB_FLOW));
    }

    // --- reading the policy from a git ref ---------------------------------

    fn commit_file(repo: &Repository, refname: &str, content: &str, parent: Option<Oid>) -> Oid {
        let blob = repo.blob(content.as_bytes()).unwrap();
        let mut builder = repo.treebuilder(None).unwrap();
        builder.insert(POLICY_PATH, blob, 0o100644).unwrap();
        let tree = repo.find_tree(builder.write().unwrap()).unwrap();
        let sig = Signature::now("t", "t@example.test").unwrap();
        let parents: Vec<_> = parent
            .map(|p| repo.find_commit(p).unwrap())
            .into_iter()
            .collect();
        let parents: Vec<&git2::Commit> = parents.iter().collect();
        repo.commit(Some(refname), &sig, &sig, "policy", &tree, &parents)
            .unwrap()
    }

    fn empty_commit(repo: &Repository, refname: &str) -> Oid {
        let tree = repo
            .find_tree(repo.treebuilder(None).unwrap().write().unwrap())
            .unwrap();
        let sig = Signature::now("t", "t@example.test").unwrap();
        repo.commit(Some(refname), &sig, &sig, "no policy", &tree, &[])
            .unwrap()
    }

    fn temp_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();
        (dir, repo)
    }

    #[test]
    fn loads_the_policy_from_the_base_ref() {
        let (_dir, repo) = temp_repo();
        commit_file(&repo, "refs/heads/main", &renovate_policy(), None);

        let config = VerifyConfig::load_from_ref(&repo, "main").unwrap();

        assert!(config.fail_on_external);
        assert!(config.allow_entry(RENOVATE).is_some());
    }

    /// The point of reading from the base: a branch cannot allow-list its own
    /// author or switch the hard stop off.
    #[test]
    fn a_branch_cannot_change_the_policy_that_judges_it() {
        let (_dir, repo) = temp_repo();
        let base = commit_file(&repo, "refs/heads/main", &renovate_policy(), None);
        let hostile = format!(
            r#"
            [verify_signatures]
            fail_on_external = false
            [[verify_signatures.allow]]
            email = "attacker@example.test"
            keys = ["{WEB_FLOW}"]
            "#
        );
        commit_file(&repo, "refs/heads/feature", &hostile, Some(base));

        let judged_by_base = VerifyConfig::load_from_ref(&repo, "main").unwrap();

        assert!(judged_by_base.fail_on_external, "hard stop stays on");
        assert!(judged_by_base
            .allow_entry("attacker@example.test")
            .is_none());
        // The branch's own file does say otherwise; that is what is ignored.
        let own = VerifyConfig::load_from_ref(&repo, "feature").unwrap();
        assert!(own.allow_entry("attacker@example.test").is_some());
    }

    #[test]
    fn a_base_without_the_file_is_the_default_policy() {
        let (_dir, repo) = temp_repo();
        empty_commit(&repo, "refs/heads/main");

        assert_eq!(
            VerifyConfig::load_from_ref(&repo, "main").unwrap(),
            VerifyConfig::default()
        );
    }

    #[test]
    fn an_invalid_file_at_the_base_is_an_error_not_the_default() {
        let (_dir, repo) = temp_repo();
        commit_file(
            &repo,
            "refs/heads/main",
            "[verify_signatures]\nfail_on_extrenal = true\n",
            None,
        );

        let message = VerifyConfig::load_from_ref(&repo, "main")
            .unwrap_err()
            .to_string();

        assert!(message.contains("fail_on_extrenal"), "got: {message}");
    }

    #[test]
    fn an_unknown_base_ref_is_an_error() {
        let (_dir, repo) = temp_repo();
        empty_commit(&repo, "refs/heads/main");

        assert!(VerifyConfig::load_from_ref(&repo, "no-such-ref").is_err());
    }
}
