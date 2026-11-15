use std::env;

use clap::Parser;
use octocrab::Octocrab;
use owo_colors::OwoColorize;

use super::CIExit;
use crate::{
    ops::{
        git_signature_ops::extract_commits, signature_ops::verify_commits_with,
        trust_fetcher::fetch_trust_list, verify_config::VerifyConfig,
    },
    Error,
};

#[derive(Parser, Clone)]
pub struct VerifySignatures {
    /// Base ref for commit range
    #[clap(long, default_value = "origin/main")]
    pub base: String,

    /// Head ref for commit range
    #[clap(long, default_value = "HEAD")]
    pub head: String,

    /// Repository owner (auto-detected if not provided)
    #[clap(long)]
    pub repo_owner: Option<String>,

    /// Repository name (auto-detected if not provided)
    #[clap(long)]
    pub repo_name: Option<String>,

    /// Git fetch depth
    #[clap(long, default_value = "200")]
    pub fetch_depth: usize,

    /// Fail if trusted identities have unsigned commits
    #[clap(long, default_value_t = true)]
    pub fail_on_unsigned: bool,

    /// Fail for commits from authors who are neither trusted nor on the allow
    /// list. Can also be set with `fail_on_external = true` under
    /// `[verify_signatures]` in `pcu.toml` at the base ref, which a branch
    /// cannot change.
    #[clap(long)]
    pub fail_on_external: bool,

    /// Post verification results as a PR comment
    #[clap(long)]
    pub post_comment: bool,

    /// PR number to comment on (required if --post-comment is used)
    #[clap(long, required_if_eq("post_comment", "true"))]
    pub pr_number: Option<u64>,

    /// GitHub token for read-only access (fetching trust list)
    /// If not provided, will use GITHUB_TOKEN env var
    #[clap(long)]
    pub github_token: Option<String>,
}

impl std::fmt::Debug for VerifySignatures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifySignatures")
            .field("base", &self.base)
            .field("head", &self.head)
            .field("repo_owner", &self.repo_owner)
            .field("repo_name", &self.repo_name)
            .field("fetch_depth", &self.fetch_depth)
            .field("fail_on_unsigned", &self.fail_on_unsigned)
            .field("fail_on_external", &self.fail_on_external)
            .field("post_comment", &self.post_comment)
            .field("pr_number", &self.pr_number)
            .field("github_token", &super::Redacted(&self.github_token))
            .finish()
    }
}

/// Longest author email or subject written into the PR comment.
const MAX_UNTRUSTED_LEN: usize = 120;

/// Make attacker-controlled text safe inside a markdown code span (the author
/// email in the table). Control characters, backticks and pipes would end the
/// span, add a table column or start a new line, letting a commit author
/// render their own markdown in a comment posted under the bot's name.
fn sanitize_code_span(text: &str) -> String {
    let mut out: String = text
        .chars()
        .take(MAX_UNTRUSTED_LEN)
        .map(|c| {
            if c.is_control() || c == '`' || c == '|' {
                '?'
            } else {
                c
            }
        })
        .collect();
    if text.chars().count() > MAX_UNTRUSTED_LEN {
        out.push('…');
    }
    out
}

/// Make attacker-controlled text safe as plain markdown text (the commit
/// subject): neutralise markup, links, images, HTML and `@mentions`, and keep
/// it on one line.
fn escape_markdown_text(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().take(MAX_UNTRUSTED_LEN) {
        match c {
            c if c.is_control() => out.push(' '),
            '@' => out.push_str("@\u{200B}"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '<' | '>' | '|' | '~' | '!' | '#'
            | '&' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    if text.chars().count() > MAX_UNTRUSTED_LEN {
        out.push('…');
    }
    out
}

/// Replace control characters (terminal escape sequences) in text printed to
/// the CI log.
fn strip_control(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

impl VerifySignatures {
    pub async fn run_verify(self) -> Result<CIExit, Error> {
        log::info!("=== Commit Signature Verification ===");

        // Open git repository
        let git_repo = git2::Repository::open(".")?;

        // Get owner and repo (auto-detect from git config if not provided)
        let (owner, repo) = detect_repository(&git_repo, &self.repo_owner, &self.repo_name)?;

        // Initialize GitHub client for read-only operations (fetching trust
        // list) Uses --github-token flag or falls back to GITHUB_TOKEN
        // env var
        let env_token = env::var("GITHUB_TOKEN").ok();
        let token = self.github_token.as_deref().or(env_token.as_deref());
        let readonly_client = initialize_github_client_with_token(
            token,
            "Read-only GitHub token not provided (use --github-token or set GITHUB_TOKEN env var)",
        )?;

        println!("\n{}\n", "=== Commit Signature Verification ===".bold());
        println!("Repository: {owner}/{repo}\n");

        // Step 1: Fetch trust list from GitHub
        log::info!("Fetching trust list from GitHub...");
        let trust_map = fetch_trust_list(&readonly_client, &owner, &repo).await?;

        // Policy (allow list, hard stop) from the base ref, never the branch
        // under review: a PR must not be able to allow-list itself.
        let mut policy = VerifyConfig::load_from_ref(&git_repo, &self.base)?;
        if self.fail_on_external {
            policy.fail_on_external = true;
        }
        log::info!(
            "Policy from {}: {} allow-list entr{}, hard stop for external contributors {}",
            self.base,
            policy.allow.len(),
            if policy.allow.len() == 1 { "y" } else { "ies" },
            if policy.fail_on_external { "on" } else { "off" }
        );

        // Step 2: Extract commits from git
        log::info!("Extracting commits from {}..{}", self.base, self.head);
        let commits = extract_commits(&git_repo, &self.base, &self.head)?;

        if commits.is_empty() {
            println!("{}\n", "ℹ  No commits to verify".yellow());
            return Ok(CIExit::VerificationPassed);
        }

        println!("ℹ  Found {} commit(s) to verify\n", commits.len());

        // Step 3: Verify commits against the trust map and the policy
        let (results, summary) = verify_commits_with(commits, &trust_map, &policy);

        // Step 4: Display results (privacy-safe)
        display_results(&results);

        // Step 5: Display summary
        display_summary(&summary, &results);

        // Early return on failure if requested
        if summary.failures > 0 && self.fail_on_unsigned {
            return Err(Error::SignatureVerificationFailed(summary.failures));
        }

        // Step 6: Post PR comment if requested
        if self.post_comment {
            if let Some(pr_number) = self.pr_number {
                log::info!("Posting verification results to PR #{pr_number}");

                // Create a separate client with write access for posting
                // comments This requires GITHUB_TOKEN env var
                // with write permissions
                match initialize_github_client_from_env() {
                    Ok(write_client) => {
                        if let Err(e) = post_verification_comment(
                            &write_client,
                            &owner,
                            &repo,
                            pr_number,
                            &results,
                            &summary,
                        )
                        .await
                        {
                            log::warn!("Failed to post PR comment: {e}");
                            eprintln!("⚠  Warning: Failed to post PR comment: {e}");
                        }
                    }
                    Err(e) => {
                        log::warn!("Cannot post PR comment - GITHUB_TOKEN env var not set for write access: {e}");
                        eprintln!("⚠  Warning: Cannot post PR comment - GITHUB_TOKEN env var required for write access");
                    }
                }
            }
        }

        if summary.failures > 0 {
            Err(Error::SignatureVerificationFailed(summary.failures))
        } else {
            Ok(CIExit::VerificationPassed)
        }
    }
}

/// Post verification results as a PR comment
async fn post_verification_comment(
    github: &Octocrab,
    owner: &str,
    repo: &str,
    pr_number: u64,
    results: &[crate::ops::signature_ops::VerificationResult],
    summary: &crate::ops::signature_ops::VerificationSummary,
) -> Result<(), Error> {
    let comment = build_comment(results, summary)?;
    post_comment_to_github(github, owner, repo, pr_number, &comment).await?;
    Ok(())
}

/// Build the verification comment body
fn build_comment(
    results: &[crate::ops::signature_ops::VerificationResult],
    summary: &crate::ops::signature_ops::VerificationSummary,
) -> Result<String, Error> {
    use std::fmt::Write;

    let mut comment = String::new();
    let write_err = |e| Error::GpgError(format!("Failed to write comment: {e}"));

    if summary.failures > 0 {
        writeln!(&mut comment, "## ❌ Commit Signature Verification - FAILED")
            .map_err(write_err)?;
        writeln!(&mut comment).map_err(write_err)?;
        writeln!(
            &mut comment,
            "**⚠️ Security Alert:** One or more commits failed signature verification."
        )
        .map_err(write_err)?;
        writeln!(&mut comment).map_err(write_err)?;

        // List failed commits
        writeln!(&mut comment, "### Failed Commits").map_err(write_err)?;
        writeln!(&mut comment).map_err(write_err)?;

        write_failed_commits(&mut comment, results).map_err(write_err)?;

        writeln!(&mut comment).map_err(write_err)?;
        write_summary(&mut comment, summary, true).map_err(write_err)?;

        if summary.external_contributors > 0 {
            writeln!(&mut comment).map_err(write_err)?;
            write_external_contributors(&mut comment, results).map_err(write_err)?;
        }

        if summary.allow_listed > 0 {
            writeln!(&mut comment).map_err(write_err)?;
            write_allow_listed(&mut comment, results).map_err(write_err)?;
        }

        writeln!(&mut comment).map_err(write_err)?;
        write_action_required(&mut comment).map_err(write_err)?;
    } else {
        writeln!(
            &mut comment,
            "## ✅ Commit Signature Verification - Success"
        )
        .map_err(write_err)?;
        writeln!(&mut comment).map_err(write_err)?;
        writeln!(&mut comment, "All commits have been verified successfully.")
            .map_err(write_err)?;
        writeln!(&mut comment).map_err(write_err)?;
        write_summary(&mut comment, summary, false).map_err(write_err)?;

        if summary.external_contributors > 0 {
            writeln!(&mut comment).map_err(write_err)?;
            write_external_contributors(&mut comment, results).map_err(write_err)?;
        }

        if summary.allow_listed > 0 {
            writeln!(&mut comment).map_err(write_err)?;
            write_allow_listed(&mut comment, results).map_err(write_err)?;
        }

        writeln!(&mut comment).map_err(write_err)?;
        writeln!(&mut comment, "No impersonation attempts detected.").map_err(write_err)?;
    }

    Ok(comment)
}

/// Write failed commits section
fn write_failed_commits(
    comment: &mut String,
    results: &[crate::ops::signature_ops::VerificationResult],
) -> std::fmt::Result {
    use std::fmt::Write;

    for result in results.iter().filter(|r| !r.passed) {
        let sha_short = &result.commit.sha[..8.min(result.commit.sha.len())];
        writeln!(
            comment,
            "- `{}` {} - {}",
            sha_short,
            escape_markdown_text(&result.commit.subject),
            result.reason.display_message()
        )?;
    }
    Ok(())
}

/// Write summary section
fn write_summary(
    comment: &mut String,
    summary: &crate::ops::signature_ops::VerificationSummary,
    include_failures: bool,
) -> std::fmt::Result {
    use std::fmt::Write;

    writeln!(comment, "### Summary")?;
    writeln!(
        comment,
        "- **Commits checked**: {}",
        summary.commits_checked
    )?;
    writeln!(
        comment,
        "- **Trusted verified**: {}",
        summary.trusted_verified
    )?;
    if summary.allow_listed > 0 {
        writeln!(comment, "- **Allow-listed**: {}", summary.allow_listed)?;
    }
    writeln!(
        comment,
        "- **External contributors**: {}",
        summary.external_contributors
    )?;
    if include_failures {
        writeln!(comment, "- **Failures**: ❗ {}", summary.failures)?;
    }
    Ok(())
}

/// Write action required section
fn write_action_required(comment: &mut String) -> std::fmt::Result {
    use std::fmt::Write;

    writeln!(comment, "### Action Required")?;
    writeln!(comment, "- Review the failed commits immediately")?;
    writeln!(comment, "- Verify the committer's identity")?;
    writeln!(comment, "- **DO NOT MERGE** if impersonation is suspected")?;
    Ok(())
}

/// Whether a verification result is for an author who is neither a trusted
/// identity nor allow-listed.
fn is_external(reason: &crate::ops::signature_ops::VerificationReason) -> bool {
    use crate::ops::signature_ops::VerificationReason;

    matches!(
        reason,
        VerificationReason::ExternalUnsigned
            | VerificationReason::ExternalInvalidSignature
            | VerificationReason::ExternalNotAllowed { .. }
    )
}

/// Write external contributors table section. Writes nothing when there are
/// no external contributors.
fn write_external_contributors(
    comment: &mut String,
    results: &[crate::ops::signature_ops::VerificationResult],
) -> std::fmt::Result {
    use std::fmt::Write;

    use crate::ops::signature_ops::VerificationReason;

    let external: Vec<_> = results.iter().filter(|r| is_external(&r.reason)).collect();
    if external.is_empty() {
        return Ok(());
    }

    writeln!(comment, "### External Contributors")?;
    writeln!(comment)?;
    writeln!(comment, "| Commit | Author | Status |")?;
    writeln!(comment, "|--------|--------|--------|")?;

    for result in external {
        let sha_short = &result.commit.sha[..8.min(result.commit.sha.len())];
        let status = match &result.reason {
            VerificationReason::ExternalNotAllowed { .. } => "❌ Not on the allow list",
            VerificationReason::ExternalInvalidSignature => {
                "⚠️ Invalid signature (bad, expired or revoked key)"
            }
            _ => "Unsigned (expected for bots/external)",
        };
        writeln!(
            comment,
            "| `{}` | `{}` | {} |",
            sha_short,
            sanitize_code_span(&result.commit.author_email),
            status
        )?;
    }
    Ok(())
}

/// Write the allow-listed identities table. Writes nothing when none matched.
fn write_allow_listed(
    comment: &mut String,
    results: &[crate::ops::signature_ops::VerificationResult],
) -> std::fmt::Result {
    use std::fmt::Write;

    use crate::ops::signature_ops::VerificationReason;

    let allowed: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.reason, VerificationReason::AllowListed))
        .collect();
    if allowed.is_empty() {
        return Ok(());
    }

    writeln!(comment, "### Allow-listed Identities")?;
    writeln!(comment)?;
    writeln!(comment, "| Commit | Author | Signing key |")?;
    writeln!(comment, "|--------|--------|-------------|")?;

    for result in allowed {
        let sha_short = &result.commit.sha[..8.min(result.commit.sha.len())];
        writeln!(
            comment,
            "| `{}` | `{}` | `{}` |",
            sha_short,
            sanitize_code_span(&result.commit.author_email),
            sanitize_code_span(result.commit.key_id.as_deref().unwrap_or(""))
        )?;
    }
    Ok(())
}

/// Post comment to GitHub using octocrab's issues API
/// Updates existing comment if found, otherwise creates a new one
async fn post_comment_to_github(
    github: &Octocrab,
    owner: &str,
    repo: &str,
    pr_number: u64,
    comment: &str,
) -> Result<(), Error> {
    // First, try to find an existing verification comment
    let existing_comment_id =
        find_existing_verification_comment(github, owner, repo, pr_number).await?;

    if let Some(comment_id) = existing_comment_id {
        // Update existing comment
        log::info!("Updating existing PR comment (ID: {comment_id})");
        github
            .issues(owner, repo)
            .update_comment(comment_id, comment)
            .await
            .map_err(|e| Error::GpgError(format!("Failed to update PR comment: {e}")))?;
    } else {
        // Create new comment
        log::info!("Creating new PR comment");
        github
            .issues(owner, repo)
            .create_comment(pr_number, comment)
            .await
            .map_err(|e| Error::GpgError(format!("Failed to create PR comment: {e}")))?;
    }

    Ok(())
}

/// Find existing verification comment on the PR
/// Returns the comment ID if found
async fn find_existing_verification_comment(
    github: &Octocrab,
    owner: &str,
    repo: &str,
    pr_number: u64,
) -> Result<Option<octocrab::models::CommentId>, Error> {
    // List all comments on the PR
    let comments = github
        .issues(owner, repo)
        .list_comments(pr_number)
        .send()
        .await
        .map_err(|e| Error::GpgError(format!("Failed to list PR comments: {e}")))?;

    // Look for a comment containing our signature header
    for comment in comments {
        if let Some(body) = &comment.body {
            if body.contains("## ❌ Commit Signature Verification")
                || body.contains("## ✅ Commit Signature Verification")
            {
                return Ok(Some(comment.id));
            }
        }
    }

    Ok(None)
}

/// Initialize GitHub API client from GITHUB_TOKEN env var
fn initialize_github_client_from_env() -> Result<Octocrab, Error> {
    let github_token = env::var("GITHUB_TOKEN")
        .map_err(|_| Error::GpgError("GITHUB_TOKEN environment variable not set".to_string()))?;

    Ok(Octocrab::builder().personal_token(github_token).build()?)
}

/// Initialize GitHub API client with provided token or fallback
fn initialize_github_client_with_token(
    token: Option<&str>,
    error_msg: &str,
) -> Result<Octocrab, Error> {
    let github_token = token
        .map(String::from)
        .ok_or_else(|| Error::GpgError(error_msg.to_string()))?;

    Ok(Octocrab::builder().personal_token(github_token).build()?)
}

/// Detect repository owner and name from git config or CLI args
fn detect_repository(
    git_repo: &git2::Repository,
    repo_owner: &Option<String>,
    repo_name: &Option<String>,
) -> Result<(String, String), Error> {
    if let (Some(o), Some(r)) = (repo_owner, repo_name) {
        return Ok((o.clone(), r.clone()));
    }

    // Try to auto-detect from git remote
    let remote = git_repo.find_remote("origin")?;
    let url = remote
        .url()
        .map_err(|e| Error::GitError(format!("No valid URL for origin remote: {e}")))?;

    let (parsed_owner, parsed_repo) = parse_github_url(url)?;

    Ok((
        repo_owner.clone().unwrap_or(parsed_owner),
        repo_name.clone().unwrap_or(parsed_repo),
    ))
}

/// Display verification results for each commit
fn display_results(results: &[crate::ops::signature_ops::VerificationResult]) {
    for result in results {
        let sha_short = &result.commit.sha[..8.min(result.commit.sha.len())];
        let status_symbol = if result.passed {
            "✓".green().bold().to_string()
        } else {
            "✗".red().bold().to_string()
        };

        println!(
            "{} {}   {} {}",
            status_symbol,
            if result.passed { "OK" } else { "FAIL" },
            sha_short.bold(),
            strip_control(&result.commit.subject)
        );

        // Show reason (privacy-safe, no PII)
        println!("    {}", result.reason.display_message());
        println!();
    }
}

/// Display verification summary
fn display_summary(
    summary: &crate::ops::signature_ops::VerificationSummary,
    results: &[crate::ops::signature_ops::VerificationResult],
) {
    println!("{}\n", "=== Verification Summary ===".bold());
    println!("Commits checked:         {}", summary.commits_checked);
    println!(
        "Trusted verified:        {}",
        summary.trusted_verified.to_string().green()
    );
    if summary.allow_listed > 0 {
        println!(
            "Allow-listed:            {}",
            summary.allow_listed.to_string().green()
        );
    }
    println!(
        "External contributors:   {}",
        summary.external_contributors.to_string().green()
    );

    if summary.failures > 0 {
        println!(
            "Failures:                {}\n",
            summary.failures.to_string().red().bold()
        );
        println!("{}", "✗ Signature verification FAILED!".red().bold());
        println!("\n{}:", "Action required".bold());
        println!("  - Review failed commits immediately");
        println!("  - Verify the committer's identity");
        println!("  - Do NOT merge if impersonation is suspected\n");
    } else {
        println!();
        println!("{}", "✓ All signature checks passed!".green().bold());
        println!("\nNo impersonation attempts detected.\n");
    }

    // List external contributors with their identities
    let external: Vec<_> = results.iter().filter(|r| is_external(&r.reason)).collect();

    if !external.is_empty() {
        println!("{}", "External Contributors:".bold());
        for result in external {
            let sha_short = &result.commit.sha[..8.min(result.commit.sha.len())];
            println!(
                "  {} {}",
                sha_short.bold(),
                strip_control(&result.commit.author_email)
            );
        }
        println!();
    }
}

/// Parse GitHub URL to extract owner and repo
/// Supports both HTTPS and SSH formats
fn parse_github_url(url: &str) -> Result<(String, String), Error> {
    // Remove .git suffix if present
    let url = url.trim_end_matches(".git");

    if url.starts_with("https://github.com/") {
        // HTTPS format: https://github.com/owner/repo
        let parts: Vec<&str> = url
            .trim_start_matches("https://github.com/")
            .split('/')
            .collect();
        if parts.len() >= 2 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        }
    } else if url.starts_with("git@github.com:") {
        // SSH format: git@github.com:owner/repo
        let parts: Vec<&str> = url
            .trim_start_matches("git@github.com:")
            .split('/')
            .collect();
        if parts.len() >= 2 {
            return Ok((parts[0].to_string(), parts[1].to_string()));
        }
    }

    Err(Error::GitError(format!(
        "Unable to parse GitHub URL: {url}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::signature_ops::{
        CommitInfo, SignatureStatus, VerificationReason, VerificationResult, VerificationSummary,
    };

    fn make_external_result(sha: &str, email: &str) -> VerificationResult {
        VerificationResult {
            commit: CommitInfo {
                sha: sha.to_string(),
                author_email: email.to_string(),
                author_name: "External User".to_string(),
                subject: "external commit".to_string(),
                signature_status: SignatureStatus::None,
                key_id: None,
                signer: None,
            },
            passed: true,
            reason: VerificationReason::ExternalUnsigned,
        }
    }

    /// RED: issue #862 — success comment must include "External Contributors"
    /// section when there are external contributor results
    #[test]
    fn test_build_comment_includes_external_contributors_section() {
        let results = vec![make_external_result(
            "a1b2c3d4e5f6",
            "renovate[bot]@users.noreply.github.com",
        )];
        let summary = VerificationSummary {
            commits_checked: 1,
            trusted_verified: 0,
            allow_listed: 0,
            external_contributors: 1,
            failures: 0,
        };

        let comment = build_comment(&results, &summary).unwrap();
        assert!(
            comment.contains("External Contributors"),
            "Comment should contain 'External Contributors' section, got:\n{comment}"
        );
    }

    /// RED: issue #862 — success comment must include author email of external
    /// contributor
    #[test]
    fn test_build_comment_includes_external_contributor_email() {
        let results = vec![make_external_result(
            "a1b2c3d4e5f6",
            "renovate[bot]@users.noreply.github.com",
        )];
        let summary = VerificationSummary {
            commits_checked: 1,
            trusted_verified: 0,
            allow_listed: 0,
            external_contributors: 1,
            failures: 0,
        };

        let comment = build_comment(&results, &summary).unwrap();
        assert!(
            comment.contains("renovate[bot]@users.noreply.github.com"),
            "Comment should include external contributor email, got:\n{comment}"
        );
    }

    /// RED: issue #862 — success comment must include short SHA of external
    /// contributor commit
    #[test]
    fn test_build_comment_includes_external_contributor_sha() {
        let results = vec![make_external_result(
            "a1b2c3d4e5f6",
            "renovate[bot]@users.noreply.github.com",
        )];
        let summary = VerificationSummary {
            commits_checked: 1,
            trusted_verified: 0,
            allow_listed: 0,
            external_contributors: 1,
            failures: 0,
        };

        let comment = build_comment(&results, &summary).unwrap();
        // short SHA = first 8 chars
        assert!(
            comment.contains("a1b2c3d4"),
            "Comment should include short SHA of external contributor, got:\n{comment}"
        );
    }

    /// Verify that the comment does NOT include external contributor section
    /// when there are no external contributors (regression guard)
    #[test]
    fn test_build_comment_no_external_contributors_no_section() {
        let results = vec![];
        let summary = VerificationSummary {
            commits_checked: 0,
            trusted_verified: 0,
            allow_listed: 0,
            external_contributors: 0,
            failures: 0,
        };

        let comment = build_comment(&results, &summary).unwrap();
        assert!(
            !comment.contains("### External Contributors"),
            "Comment should not contain external contributors section when there are none, got:\n{comment}"
        );
    }

    fn summary_for(failures: usize, external: usize) -> VerificationSummary {
        VerificationSummary {
            commits_checked: failures + external,
            trusted_verified: 0,
            allow_listed: 0,
            external_contributors: external,
            failures,
        }
    }

    /// An author email that closes the code span must not be able to render
    /// markup (a link, an image) in the comment posted under the bot's name.
    #[test]
    fn test_comment_neutralises_markdown_in_author_email() {
        let hostile = "a`[Approve](https://evil.example)`@b.test";
        let comment = build_comment(
            &[make_external_result("a1b2c3d4e5f6", hostile)],
            &summary_for(0, 1),
        )
        .unwrap();

        let row = comment
            .lines()
            .find(|l| l.contains("a1b2c3d4"))
            .expect("table row");
        assert_eq!(
            row.matches('`').count(),
            4,
            "only the sha and email spans may use backticks: {row}"
        );
        assert!(!row.contains('\n'));
    }

    #[test]
    fn test_comment_keeps_the_table_to_three_columns() {
        let comment = build_comment(
            &[make_external_result(
                "a1b2c3d4e5f6",
                "x|y|z@b.test\n## fake",
            )],
            &summary_for(0, 1),
        )
        .unwrap();

        let row = comment
            .lines()
            .find(|l| l.contains("a1b2c3d4"))
            .expect("table row");
        assert_eq!(row.matches('|').count(), 4, "three columns: {row}");
        assert!(!comment.contains("\n## fake"));
    }

    #[test]
    fn test_escape_markdown_text_neutralises_links_mentions_and_newlines() {
        let escaped = escape_markdown_text("[click](https://evil.example) @maintainer\n## hi <b>");

        assert!(!escaped.contains("]("), "no live link: {escaped}");
        assert!(!escaped.contains('\n'));
        assert!(
            escaped.contains("@\u{200B}maintainer"),
            "mention broken: {escaped}"
        );
        assert!(!escaped.contains("<b>"));
    }

    #[test]
    fn test_untrusted_text_is_truncated() {
        let long = "a".repeat(MAX_UNTRUSTED_LEN + 50);

        assert_eq!(
            sanitize_code_span(&long).chars().count(),
            MAX_UNTRUSTED_LEN + 1
        );
        assert_eq!(
            escape_markdown_text(&long).chars().count(),
            MAX_UNTRUSTED_LEN + 1
        );
    }

    #[test]
    fn test_strip_control_removes_terminal_escapes() {
        assert_eq!(strip_control("ok\x1b[31mred\x07"), "ok?[31mred?");
    }

    /// The token must not appear when the CLI arguments are debug-logged.
    #[test]
    fn test_debug_output_redacts_the_github_token() {
        use clap::Parser;

        let secret = "ghp_SECRETVALUE0123456789";
        let verify = VerifySignatures::parse_from(["verify-signatures", "--github-token", secret]);
        let shown = format!("{verify:?}");
        assert!(!shown.contains(secret), "token leaked: {shown}");
        assert!(shown.contains("<redacted>"), "got: {shown}");

        let comment =
            crate::cli::comment_pr::CommentPr::parse_from(["comment-pr", "--github-token", secret]);
        assert!(!format!("{comment:?}").contains(secret));

        let issue = crate::cli::create_issue::CreateIssue::parse_from([
            "create-issue",
            "--title",
            "t",
            "--github-token",
            secret,
        ]);
        assert!(!format!("{issue:?}").contains(secret));
    }

    // --- allow list and hard stop (#1132) -----------------------------------

    fn result_with(
        sha: &str,
        email: &str,
        reason: VerificationReason,
        passed: bool,
        key: Option<&str>,
    ) -> VerificationResult {
        VerificationResult {
            commit: CommitInfo {
                sha: sha.to_string(),
                author_email: email.to_string(),
                author_name: "Someone".to_string(),
                subject: "a commit".to_string(),
                signature_status: SignatureStatus::Good,
                key_id: key.map(str::to_string),
                signer: None,
            },
            passed,
            reason,
        }
    }

    fn summary_with(allow_listed: usize, external: usize, failures: usize) -> VerificationSummary {
        VerificationSummary {
            commits_checked: allow_listed + external + failures,
            trusted_verified: 0,
            allow_listed,
            external_contributors: external,
            failures,
        }
    }

    #[test]
    fn test_comment_lists_allow_listed_identities_with_their_key() {
        let results = vec![result_with(
            "aabbccdd1122",
            "29139614+renovate[bot]@users.noreply.github.com",
            VerificationReason::AllowListed,
            true,
            Some("B5690EEEBB952194"),
        )];

        let comment = build_comment(&results, &summary_with(1, 0, 0)).unwrap();

        assert!(comment.contains("### Allow-listed Identities"), "{comment}");
        assert!(comment.contains("- **Allow-listed**: 1"), "{comment}");
        assert!(comment.contains("`B5690EEEBB952194`"), "{comment}");
        assert!(comment.contains("`aabbccdd`"), "{comment}");
        assert!(!comment.contains("### External Contributors"), "{comment}");
        assert!(
            comment.contains("All commits have been verified"),
            "{comment}"
        );
    }

    #[test]
    fn test_comment_omits_the_allow_listed_section_when_none_matched() {
        let results = vec![make_external_result("a1b2c3d4e5f6", "x@example.test")];

        let comment = build_comment(&results, &summary_with(0, 1, 0)).unwrap();

        assert!(!comment.contains("Allow-listed"), "{comment}");
    }

    /// With the hard stop on, a commit from an unlisted external author fails,
    /// is listed under the failed commits and shown as not allowed.
    #[test]
    fn test_comment_reports_the_hard_stop_as_a_failure() {
        let results = vec![result_with(
            "deadbeef0000",
            "stranger@example.test",
            VerificationReason::ExternalNotAllowed {
                invalid_signature: false,
            },
            false,
            None,
        )];

        let comment = build_comment(&results, &summary_with(0, 1, 1)).unwrap();

        assert!(comment.contains("FAILED"), "{comment}");
        assert!(comment.contains("### Failed Commits"), "{comment}");
        assert!(
            comment.contains("External contributor not on the allow list"),
            "{comment}"
        );
        assert!(comment.contains("### External Contributors"), "{comment}");
        assert!(comment.contains("❌ Not on the allow list"), "{comment}");
        let table_rows = comment
            .lines()
            .filter(|l| l.starts_with("| `deadbeef`"))
            .count();
        assert_eq!(table_rows, 1, "the table must not be empty: {comment}");
    }

    #[test]
    fn test_comment_reports_an_allow_listed_identity_with_a_bad_signature_as_failed() {
        let results = vec![result_with(
            "cafe00001111",
            "29139614+renovate[bot]@users.noreply.github.com",
            VerificationReason::AllowListedBadSignature,
            false,
            Some("1111111111111111"),
        )];

        let comment = build_comment(&results, &summary_with(0, 0, 1)).unwrap();

        assert!(comment.contains("FAILED"), "{comment}");
        assert!(
            comment.contains(
                "Allow-listed identity: signature missing, invalid or from an unapproved key"
            ),
            "{comment}"
        );
    }

    #[test]
    fn test_fail_on_external_flag_is_parsed_and_off_by_default() {
        use clap::Parser;

        let off = VerifySignatures::parse_from(["verify-signatures"]);
        let on = VerifySignatures::parse_from(["verify-signatures", "--fail-on-external"]);

        assert!(!off.fail_on_external);
        assert!(on.fail_on_external);
        assert!(format!("{on:?}").contains("fail_on_external: true"));
    }
}
