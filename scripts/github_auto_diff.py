#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

from pathlib import Path

# Ensure local repository modules resolve when this script is executed as a
# remote action (where site-packages may lag behind action source).
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from brain.core.auto_diff_report import (
    build_auto_diff_summary,
    render_auto_diff_markdown,
    render_bootstrap_markdown,
)
from brain.core.diff import diff_sarif


def main() -> int:
    parser = argparse.ArgumentParser(description="Create and publish a CASM Auto-Diff GitHub report.")
    parser.add_argument("--new-sarif", required=True, help="Path to current SARIF file")
    parser.add_argument("--old-sarif", default=None, help="Path to baseline SARIF file")
    parser.add_argument("--tool", default="http_verify", help="Tool filter for SARIF diff")
    parser.add_argument("--max-findings", type=int, default=20, help="Max findings listed per section")
    parser.add_argument("--run-url", default=None, help="Actions run URL")
    parser.add_argument("--evidence-path", default=None, help="Path to evidence JSONL")
    parser.add_argument("--report-path", default=None, help="Path to markdown report")
    parser.add_argument("--summary-path", default=None, help="Write rendered markdown to this path")
    parser.add_argument("--json-out", default=None, help="Write machine-readable summary JSON to this path")
    parser.add_argument(
        "--mode",
        choices=["none", "auto", "issue", "pr"],
        default="auto",
        help="Publish target mode",
    )
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"), help="owner/repo")
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub token")
    parser.add_argument("--pr-number", type=int, default=None, help="PR number for PR comments")
    parser.add_argument("--issue-number", type=int, default=None, help="Issue number for issue comments")
    parser.add_argument(
        "--issue-title",
        default="CASM Security Baseline",
        help="Issue title used when creating/finding baseline issue",
    )
    parser.add_argument(
        "--issue-label",
        action="append",
        default=None,
        help="Label(s) to apply when creating a baseline issue (repeatable)",
    )
    parser.add_argument(
        "--post-on-no-change",
        action="store_true",
        help="Publish even if baseline exists and there are no added/removed findings",
    )
    args = parser.parse_args()

    new_sarif = Path(args.new_sarif)
    if not new_sarif.exists():
        print(f"Missing --new-sarif path: {new_sarif}", file=sys.stderr)
        return 2

    has_baseline = bool(args.old_sarif and Path(args.old_sarif).exists())
    rendered = ""
    added_count = 0
    removed_count = 0
    unchanged_count = 0
    has_changes = False

    if has_baseline:
        diff = diff_sarif(str(Path(args.old_sarif)), str(new_sarif), tool_filter=args.tool)
        summary = build_auto_diff_summary(diff, max_findings=args.max_findings)
        rendered = render_auto_diff_markdown(
            summary,
            old_label=str(args.old_sarif),
            new_label=str(new_sarif),
            run_url=args.run_url,
            evidence_path=args.evidence_path,
            sarif_path=str(new_sarif),
            report_path=args.report_path,
        )
        added_count = summary.added_count
        removed_count = summary.removed_count
        unchanged_count = summary.unchanged_count
        has_changes = summary.has_changes
    else:
        rendered = render_bootstrap_markdown(
            new_label=str(new_sarif),
            run_url=args.run_url,
            evidence_path=args.evidence_path,
            sarif_path=str(new_sarif),
            report_path=args.report_path,
        )

    if args.summary_path:
        summary_path = Path(args.summary_path)
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)

    job_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if job_summary_path:
        with Path(job_summary_path).open("a", encoding="utf-8") as handle:
            handle.write(rendered + "\n")

    publish_mode = args.mode
    published = False
    target_kind = "none"
    target_number = None
    post_skipped_reason = ""

    if publish_mode == "none":
        post_skipped_reason = "mode_none"
    elif has_baseline and not has_changes and not args.post_on_no_change:
        post_skipped_reason = "no_change"
    elif not args.repo or not args.token:
        post_skipped_reason = "missing_repo_or_token"
    else:
        target_kind, target_number = _resolve_target(
            mode=publish_mode,
            repo=args.repo,
            token=args.token,
            pr_number=args.pr_number,
            issue_number=args.issue_number,
            issue_title=args.issue_title,
            issue_labels=args.issue_label or [],
        )
        if target_number is None:
            post_skipped_reason = "missing_target_number"
        else:
            comment = _post_comment(
                repo=args.repo,
                token=args.token,
                issue_number=target_number,
                body=rendered,
            )
            published = True
            print(
                f"Published CASM Auto-Diff comment to {target_kind} #{target_number}: {comment.get('html_url', '')}",
                file=sys.stderr,
            )

    payload = {
        "has_baseline": has_baseline,
        "added_count": added_count,
        "removed_count": removed_count,
        "unchanged_count": unchanged_count,
        "has_changes": has_changes,
        "published": published,
        "target_kind": target_kind,
        "target_number": target_number,
        "post_skipped_reason": post_skipped_reason,
        "new_sarif": str(new_sarif),
        "old_sarif": str(args.old_sarif) if args.old_sarif else "",
    }
    if args.summary_path:
        payload["summary_path"] = str(args.summary_path)

    if args.json_out:
        json_out = Path(args.json_out)
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    return 0


def _resolve_target(
    *,
    mode: str,
    repo: str,
    token: str,
    pr_number: int | None,
    issue_number: int | None,
    issue_title: str,
    issue_labels: list[str],
) -> tuple[str, int | None]:
    if mode == "pr":
        return "pr", pr_number

    if mode == "issue":
        if issue_number is not None:
            return "issue", issue_number
        number, _ = _find_or_create_issue(
            repo=repo,
            token=token,
            title=issue_title,
            labels=issue_labels,
        )
        return "issue", number

    if pr_number is not None:
        return "pr", pr_number
    if issue_number is not None:
        return "issue", issue_number

    number, _ = _find_or_create_issue(
        repo=repo,
        token=token,
        title=issue_title,
        labels=issue_labels,
    )
    return "issue", number


def _find_or_create_issue(
    *,
    repo: str,
    token: str,
    title: str,
    labels: list[str],
) -> tuple[int, bool]:
    issues = _api_request(
        "GET",
        f"https://api.github.com/repos/{repo}/issues?state=open&per_page=100",
        token=token,
        payload=None,
    )
    if isinstance(issues, list):
        for item in issues:
            if not isinstance(item, dict):
                continue
            if "pull_request" in item:
                continue
            if item.get("title") == title and isinstance(item.get("number"), int):
                return int(item["number"]), False

    payload = {
        "title": title,
        "body": "Tracking issue for CASM Auto-Diff findings and evidence-backed change reports.",
    }
    if labels:
        payload["labels"] = labels
    try:
        created = _api_request(
            "POST",
            f"https://api.github.com/repos/{repo}/issues",
            token=token,
            payload=payload,
        )
    except RuntimeError:
        if not labels:
            raise
        created = _api_request(
            "POST",
            f"https://api.github.com/repos/{repo}/issues",
            token=token,
            payload={
                "title": payload["title"],
                "body": payload["body"],
            },
        )

    if not isinstance(created, dict) or not isinstance(created.get("number"), int):
        raise RuntimeError("GitHub API did not return an issue number")
    return int(created["number"]), True


def _post_comment(*, repo: str, token: str, issue_number: int, body: str) -> dict:
    result = _api_request(
        "POST",
        f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments",
        token=token,
        payload={"body": body},
    )
    if isinstance(result, dict):
        return result
    return {}


def _api_request(method: str, url: str, *, token: str, payload: dict | None) -> dict | list | None:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url=url,
        data=body,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "casm-auto-diff-bot",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API request failed ({method} {url}) status={exc.code} detail={detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"GitHub API request failed ({method} {url}) error={exc.reason}") from exc

    if not raw.strip():
        return None
    return json.loads(raw)


if __name__ == "__main__":
    raise SystemExit(main())
