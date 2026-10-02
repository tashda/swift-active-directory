#!/usr/bin/env python3
"""Writes the release notes for one release of a package repository.

The same file is used by every package repository (see .github/workflows/release.yml): commits are
grouped by what they touch, taken from the paths themselves, so no repository needs a table of its
own. Sources/<Target>/ gives one group per target; Tests, CI and packaging, and documentation get a
group each.
"""
from __future__ import annotations

import argparse
import os
import subprocess
from collections import Counter, OrderedDict

DOCUMENTATION_SUFFIXES = (".md", ".docc", ".txt")
# GitHub cuts a release body at 125,000 characters; the newest commits are the ones worth listing.
MAX_COMMITS = 150


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    return result.stdout.strip()


def git_lines(*args: str) -> list[str]:
    return [line for line in git(*args).splitlines() if line.strip()]


def category_of(path: str) -> str:
    parts = path.split("/")
    if parts[0] == "Sources" and len(parts) > 2:
        return parts[1]
    if parts[0] == "Sources":
        return "Sources"
    if parts[0] == "Tests" or parts[0].endswith("Tests"):
        return "Tests"
    if parts[0] in (".github", "scripts") or path in ("Package.swift", "Package.resolved"):
        return "CI & Packaging"
    if parts[0] == "docs" or ".docc" in path or path.endswith(DOCUMENTATION_SUFFIXES):
        return "Documentation"
    return "Other"


def category_of_commit(files: list[str]) -> str:
    counts = Counter(category_of(path) for path in files)
    if not counts:
        return "Other"
    best = max(counts.values())
    # First path wins a tie, so the order is stable.
    for path in files:
        name = category_of(path)
        if counts[name] == best:
            return name
    return "Other"


def short_paths(files: list[str], limit: int = 4) -> str:
    preview = ", ".join(f"`{path}`" for path in files[:limit])
    remainder = len(files) - limit
    return f"{preview}, and {remainder} more" if remainder > 0 else preview


def commit_range(previous_tag: str | None) -> str | None:
    if not previous_tag:
        return None
    verified = subprocess.run(["git", "rev-parse", "--verify", "--quiet", previous_tag], capture_output=True, text=True)
    return f"{previous_tag}..HEAD" if verified.returncode == 0 else None


def load_commits(range_spec: str | None) -> tuple[OrderedDict[str, list[tuple[str, list[str]]]], int]:
    """The commits grouped by category, and how many older ones were left out."""
    if range_spec:
        hashes = git_lines("rev-list", "--reverse", "--no-merges", range_spec)
    else:
        hashes = git_lines("rev-list", "--reverse", "--max-count=30", "--no-merges", "HEAD")
    omitted = max(0, len(hashes) - MAX_COMMITS)
    hashes = hashes[omitted:]
    grouped: OrderedDict[str, list[tuple[str, list[str]]]] = OrderedDict()
    for commit_hash in hashes:
        subject = git("show", "-s", "--format=%s", commit_hash)
        files = git_lines("show", "--format=", "--name-only", "--diff-filter=ACDMRTUXB", commit_hash)
        grouped.setdefault(category_of_commit(files), []).append((subject, files))
    return grouped, omitted


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-name", default=os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1])
    parser.add_argument("--new-tag", required=True)
    parser.add_argument("--previous-tag", default="")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    previous_tag = args.previous_tag.strip() or None
    range_spec = commit_range(previous_tag)
    if range_spec is None:
        previous_tag = None
    grouped, omitted = load_commits(range_spec)
    commit_count = sum(len(entries) for entries in grouped.values())
    repository = os.environ.get("GITHUB_REPOSITORY", "")

    lines = [f"# {args.repo_name} {args.new_tag}", "", "## Summary", ""]
    if previous_tag:
        lines.append(f"- Release range: `{previous_tag}` -> `{args.new_tag}`")
    else:
        lines.append(f"- First release: the latest {commit_count} commits are listed")
    lines.append(f"- Commits included: {commit_count}")
    if omitted:
        lines.append(f"- {omitted} older commits are not listed; the compare link shows all of them")
    if repository and previous_tag:
        lines.append(f"- Compare: https://github.com/{repository}/compare/{previous_tag}...{args.new_tag}")
    lines.extend(["", "## Detailed Changes", ""])

    if not grouped:
        lines.extend(["- No changes were detected in the selected range.", ""])
    else:
        for category, entries in grouped.items():
            lines.extend([f"### {category}", ""])
            for subject, files in entries:
                lines.append(f"- {subject}")
                if files:
                    lines.append(f"  - Touched: {short_paths(files)}")
            lines.append("")

    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + "\n")


if __name__ == "__main__":
    main()
