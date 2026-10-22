#!/usr/bin/env python3
"""Bootstrap GitHub labels, milestones, issues and the roadmap Project from
.github/backlog/backlog.json.

Dry-run by default: it prints exactly what it would create. Publishing issues
is visible to everyone, so --apply is an explicit, reviewed step.

Idempotent: existing labels are updated, existing milestones and issues (same
title) are skipped, so re-running after editing the backlog only adds new items.

Requires the GitHub CLI, authenticated: `gh auth login` (add the `project`
scope for --project: `gh auth refresh -s project`).

Usage:
  scripts/github/bootstrap.py                      # dry run
  scripts/github/bootstrap.py --apply              # labels, milestones, issues
  scripts/github/bootstrap.py --apply --project    # ... and the Project board
"""

import argparse
import json
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKLOG = ROOT / ".github" / "backlog" / "backlog.json"
PROJECT_TITLE = "ShieldMon Roadmap"


def gh(*args, parse=False):
    res = subprocess.run(["gh", *args], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])}…: {res.stderr.strip()}")
    return json.loads(res.stdout) if parse else res.stdout.strip()


def default_repo():
    url = subprocess.run(["git", "-C", str(ROOT), "remote", "get-url", "origin"],
                         capture_output=True, text=True, check=True).stdout.strip()
    # git@github.com:owner/repo.git or https://github.com/owner/repo(.git)
    path = url.split("github.com", 1)[1].lstrip(":/")
    return path.removesuffix(".git")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", default=None, help="owner/name (default: origin remote)")
    ap.add_argument("--apply", action="store_true", help="actually create things on GitHub")
    ap.add_argument("--project", action="store_true", help="also create/fill the Project board")
    args = ap.parse_args()

    data = json.loads(BACKLOG.read_text())
    repo = args.repo or default_repo()
    owner = repo.split("/")[0]

    print(f"Repository: {repo}{'' if args.apply else '   (DRY RUN — nothing is published)'}\n")
    print(f"Labels ({len(data['labels'])}): " + ", ".join(l["name"] for l in data["labels"]))
    print(f"\nMilestones ({len(data['milestones'])}):")
    for m in data["milestones"]:
        print(f"  - {m['title']}")
    by_ms = {}
    for i in data["issues"]:
        by_ms.setdefault(i["milestone"], []).append(i)
    print(f"\nIssues ({len(data['issues'])}):")
    for ms, items in by_ms.items():
        print(f"  {ms}")
        for i in sorted(items, key=lambda x: not x["title"].startswith("[epic]")):
            print(f"    - {i['title']}  [{', '.join(i['labels'])}]")
    if args.project:
        print(f"\nProject: '{PROJECT_TITLE}' (owner {owner}) with every issue added")
    if not args.apply:
        print("\nRe-run with --apply to publish.")
        return

    gh("auth", "status")

    for l in data["labels"]:
        gh("label", "create", l["name"], "--repo", repo, "--color", l["color"],
           "--description", l["description"], "--force")
    print("labels: synced")

    existing_ms = {m["title"] for m in gh("api", f"repos/{repo}/milestones?state=all&per_page=100", parse=True)}
    for idx, m in enumerate(data["milestones"]):
        if m["title"] in existing_ms:
            continue
        state = "closed" if idx == 0 else "open"  # M1 shipped with the first version
        gh("api", f"repos/{repo}/milestones", "-f", f"title={m['title']}",
           "-f", f"description={m['description']}", "-f", f"state={state}")
        print(f"milestone: {m['title']}")

    existing = {i["title"]: i["number"] for i in
                gh("issue", "list", "--repo", repo, "--state", "all", "--limit", "1000",
                   "--json", "title,number", parse=True)}
    numbers = {}
    # Epics first so tasks can link to them.
    ordered = sorted(data["issues"], key=lambda i: not i["title"].startswith("[epic]"))
    for i in ordered:
        if i["title"] in existing:
            numbers[i["key"]] = existing[i["title"]]
            continue
        body = i["body"]
        if i.get("epic") and i["epic"] in numbers:
            body = f"Part of #{numbers[i['epic']]}\n\n" + body
        url = gh("issue", "create", "--repo", repo, "--title", i["title"], "--body", body,
                 "--milestone", i["milestone"], *sum((["--label", l] for l in i["labels"]), []))
        numbers[i["key"]] = int(url.rstrip("/").rsplit("/", 1)[1])
        print(f"issue #{numbers[i['key']]}: {i['title']}")
        time.sleep(1)  # stay well below secondary rate limits

    if args.project:
        projects = gh("project", "list", "--owner", owner, "--format", "json", parse=True)["projects"]
        proj = next((p for p in projects if p["title"] == PROJECT_TITLE), None)
        if proj is None:
            proj = gh("project", "create", "--owner", owner, "--title", PROJECT_TITLE, "--format", "json", parse=True)
            gh("project", "link", str(proj["number"]), "--owner", owner, "--repo", repo)
            print(f"project: created #{proj['number']}")
        for key, num in numbers.items():
            gh("project", "item-add", str(proj["number"]), "--owner", owner,
               "--url", f"https://github.com/{repo}/issues/{num}")
        print(f"project: {len(numbers)} issues added")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as e:
        sys.exit(f"bootstrap: {e}")
