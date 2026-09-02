# Achilles recipes

First-party **packaged runs** for the Achilles harness. Skills teach the model
mid-chat. Recipes start a whole session with tools, parameters, and a prompt
already set — so a teammate (or a cron job) does not have to recite the
playbook.

These YAML files are compiled into the desktop and CLI binary (same idea as
skills). On launch they are written to the app data `shipped-recipes/`
folder and show up in the Recipe Library without an import. They cannot be
deleted; editing one saves a personal copy.

You can still import extra recipes, or pass a path to the CLI.

Do not treat this folder as a second scanner. Engines still write
`achilles.db`. Recipes only call `appsec_scan` / `appsec_query` / `appsec_intel`
and then write a recap in the session.

## Shipped

| File | When to run it |
|------|----------------|
| [scan-recap.yaml](scan-recap.yaml) | Scan a workspace (fast by default), then recap open findings |
| [sca-hygiene-report.yaml](sca-hygiene-report.yaml) | SCA (known-vulnerable deps) plus pinning / lockfile hygiene |
| [security-review.yaml](security-review.yaml) | High-confidence review of a PR, branch, or git diff |

## Run

Desktop: **Recipes**, then Run. To automate, open the recipe and **Schedule**
(cron), or **Scheduler → Create Schedule** and pick it from **Library**.
The scheduler only fires recipes; it is not a scan queue.

CLI (name lookup after the app has materialized shipped recipes, or a path):

```bash
goose run --recipe scan-recap --params workspace=/path/to/repo
goose run --recipe recipes/security-review.yaml --params workspace=/path/to/repo --params pr=123
```

Schedule examples (server must be started with `--enable-scheduler`):

```bash
# Daily 02:00 local — fast scan + recap
goose schedule add --schedule-id nightly-scan --cron "0 0 2 * * *" \
  --recipe-source recipes/scan-recap.yaml \
  --params workspace=/path/to/repo

# Monday 09:00 local — SCA + pinning
goose schedule add --schedule-id weekly-sca --cron "0 0 9 * * 1" \
  --recipe-source recipes/sca-hygiene-report.yaml \
  --params workspace=/path/to/repo
```

`workspace` on the schedule is required so the job does not scan the
server's current directory by accident.

## vs skills

| | Skills (`skills/`) | Recipes (this folder) |
|---|---|---|
| Shape | `SKILL.md` playbook, loaded when the topic matches | YAML session: extensions + params + prompt |
| Best for | How to think about a class of issues | Same job, same tools, on demand or on a timer |
| Example | `security-review` while already chatting | Launch `security-review.yaml` with a PR number |
