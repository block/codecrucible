# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd onboard` to get started.

## Beads stays local

Keep the Beads database, Dolt storage, exports, and backups out of the Git
repository and its history. `.beads*` is ignored and must remain ignored.
Use `bd --sandbox` to disable automatic synchronization. Never run `bd sync`,
`bd dolt push`, or Git-backed Beads backups, and never add a Beads/Dolt remote
pointing at the code repository. Do not force-add ignored Beads files or push
`refs/dolt/*`. The Git workflow below applies only to source and documentation.

## Quick Reference

```bash
bd --sandbox ready              # Find available work
bd --sandbox show <id>          # View issue details
bd --sandbox update <id> --status in_progress  # Claim work
bd --sandbox close <id>         # Complete work locally
```

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
