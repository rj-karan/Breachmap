# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use GitHub's private
vulnerability reporting on this repository
(Security tab, "Report a vulnerability") or email rjkaran418@gmail.com. You
will get an acknowledgement within 72 hours.

## What is in scope

- The policy evaluator producing a wrong allow or deny (an accuracy bug is a
  security bug here: a missed path is a false negative for a real user).
- Any way for repository content, workflow text or cloud tags to influence
  scoring, edge creation or fix acceptance (prompt injection into the patch
  drafter is in scope).
- Any code path that would write to a cloud account or cluster. Breachmap is
  read-only by design.
- Lab replay reaching a resource not tagged `breachmap-lab=true`.

## Supported versions

Only the `main` branch is supported while the project is pre-1.0.

## Design

See the "Securing Breachmap itself" section of `docs/design.md` for the threat
model and defenses.
