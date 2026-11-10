## Summary

<!-- One paragraph: what changed and why. -->

Closes #

## Changes

-

## Verification

<!-- Paste the real commands and results. -->

```
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest
```

## Checklist

- [ ] Branch is `type/N-slug` and every commit has `Refs #N`
- [ ] Tests added or updated; new IAM rules cite the AWS doc sentence
- [ ] Docs updated (`docs/`, README Status, `docs/learning-path.md` if a new concept)
- [ ] No cloud write permissions introduced
- [ ] No AI attribution trailers in commits or this PR
