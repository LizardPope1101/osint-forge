# Wiki Drafts

This directory stages proposed GitHub wiki changes without publishing them.
Files use the exact names expected by the wiki repository.

## Promotion workflow

1. Update drafts alongside the repository feature that changes behavior.
2. Review drafts through the normal repository pull-request and CI process.
3. Keep release-specific wording marked as unreleased until live validation
   and every sequential release gate are complete.
4. Immediately before promotion, compare each draft against its published wiki
   counterpart and incorporate any intervening wiki edits.
5. Publish the reviewed files to the wiki in one focused wiki commit.
6. Verify page rendering, links, sidebar navigation, stable-release wording,
   and the wiki commit history.
7. Remove or refresh promoted drafts in a follow-up repository change so stale
   drafts are not mistaken for current proposals.

The published wiki and [[Release Process]] remain authoritative. Files here are
ordinary repository documentation and are not visible as wiki pages.
