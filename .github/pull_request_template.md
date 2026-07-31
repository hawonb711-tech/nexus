## What & why

<!-- What does this change and why? Link any issue. -->

## How I verified

<!-- Required. For detection/ranking changes, include before/after numbers from a
     reproducible command (npx tsx scripts/*benchmark.ts, nexus eval-search,
     nexus dense-eval, or a new test). -->

- [ ] `npm run build` clean
- [ ] `npm test` green
- [ ] Added/updated tests for the change
- [ ] Stays local-first with no model API in core paths; heavy capabilities use optional peers and explicit collectors enforce the trust boundary

## Notes

<!-- Anything reviewers should know. Negative results welcome. -->
