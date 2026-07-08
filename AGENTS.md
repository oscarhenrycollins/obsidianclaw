# Agent Notes

Tips for the coding agent working on this repo.

## Git & GitHub

- The `gh` CLI is installed and ready to use. Use it to create, view, and merge PRs without leaving the terminal.
  ```bash
  gh pr create --title "..." --body "..."        # open a PR
  gh pr view                                      # review current PR
  gh pr merge                                     # merge when ready
  ```
- Prefer small, focused commits with clear messages. The `drop-tailscale` branch is an example of good commit hygiene.
- Don't commit generated artifacts (`main.js`) unless they changed meaningfully.
- Always run `npm run build` before committing to make sure the TypeScript compiles.

## Code Style

- Follow existing patterns: early returns, named sections (`// ─── Section Name ─`), and JSDoc for exported helpers.
- Obsidian plugin specifics:
  - Avoid `innerHTML` on dynamically created elements (ObsidianReviewBot compliance).
  - Use `createEl` / `createDiv` / `ownerDocument.createElementNS` for DOM construction.
  - Keep `main.ts` focused on plugin lifecycle and UI classes. Extract helpers into sibling modules (`svgs.ts`, `types.ts`, `lib.ts`, `at-mention.ts`).

## Testing

- Run `npm test` for the unit-test suite (`src/lib.test.ts`, `src/at-mention.test.ts`).
- Run `npm run build` before committing to make sure the TypeScript compiles.
- Manual sanity checklist before PR:
  1. `npm run build` passes
  2. `npm run lint` passes
  3. `npm run typecheck` passes
  4. `npm test` passes
  5. `npm run format:check` passes
  6. No `console.error` from obvious typos
  7. Imported symbols actually exist in their source files
