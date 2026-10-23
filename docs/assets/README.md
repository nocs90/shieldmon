# Brand assets

- `logo-mark.svg`: the mark alone (square; avatars, favicons, badges).
- `logo.svg`: mark plus wordmark. The wordmark switches to a light ink under
  `prefers-color-scheme: dark`.

The mark is a shield split red/blue (exposure and protection) around an elephant: an
elephant never forgets, and ShieldMon keeps every finding's audit trail. The trunk curls
into a check mark because findings close only on scan evidence.

| Ink  | Hex       | Use                           |
|------|-----------|-------------------------------|
| Red  | `#E63946` | left half of the shield       |
| Blue | `#2F80ED` | right half, "MON"             |
| Navy | `#0F1B2D` | "SHIELD" on light backgrounds |

The terminal banner shown by `shieldmon --help` is a pixel version of the same mark,
kept in `internal/cli/banner.go`. Update both when the mark changes.
