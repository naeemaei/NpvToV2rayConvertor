# Hardened build changes

- Fixed WebSocket Host loss when Host is stored under `wsSettings.headers.Host`.
- Added recursive discovery of embedded Xray/V2Ray JSON fields.
- Added fallback for structured profiles with empty `v2rayJson`.
- Added transport normalization and more transport/security fields.
- Added protocol inference only when explicit or verified; unknown types are not guessed.
- Added unsupported-profile cards and diagnostics export.
- Added direct embedded share-link recovery.
- Added de-duplication across multiple candidate representations.

Validated against the three NPVT samples supplied in this conversation:
- 4/4 import links
- 34/34 import links
- 17/17 import links
