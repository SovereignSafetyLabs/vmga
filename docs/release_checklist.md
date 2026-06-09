# VMGA Release Checklist

Before making VMGA public:

- Verify the MIT License is present and reflected in package metadata.
- Run the VMGA test suite.
- Run secrets scanning.
- Run SAST or document the static-analysis substitute.
- Review dependency and license posture.
- Verify docs do not claim prompt-injection prevention, DLP, host security,
  compliance certification, or hard isolation without deployment preconditions.
- For OpenClaw examples, capture `openclaw security audit --deep` and
  `openclaw secrets audit --check` output.
- If OpenClaw SecretRefs are migrated, retain the redacted `openclaw secrets
  apply` plan and `openclaw secrets reload` result.
- If trusted-proxy auth is documented or enabled, verify the proxy authenticates
  users, is the only gateway path, strips or overwrites identity headers, and
  has an explicit `allowUsers` operator list for shared audiences.
- Verify example policies use placeholder domains and strict defaults.
- Verify `SECURITY.md` has a monitored reporting path.
- Record DSOVS self-assessment evidence in `docs/dsovs_readiness.md`.
