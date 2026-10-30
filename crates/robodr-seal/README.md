# robodr-seal

Captured-unit software protection of RoboDR's secure delivery
(`docs/SECURE-DELIVERY.md` §7, decisions §7.9, Sprint 13c): what keeps
delivered software, models and mission configuration unreadable on a unit
an adversary holds.

```
robodr-seal keygen depot|policy --out FILE
robodr-seal policy sign --key FILE --platform P --version N --pcr I=HEX... --out FILE
robodr-seal provision TPM [--owner-auth-file FILE]
robodr-seal enroll --seal-dir DIR --unit U --platform P --policy-authority FILE.pub TPM
robodr-seal enroll-fallback --seal-dir DIR --unit U --platform P --key FILE
robodr-seal policy install|commit --seal-dir DIR [--policy FILE] TPM
robodr-seal rewrap --depot-key FILE --rpk RPK_DIR --unit-record UNIT.json
robodr-seal volume format|open|format-tang|open-tang|close ...
robodr-seal erase --seal-dir DIR --trigger T [--device DEV] [TPM]
robodr-seal status --seal-dir DIR [TPM]
```

`man robodr-seal(8)`, `docs/OPERATIONS.md` section 12.

| Module | What |
|---|---|
| `chunk` | content key, HKDF subkeys, XChaCha20-Poly1305 chunks bound to their place, synthetic nonces, key commitment, keyed file digests |
| `wrap` | X25519 / P-256 ECDH key wraps bound to recipient and purpose |
| `policy` | the signed PCR policy, TPM policy digests computed offline (checked against swtpm) |
| `tpm` | `tpm2-tools` driver: provisioning, the TPM-resident UWK, unwrap in an encrypted policy session, policy floor, erase epoch |
| `luks` | LUKS2 runtime volume (`cryptsetup`), Clevis/Tang fallback |
| `unit` | the seal directory: enrol, unwrap, policy install / commit, volume key, erase |
| `rpk` | seal at release, re-wrap at the depot, open on the unit |

## Tests

`cargo test -p robodr-seal` runs the pure tests always. With
`ROBODR_SWTPM=1` (swtpm, tpm2-tools) the TPM tests run against a software
TPM per test; with `ROBODR_TANG=1` (tangd, clevis, cryptsetup) the
fallback test runs against a real Tang server; with `ROBODR_SEAL_DM=1`
(root, loop devices, device-mapper) the runtime volume is opened and
mounted for real. `tests/exit_criteria.rs` holds the four exit criteria
of §10, `tests/adversarial.rs` the attacks, `tests/cli.rs` the binary,
`tests/fuzz_smoke.rs` the `seal_*` fuzz harnesses.
