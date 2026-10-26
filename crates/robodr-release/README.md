# robodr-release

The connected-side release tool of RoboDR's secure delivery
(`docs/SECURE-DELIVERY.md` §4.1, Sprint 13a). Formats and every content
rule are in `robodr-pkg`; this crate reads and writes files and runs the
CLI.

```
robodr-release keygen       --out SECRET_KEY_FILE [--key-id ID]
robodr-release fingerprint  --key KEY_FILE
robodr-release build rpk    --spec SPEC.json --payload DIR --out-dir DIR
robodr-release build bundle --programme P --seq N [--prev-bundle DIR | --prev-hash HEX]
                            --rpk DIR... TRUST
                            [--parity M [--parity-group K] [--shard-size BYTES]] --out DIR
robodr-release sign         --key SECRET_KEY_FILE --target RPK_DIR|BUNDLE_DIR|DEPLOYMENT.json TRUST
robodr-release sign         --key SECRET_KEY_FILE --target TRUST.json [TRUST]
robodr-release verify rpk|bundle|trust|deployment ... TRUST
robodr-release import       --from MEDIA_BUNDLE_DIR --to NEW_DIR TRUST CHAIN
robodr-release repair       --dir BUNDLE_DIR TRUST

TRUST: --trust TRUST.json --root FPR... --site SITE (--trust-anchor ANCHOR.json | --no-trust-anchor)
CHAIN: --genesis | --after SEQ:HASH | --state FILE [--genesis] [--commit]
```

`robodr-release --help` has the full usage. Exit codes: 0 ok, 1 refused
or error (`refused (<code>): <detail>` on stderr), 2 usage.

## Release flow

1. `keygen` on the offline signing station, once per key holder
   (`robodr-blackbox` Ed25519 key files, secret 0600 plus `.pub`). The
   delivery roots write the site trust file (site, roles, programmes with
   their release keys and packages, unit rings, quorums, revocations,
   floors, `expires_at`) and each runs `sign --target trust.json` until
   the root quorum is reached. The root fingerprints and the site name are
   carried to the site out of band (`--root`, `--site`). Every station
   that verifies creates its trust anchor once:
   `verify trust --trust trust.json --root ... --site SITE
   --trust-anchor /var/lib/robodr/trust-anchor.json --init-anchor`.
2. `build rpk`: a spec (`robodr-rpk-spec/1`: every manifest member but the
   payload) and a payload directory become `rpk_<name>_<serial>_<arch>/`
   with `MANIFEST.json` and `chunks/`. Deterministic: the same inputs give
   the same bytes on any host. Symlinks, special files, empty
   directories, unsafe names and setuid / group- or other-writable modes
   are refused, never normalised.
3. `sign --target <rpk dir>` by two (the release quorum) holders of
   release keys of the programme that owns the package. `sign` re-checks
   the manifest, the exact file set, every chunk and content hash, the
   site policy and every signature already present before signing.
4. `build bundle`: copies the signed RPKs into a staging directory,
   verifies the copies (release quorum, site policy, every hash), lists
   every file in `bundle.json`, adds Reed-Solomon parity (`--parity M`:
   `M` parity files per group of `--parity-group K` files), publishes the
   directory atomically. Then `sign --target <bundle dir>` by two release
   key holders of its programme (`sign` verifies every RPK in it first).
5. The bundle directory, `trust.json` and `trust.json.sig` cross the gap.

## Importing from media: use only the verified copy

Never verify a bundle in place on removable media and then copy or
install it: the device can serve other bytes on the second read. Import
it instead:

```
robodr-release import --from /media/usb/bundle-0007 --to /srv/robodr/inbound/bundle-0007 \
    --trust /media/usb/trust.json --root FPR --root FPR --root FPR --site SITE \
    --trust-anchor /var/lib/robodr/trust-anchor.json --state chain-<programme>.json --commit
```

authenticates `bundle.json`, refuses any symlink, special or stray file
on the media, copies every listed file (reading at most its listed size)
into a staging directory next to `--to`, verifies the **copy** exactly
like `verify bundle`, and only then renames it to `--to`. Use only
`--to` afterwards (the depot imports from it); the media can be
discarded.

## Verifying

```
robodr-release verify bundle --dir BUNDLE --trust trust.json --root FPR --root FPR --root FPR \
    --site SITE --trust-anchor ANCHOR.json --state chain-<programme>.json [--genesis] --commit
```

checks, in order: the trust file against the pinned roots and site, the
root quorum and its expiry, as the site's trust anchor or a rotation of
it (an older file, another site's file, or one that drops a revocation or
lowers a floor is refused); `bundle.json` (strict parse, release quorum, programme accepted);
the chain against the state file (a gap, a replay, an equivocation or a
broken link is refused); that the tree holds exactly the listed files
(no symlink, no stray file or directory); every file's size and hash;
then each RPK (digest named by the bundle, release quorum of its
programme, site policy, file set, chunk and content hashes). Sizes are
compared before anything is hashed. `--commit` advances the trust anchor
(when the bundle was accepted under a rotation) and then writes the new
chain head, only after all of that passed. The state also records the
site and the trust file the head was accepted under. `--trust-anchor` is
the same file for every programme and every command; `--no-trust-anchor`
(no rollback protection: pins, site, quorum and expiry only) must be
given explicitly and is refused with `--state`.

`repair` rebuilds up to `M` missing or damaged files per parity group,
only after `bundle.json` is authenticated, checks each rebuilt file's
hash before renaming it into place and never writes through a symlinked
directory. Run `verify` afterwards.

## Limits

* Keys are files (0600) on the signing station, not HSM- or TPM-held.
* Only `public` RPKs are built; sealing is Sprint 13c.
* `--now` defaults to the system clock of the verifying host; a clock
  before 1970 is an error. Trust file expiry is judged on that clock.
* The anchor's two files are replaced signature first, then document; a
  crash in between leaves a pair that fails to load (refused, restore
  from the last accepted trust file), never an older anchor.
* `-h` / `--help` only as the whole command line; anywhere else it is a
  usage error (exit 2).
