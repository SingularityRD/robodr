# Finding schemas and third-party validation

What a SIEM or SOC team needs to check that the findings it receives are
well formed, with tools that are not RoboDR's own.

| File | What it is |
|---|---|
| `../../docs/contracts/robodr-finding.schema.json` | The `robodr.findings` contract (envelope + OCSF member), JSON Schema 2020-12 |
| `ocsf-1.1.0-detection_finding.schema.json` | OCSF 1.1.0 Detection Finding (class 2004), strict, JSON Schema 2020-12, generated |
| `build_ocsf_schema.py` | Fetches the official OCSF source and generates the file above |
| `validate_findings.py` | Validates JSON / NDJSON findings against both schemas with `jsonschema` |

## Validate what you receive

```sh
pip install 'jsonschema>=4.18'
python3 integrations/schemas/validate_findings.py findings.ndjson
# or with check-jsonschema, contract schema only:
check-jsonschema --schemafile docs/contracts/robodr-finding.schema.json finding.json
```

`validate_findings.py` exits 0 when every message passes both schemas, 1
otherwise, and prints `file:line: [schema] /json/pointer: message` per error
(`--json` for a machine-readable report). Schema validation is not
authentication: verify the `robodr-finding-sig` header first
(`docs/contracts/robodr.findings.md` §2).

## How RoboDR uses it

`crates/robodr-ocsf/tests/external_validator.rs` builds one finding for every
rule id in the catalog (at two severities), the full example finding and the
golden example, and runs `validate_findings.py` on them. It also feeds eleven
tampered findings and requires both this validator and the in-crate validator
to reject them (undeclared keys are rejected by the schemas only: the crate
tolerates unknown keys for forward compatibility). With
`ROBODR_REQUIRE_EXTERNAL_VALIDATOR=1` a missing `python3`/`jsonschema` fails
the test instead of skipping it. The `pure` CI job sets it, after installing
the hash-pinned packages of `scripts/ci-python-requirements.txt`.

## Result against OCSF 1.1.0

Every produced finding passes the contract schema. Against OCSF 1.1.0 there
is exactly one deviation, pinned in the test (`KNOWN_OCSF_DEVIATIONS`):

* `ocsf.device.model` is not an attribute of the OCSF 1.1.0 `device` object.
  The same value is in `ocsf.unmapped.robodr.robot.model`. A strict OCSF
  consumer rejects or drops it; moving it is a contract change
  (docs/SALES-READINESS.md WP2).

This settles the crate README's OCSF-UNCERTAIN list (`crates/robodr-ocsf/README.md`):

| Question | OCSF 1.1.0 answer |
|---|---|
| `status_id` enum for Detection Finding | 0 Unknown, 1 New, 2 In Progress, 3 Suppressed, 4 Resolved, 99 Other: as assumed |
| `device.model` | **not defined** (see above) |
| `evidences[]` shape | `evidences` object; `data` (JSON) is defined; at least one of `actor, api, connection_info, data, dst_endpoint, file, process, query, src_endpoint` must be set (we set `data`) |
| `resources[].labels` | defined (`resource_details.labels`, string array) |
| `finding_info.attacks[]` with ATT&CK for ICS ids | the shape (`technique.{uid,name}`) is valid; OCSF does not constrain the id to Enterprise ATT&CK |
| `device` and `resources` on the class | `resources` is a class attribute; `device` comes from the `host` profile and is accepted. We do not list `host` in `metadata.profiles`; OCSF does not require it |

## Regenerating the OCSF schema

```sh
python3 -m venv /tmp/ocsf && /tmp/ocsf/bin/pip install ocsf-lib==0.10.4
/tmp/ocsf/bin/python integrations/schemas/build_ocsf_schema.py fetch /tmp/ocsf-work
python3 integrations/schemas/build_ocsf_schema.py convert /tmp/ocsf-work/compiled.json \
    integrations/schemas/ocsf-1.1.0-detection_finding.schema.json
sha256sum integrations/schemas/ocsf-1.1.0-detection_finding.schema.json
```

`fetch` downloads the 83 files of `ocsf/ocsf-schema` tag `v1.1.0` that the
Detection Finding class reaches and compiles them with `ocsf-lib` (the OCSF
project's reference compiler). The compiler's list order varies between runs;
the converter's output does not. Checked-in output sha256:
`f215ed2037d1d6e63c4b6bfb11325821a5026454819743ca51306d1e903b852b`
(ocsf-lib 0.10.4, OCSF v1.1.0, generated 2026-10-31).

What is ours and what is official: the attribute names, types, enums,
requirements, regexes, lengths and constraints come unmodified from the OCSF
compiler; the mapping of those to JSON Schema keywords is
`build_ocsf_schema.py` (documented at its top). The OCSF schema server's own
`/api/validate` endpoint was not reachable from the build environment, so the
two have not been compared; doing so is the remaining step to call this the
OCSF reference result.

## Licence

The OCSF schema is © the OCSF project, Apache License 2.0
(`LICENSES/LICENSE-APACHE-2.0`). `ocsf-1.1.0-detection_finding.schema.json`
is a derived work of OCSF schema v1.1.0, converted to JSON Schema by
`build_ocsf_schema.py`.
