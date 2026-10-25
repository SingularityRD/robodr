# RoboDR + AutoSecOps — GA Yol Haritası

> Durum: **plan** (2026-10-25). Bu belge `docs/SPRINTS.md` ve `docs/ROADMAP.md`'nin
> ticari ürün (GA) hedefli halefidir. Eski AutoSecOps entegrasyonu (`autosecops2`,
> `core/ingestion/kafka_consumer_service.py`, `core/integrations/robot_edr/`,
> `AUTONOMOUS_ELIGIBLE`, `robodr-integration` dalı) **iptal edilmiştir**; yerine
> [`SingularityRD/AutoSecOps1`](https://github.com/SingularityRD/AutoSecOps1)
> entegrasyonu gelir. Uygulama talimatı (ajan promptu): [`GA-AGENT-PROMPT.md`](GA-AGENT-PROMPT.md).

---

## 0. Yönetici özeti

| | RoboDR (bu repo) | AutoSecOps1 |
|---|---|---|
| Ne | Robot EDR: ROS 2/DDS grafiği, Motion Firewall, Cyber-Jidoka yanıt planlayıcı, imzalı kara kutu, diyot ihracı | Agentic SOAR/SOC: workflow (Temporal), case yönetimi, agent preset'leri, 100+ entegrasyon, MCP |
| Dil / yığın | Rust (19 crate, ~115k satır), Pulsar (eBPF) | Python FastAPI + Next.js + Temporal + Postgres + MinIO + Redis (Tracecat çatalı) |
| Olgunluk | `0.1.0-alpha.1`, hiç release/tag yok, **gerçek robotta hiç çalışmadı** | Çalışan platform, `1.0.0` imajları; robot/OCSF/Kafka desteği **yok** |
| Test (2026-10-25, bu oturum) | 16 saf crate: **1997 geçti / 0 kaldı / 14 ignored** (`cargo test --locked`) | Çalıştırılmadı (docker yığını gerekir) — S0'da CI'da koşturulacak |
| GA'yı en çok engelleyen | Yanıt hiçbir şey yürütmüyor; TLS yok; saha doğrulaması yok; konsol/filo yönetimi yok; lisans/aktivasyon yok | Robot ingest yok; kanıt paketleri ek allowlist'ine takılıyor; iki-kişi onayı yok; geliştirme lisans anahtarı gömülü |

**GA tanımı (özet):** Bir müşteri, AutoSecOps1'i self-host kurup RoboDR ajanını
desteklenen bir robot platformuna (ROS 2 Humble/Jazzy, Fast DDS + Cyclone, amd64 +
arm64) kurduğunda; robot bulguları **imzalı, tekilleştirilmiş case** olarak AutoSecOps'a
düşer, kanıt paketi doğrulanabilir şekilde iliştirilir, analist/agent onaylı
containment aksiyonları robota **mTLS + Ed25519** ile gider ve robot güvenlik
durumuna göre **yürütür veya gerekçeli reddeder**; tüm bu zincir 72 saatlik soak,
red-team ve gerçek donanım üzerinde kanıtlanmış, sürümlenmiş, imzalı, belgelenmiş ve
lisanslı olarak teslim edilir.

Takvim: **S0 + 14 sprint × 2 hafta ≈ 30 hafta** (paralel ekiplerle). Faz kapıları:
S3 sonu (MVP entegrasyon), S7 sonu (Private Beta), S11 sonu (Public Beta / RC), S14 (GA).

---

## 1. Bulgular — mevcut durumun dürüst envanteri

### 1.1 RoboDR

**Güçlü yanlar:** saf crate'ler temiz (clippy `-D warnings`, non-test kodda neredeyse
sıfır `unwrap`), 11 fuzz hedefi, gerçek ROS 2 Jazzy yakalamalarıyla uçtan uca test,
Ed25519 (ed25519-dalek) imzalı kara kutu, imzalı profiller + anti-rollback, diyot
paketleme (Reed-Solomon), reproducible build + SBOM + minisign release pipeline'ı
(yazılmış ama hiç koşmamış).

**Ürün açıkları (satışı engelleyen):**

| # | Açık | Kanıt |
|---|---|---|
| R1 | Yanıt **hiçbir şey yürütmüyor**: responder sadece planlıyor, agentd `NoopExecutor`, Motion Firewall recording-only ve ROS 2 gateway'i yok, kontrol düzlemi yalnızca `recorded_not_executed` döndürüyor | `crates/robodr-responder/README.md:160-191`, `crates/robodr-firewall/README.md:194-255`, `docs/contracts/robot-edr.control-plane.md` §10 |
| R2 | **TLS yok**: kontrol düzlemi, Kafka istemcisi (SASL de yok), anchor receiver düz metin | `crates/robodr-export/README.md:264-303`, `SECURITY.md:118-121` |
| R3 | Saha doğrulaması yok: gerçek robot, RTI Connext, SROS2/DDS-Security, donanım TPM, 72 saat soak, FP oranı ölçümü yok; Zenoh kör; Pulsar kuralları gerçek motora hiç yüklenmedi; pulsard sadece WSL2'de | `README.md` Status, `docs/SPRINTS.md` S1–S4 |
| R4 | Konsol / filo yönetimi / çok kiracılık yok (`robodr-fleet` yok); güncellemeler robot başına `install-bundle.sh`, dpkg ile hiç denenmedi | `docs/ROADMAP.md:110-132`, `packaging/README.md:205-208` |
| R5 | Anahtarlar düz 0600 JSON dosya; dağıtım/rotasyon/iptal elle | `crates/robodr-blackbox/README.md:670-704` |
| R6 | CI GitHub'da **hiç koşmadı** (org billing); release workflow'u hiç tetiklenmedi; `MINISIGN_SECRET_KEY` yok; `robodr-anchor-receiver` `.deb` zorunlu listesinde değil | `docs/BUILD.md:536-557`, `.github/workflows/release.yml` |
| R7 | Ticari model yok: her şey Apache-2.0 (karar: tescilliye geçecek, D9 / S1); lisans anahtarı/aktivasyon yok; ihracat kontrol (Wassenaar 5A2) sınıflandırması yok; Pulsar GPL-2.0 eBPF hukuki incelemesi yok | `Cargo.toml:34`, `docs/SECURE-DELIVERY.md` §11 |
| R8 | Elle yazılmış kritik bileşenler: SHA-256/HMAC, Reed-Solomon, Kafka wire istemcisi (API v≤8), HTTP/1.1 sunucusu, JSON-Schema eşleyici | `crates/robodr-blackbox/src/crypto.rs`, `crates/robodr-export/src/kafka/`, `crates/robodr-agentd/src/control/` |
| R9 | Tutarsızlıklar: iki aksiyon listesi çelişiyor (`responder::autosecops` → `record_evidence` var/`rollback_config` yok; kontrol düzlemi tersi); `panic = "abort"` → her panik daemon'ı öldürür; çok sayıda bayat doküman | `crates/robodr-responder/src/autosecops.rs:74-110` vs `crates/robodr-agentd/src/control/api.rs:40-63` |
| R10 | Müşteri dokümanı yok: kurulum/quick-start, destek matrisi, EULA, SLA; `robodr-maintainers@invalid`, `singularityrd.example` yer tutucuları; `robodr-threat-forward` README/man sayfası yok | `packaging/build-deb.sh:65`, `docs/contracts/robot-edr-finding.schema.json` |

### 1.2 AutoSecOps1

**Hazır olanlar:** workflow webhook'ları (IP allowlist, per-webhook API key, NDJSON),
case API (severity enum'u **OCSF ile birebir hizalı**, custom field'lar, tag'ler,
attachment'lar content-addressed SHA-256), Redis Streams tüketici kalıbı
(`tracecat/cases/triggers/`), registry (UDF + YAML template; EDR örnekleri:
`templates/tools/sentinel_one`, `microsoft_defender_endpoint`, `crowdstrike`),
agent preset'leri + `requires_approval` ile HITL onay, entitlements + **Ed25519
lisans token'ı** (`tracecat/licensing/`), Fargate Terraform, air-gapped doküman.

**Açıklar:**

| # | Açık | Kanıt |
|---|---|---|
| A1 | ✅ **Kapandı (2026-10-25):** menşe/lisans durumu için hukuki onay alındı (ürün sahibinin beyanı). Üçüncü taraf bildirimleri imajlarla birlikte gönderiliyor (`THIRD_PARTY_NOTICES.md`, `frontend/THIRD_PARTY_NOTICES.md`, `scripts/third_party_notices.py`, AutoSecOps1 PR #6). Kalan iş: onay belgesinin referansını iç kayıtta tutmak; bağımlılık eklendikçe `just gen-notices` (CI testi zaten var) | `LICENSE`, `THIRD_PARTY_NOTICES.md`, `docs/self-hosting/license.mdx` |
| A2 | Robot/OCSF/Kafka ingest yolu **yok**; alert/finding modeli yok; case seviyesinde `external_id` tekilleştirme yok | `tracecat/db/models.py` |
| A3 | Kanıt paketleri bloklu: ek allowlist'i sadece ofis/görsel uzantıları, 20 MB/ek, 10 ek/case | `tracecat/config.py:1386-1412` |
| A4 | Onay modeli zayıf: yalnızca `agent:update` scope'u; onaylayıcı rolü / **iki-kişi kuralı yok**; YAML template'lerde `requires_approval` yok | `packages/tracecat-ee/tracecat_ee/agent/approvals/router.py` |
| A5 | Lisans altyapısında **geliştirme açık anahtarı** gömülü; değiştirilmeli | `tracecat/licensing/keys.py` |
| A6 | Rebrand artıkları: `TracecatHQ/*` git URL'leri CI'da, `docs.tracecat.com` alembic hata mesajında, Splunk HEC default `host: tracecat.com`, `x-tracecat-*` header'ları, Fargate `name_prefix="Tracecat"`, Helm repo'su upstream'e işaret ediyor | `.github/workflows/run-integration-tests.yml:128`, `test-python.yml:60`, `alembic/versions/9680c861644a_*.py:38` |
| A7 | Güvensiz `.env.example` varsayılanları: `postgres/postgres`, `MINIO_ROOT_PASSWORD=password`, `APP_ENV=development`, `DB_SSLMODE=disable`, `AUTH_ALLOWED_DOMAINS` boş, `temporal ui:latest` | `.env.example` |
| A8 | Air-gap: MCP katalog ikonları Google favicon URL'lerinden çekiliyor; Kubernetes/Helm repo'da yok | `tracecat/integrations/catalog/mcp_catalog.json` |
| A9 | Servis hesapları (doğrudan REST) `SERVICE_ACCOUNTS` entitlement'ına bağlı; case add-on'ları, agent add-on'ları, RBAC add-on'ları lisans gerektiriyor → RoboDR SKU'sunun hangi entitlement'ları içerdiği tanımlanmalı | `tracecat/tiers/` |

### 1.3 İptal edilen eski entegrasyon — RoboDR'daki izler

Eski AutoSecOps varsayımları şuralarda gömülü (S1'de temizlenecek):

- `crates/robodr-ocsf/` — `model.rs:30-55,224` (`KAFKA_TOPIC`, `DATA_SOURCE="robot_edr"`, "AutoSecOps ingestion envelope"), `validate.rs:382`, `builder.rs:28,44`, `kafka.rs:1,50`, `taint.rs:5,42,91,100`, `lib.rs`, `Cargo.toml:11`, README.
- `crates/robodr-responder/src/autosecops.rs` (tüm modül, `lib.rs:44,53` re-export, `tests.rs:6,1658-1702`) — `robotics` kategorisi, `AUTONOMOUS_ELIGIBLE`, `robot_*` sınıf adları.
- `crates/robodr-agentd/src/control/{mod.rs,api.rs}` — "AutoSecOps v1-draft" şekli, `soc:autosecops`, `/etc/robodr/soc/autosecops.pub`; `spool.rs:346`, `config.rs:286` topic gömülü.
- `crates/robodr-export/src/publish.rs:59,135,477` (başka topic reddediliyor), `crates/robodr-diode/src/manifest.rs:72,123,223`, `crates/robodr-agent/src/{lib,config,replay,outcome}.rs`, `crates/robodr-events/src/lib.rs:257`.
- Testler/fixtures: `crates/robodr-agentd/tests/{control_plane,example_configs}.rs`, `crates/robodr-ocsf/tests/*`, `fuzz/corpus/ocsf_parse_and_validate/*`, `scripts/kafka-it.sh`.
- Dokümanlar: `docs/contracts/robot-edr.findings.md` (§1, §9 checklist), `robot-edr.control-plane.md` (§9 v1-draft), `robot-edr-finding.schema.json`, `docs/SPRINTS.md`, `docs/ROADMAP.md`, `docs/OPERATIONS.md:906-923`, `CHANGELOG.md:18,39`, `README.md`, `rules/README.md:37`, crate README'leri.
- Repo dışı tasarım dokümanına atıflar (`2-tasarim/tasarim-dokumani.md`): ocsf, responder, firewall, agentd `health.rs`, correlate.

> Not: OCSF 2004 Detection Finding gövdesi `ocsf` alanında **bütün** olarak duruyor;
> yeni sözleşme bu gövdeyi korur, yalnızca zarfı (envelope) satıcıdan bağımsızlaştırır.

---

## 2. Hedef mimari

```
 ROBOT (amd64/arm64, Debian/Ubuntu)                         SOC (AutoSecOps1, self-host)
 ┌──────────────────────────────────────┐                  ┌───────────────────────────────────────────┐
 │ robodr-pulsard (eBPF host)           │                  │ Caddy (TLS)                                │
 │   └ threat-forward ──► robodr-agentd │                  │  ├ /api/robot-edr/v2/ingest  (Ed25519 imzalı│
 │ capture/RTPS/CDR ──► agentd          │  HTTPS (mTLS)    │  │    batch, robot anahtar kaydı, dedup)   │
 │   decision chain ─► black box        │ ───────────────► │  ├ robot_edr modülü: Robot/Site/Key/       │
 │   findings spool ─► robodr-uplink ───┼──(connected)──── │  │   Finding tabloları → Case upsert        │
 │                    └► diode-pack ────┼──(air-gap)─► diode-unpack ─► robodr-uplink (SOC tarafı) │
 │ control plane v2 (mTLS, kalıcı durum)│ ◄─────────────── │  ├ registry: tools.robodr.* (UDF,          │
 │   └ executor: adapters (nftables,    │  imzalı istek    │  │   requires_approval, iki-kişi kuralı)   │
 │     DDS quarantine, firewall gateway,│                  │  ├ Robot SOC agent preset + skill'ler       │
 │     platform safe-pause adapters)    │                  │  ├ Workflow şablonları (triage, contain)    │
 │ evidence API (bundle export)         │ ◄── evidence ─── │  ├ UI: Fleet, Robot detay, Bulgular, Kanıt  │
 └──────────────────────────────────────┘                  │  └ Lisans: ROBOT_EDR entitlement + robot   │
                                                           │    sayısı kotası                            │
  Opsiyonel: robodr-kafka-publish (TLS/SASL) → müşteri SIEM'i (genel OCSF ihracı)                       │
```

### 2.1 Temel mimari kararlar (önerilen; S0'da onaylanacak)

| Karar | Öneri | Gerekçe |
|---|---|---|
| D1 Bulgu taşıma | **Birincil: AutoSecOps1'e native HTTPS ingest API** (`POST /robot-edr/v2/ingest`, imzalı NDJSON batch). Kafka → **opsiyonel genel SIEM ihracı** | AutoSecOps1'de Kafka yok; webhook NDJSON satır başına workflow başlatıyor (yavaş, dedup yok). Native modül dedup, imza doğrulama, robot kaydı ve case upsert'i tek yerde yapar |
| D2 MVP köprüsü | S2–S3'te **webhook + workflow + `core.transform.deduplicate`** ile hızlı demo; S4'ten itibaren native modül | Erken uçtan uca demo, native modül paralel olgunlaşır |
| D3 Sözleşme | `robodr.findings/2.0`: satıcıdan bağımsız zarf (`data_source="robodr"`), OCSF 1.3 Detection Finding (class 2004) gövdesi aynen, provenance/taint işaretleri korunur; 1.x **parse-only** bir sürüm desteklenir | Eski AutoSecOps alan adları kalkar; başka SIEM'ler de tüketebilir |
| D4 Kontrol düzlemi | `robodr-control-plane/v2`: **mTLS (rustls)** + Ed25519 imzalı istek gövdesi, kalıcı istek durumu (kara kutu + sqlite/dosya journal), `executed`/`refused`/`reverted` gerçek durumlar | v1 düz HTTP, bellek-içi, yürütmüyor |
| D5 Aksiyon kataloğu | Tek kaynak: `robodr-responder::actions` (satıcıdan bağımsız). GA'da **yürütülen**: `restrict_motion` (firewall gateway), `quarantine_node` (DDS participant ingress/egress drop, nftables), `isolate_network` (nftables, yönetim kanalı hariç), `record_evidence`. **Platform adaptörüyle yürütülen**: `safe_pause` (Nav2 / ros2_control / PX4 adaptörleri, OEM onaylı politika ile). **GA'da yalnız plan (yürütülmez)**: `request_safe_state`, `rollback_config` | Güvenlik sistemi asla aşılmaz; geri alınamaz aksiyonlar GA sonrası |
| D6 Onay | Robot aksiyonları **asla otonom değil**; `requires_approval=True` UDF'ler; `safe_pause`/`rollback_config` için **iki-kişi kuralı** (AutoSecOps1'e eklenecek) | Fiziksel güvenlik |
| D7 HTTP/Kafka kodu | Elle yazılmış HTTP sunucusu → `rustls` + minimal, fuzz'lanmış HTTP katmanı (veya `hyper` değerlendirmesi, MSRV/air-gap uyumlu); kendi SHA-256 → `sha2`; Kafka istemcisi TLS/SASL ekle **veya** opsiyonel ihracı `rdkafka`'ya taşı (S0'da karar) | Satılan üründe denetlenmiş kütüphaneler |
| D8 Lisanslama | AutoSecOps1 lisans token'ına `robot_edr` entitlement + `max_robots` claim; ajan tarafında lisans kontrolü **yok** (robot asla lisans yüzünden körleşmez), sayım SOC'ta | Güvenlik ürünü lisans bitince sessizce kapanmamalı |
| D9 RoboDR lisansı | ✅ **Karar (2026-10-25): RoboDR Apache-2.0 olmayacak; tamamen tescilli** (AutoSecOps1 ile aynı "SingularityRD Proprietary License" modeli). İstisna: Pulsar'dan gelen eBPF prob kaynakları GPL-2.0 kalır (kaynak teklifiyle dağıtılır); vendored Pulsar userspace kodu kendi Apache-2.0 lisansını ve NOTICE'ını korur | Ticari model, ihracat kontrol |

---

## 3. Sprint planı

Ekipler: **R** RoboDR (Rust), **A** AutoSecOps backend (Python), **F** Frontend
(Next.js), **Q** QA / saha laboratuvarı, **D** DevOps / release, **L** Hukuk /
ürün / ticari. Her sprint 2 hafta. Her maddenin kabul kriteri (AC) vardır;
sprint, AC'leri karşılanmadan kapanmaz.

### Sprint 0 — Temel, hukuk ve kararlar (1 hafta, bloklayıcı)

- ✅ **L (tamamlandı, 2026-10-25):** AutoSecOps1 lisans/menşe durumu, Pulsar GPL-2.0
  eBPF dağıtımı ve ihracat kontrol sınıflandırması için hukuki onaylar alındı.
  Kalan: kararları ADR olarak kaydet (`docs/adr/0001-legal-clearance.md`: kapsam,
  tarih, belge referansı — belgenin kendisi değil), ihracat sınıflandırmasının
  getirdiği teslim koşullarını (ör. ülke kısıtları, beyanlar) S13 ticari pakete aktar.
- **L/ürün:** GA destek matrisi kararı (ROS 2 Humble+Jazzy; Fast DDS 2.14+, Cyclone 0.10+;
  Ubuntu 22.04/24.04, Debian 12; amd64+arm64; Zenoh = "algılanır, decode edilmez").
  İlk tasarım-ortağı platformlar: **Unitree Go2 EDU** (dört ayaklı) + **Unitree G1 EDU**
  (insansı) — bkz. §3a; ayrıca bir Nav2 AMR (genel ROS 2 referansı). Destek matrisine
  Unitree'nin ROS 2 Foxy/Ubuntu 20.04 + Humble/22.04 eşleşmesi ve robot üstü Jetson
  (L4T) çekirdeği eklenir; Foxy EOL olduğu için yalnız ağ-pasif (agentless) mod.
- **D:** GitHub Actions billing'i aç; RoboDR `ci.yml`'nin ilk gerçek koşusu yeşil;
  AutoSecOps1 CI'sının (python, frontend, integration, migrations) yeşil koşusu.
  **AC:** iki repo `main`'de yeşil CI rozeti.
- **Tümü:** §2.1 kararlarını (D1–D9) ADR olarak `docs/adr/` altında onayla.
- **D:** Ortak lab: AutoSecOps1 docker-compose staging + ROS 2 Gazebo robot + gerçek
  bir AMR; `just cluster` ile tekrarlanabilir kurulum.

### Sprint 1 — Eski entegrasyonu sök, sözleşme v2, tescilli lisansa geçiş

- **L/R:** Tescilli lisansa geçiş (D9): kök `LICENSE` → SingularityRD Proprietary
  License (hukukun onayladığı metin; AutoSecOps1'deki metin şablon), workspace
  `license = "LicenseRef-Proprietary"` + her crate `publish = false`; `deny.toml`
  ([licenses] `private = { ignore = true }`, kendi crate'lerimizi muaf tut, üçüncü taraf
  allowlist'i aynen); `LICENSES/LICENSE-GPL-2.0` yalnız eBPF probları için kalır,
  `LICENSES/LICENSE-APACHE-2.0` vendored Pulsar için kalır; README/BUILD.md lisans
  bölümleri, `packaging/deb` copyright dosyası, `.deb` `Section`/lisans alanı; GitHub
  repo görünürlüğü **private** (açıksa, daha önce Apache-2.0 ile yayımlanmış
  commit'lerin lisansı geri alınamaz — hukuka not).
  **AC:** `cargo deny check licenses` yeşil; `rg -n "Apache-2.0" --glob '!vendor/**'
  --glob '!LICENSES/**'` yalnız üçüncü taraf/Pulsar bağlamında; paket metadata'sı
  tescilli.
- **R:** `robodr-responder::autosecops` → `robodr-responder::actions` (satıcıdan
  bağımsız katalog; iki listedeki çelişkiyi tek listeyle çöz: `restrict_motion,
  quarantine_node, isolate_network, record_evidence, safe_pause, request_safe_state,
  rollback_config`, her biri `reversible`, `approval: single|two_person`,
  `executable_in_ga`).
- **R:** `robodr-ocsf`: zarfı `robodr.findings/2.0`'a taşı (`data_source="robodr"`,
  AutoSecOps-özel alan isimleri yerine nötr `envelope`), `DATA_SOURCE`/`KAFKA_TOPIC`
  sabitlerini yapılandırılabilir yap; 1.x parse-only; JSON Schema `$id` gerçek alan adı
  (`schemas.singularityrd.com/robodr/findings/2.0.0`).
- **R:** `robodr-export`, `robodr-diode`, `robodr-agentd` spool: topic zorunluluğunu
  kaldır, sözleşme sürümünü taşı; `soc:autosecops` → `soc:<id>` genel isimlendirme.
- **R:** Tüm dokümanlarda §1.3 listesini temizle; `docs/contracts/robodr.findings.md`
  (v2) ve `robodr.control-plane.md` (v2 taslağı) yaz; eski sözleşmeleri
  `docs/contracts/legacy/` altına "superseded" notuyla taşı; repo dışı tasarım doküman
  atıflarını kaldır.
- **R:** Bayat dokümanları düzelt (README Pulsar durumu, SPRINTS başlık, BUILD.md:557,
  agentd "No exporter", Sprint 9 HMAC, pipeline/commission "no real captures");
  `robodr-threat-forward` için README + man sayfası.
- **AC:** `rg -i autosecops crates/ fuzz/ scripts/ config/` yalnızca entegrasyon
  dokümanında anlamlı geçişler; tüm testler + fuzz smoke yeşil; schema/örnek/validator
  v2'de tutarlı; `cargo deny` yeşil.

### Sprint 2 — AutoSecOps1 MVP köprüsü (webhook yolu) + robot kaydı tasarımı

- **A:** Registry'ye `templates/tools/robodr/` + `integrations/robodr.py`:
  `verify_finding_signature` (Ed25519, `pynacl`), `parse_finding_v2`,
  `finding_to_case` (severity birebir, custom field'lar: `robot_id`, `site`,
  `rule_id`, `mitre_ics`, `profile_mode`, `safety_state`, `external_id`, `taint`).
- **A:** "RoboDR finding ingest" workflow şablonu: webhook (API key + IP allowlist) →
  imza doğrula → `core.transform.deduplicate(external_id, persist)` → case create/update.
- **R:** `robodr-uplink` (yeni bin, robodr-export içinde): spool/diode çıktısını HTTPS
  ile webhook'a/ingest API'sine iten, crash-safe, at-least-once, backoff'lu istemci
  (rustls, CA pinleme).
- **A (tasarım):** native `robot_edr` modülü ADR'ı: tablolar `Robot`, `RobotSite`,
  `RobotKey` (finding/evidence/control anahtarları, rotasyon/iptal), `RobotFinding`
  (unique `(workspace_id, external_id)`), `RobotActionRequest`; RLS; alembic
  expand/contract kuralları (`alembic/AGENTS.md`).
- **AC:** Lab'daki rogue `/cmd_vel` senaryosu → 30 sn içinde AutoSecOps1'de doğru
  severity ve alanlarla **tek** case; aynı bulgu 3 kez gönderilince yine tek case.

### Sprint 3 — Native ingest modülü v1  → **Kapı 1: MVP entegrasyon demosu**

- **A:** `tracecat/robot_edr/` modülü: router `POST /robot-edr/v2/ingest` (NDJSON
  batch, robot anahtarıyla imza doğrulama, batch boyut limiti, rate limit), servis
  (dedup upsert, case oluştur/güncelle, `occurrence_count`), alembic migrasyonları,
  scope'lar (`robot:read|update|ingest`), robot başına ingest token'ı (service account
  gerektirmeyen dar kapsamlı kimlik).
- **A:** Taint/provenance: adversary alanları case'te delimited veri olarak saklanır;
  agent prompt'larına "untrusted" etiketiyle girer (prompt-injection korpusu
  `crates/robodr-ocsf/tests/findings.rs` `INJECTIONS` → AutoSecOps eval testi).
- **R:** `robodr-uplink` → ingest API; diyot SOC tarafı: `robodr-diode-unpack` →
  `robodr-uplink` zinciri.
- **Q:** Uçtan uca entegrasyon testi CI'da (docker compose: AutoSecOps1 + agentd pcap
  replay) — iki repoda da çalışan ortak "contract test" paketi.
- **Kapı 1 AC:** connected ve air-gapped (diyot dosya aktarımı) yollarında bulgular
  imza doğrulanmış case olarak görünür; 10k bulgu/saat ingest p95 < 2 sn; kayıp 0,
  çift case 0; imzasız/yanlış anahtarlı batch 401 + audit log.

### Sprint 4 — Kanıt (evidence) ve UI v1

- **R:** Evidence API: agentd kara kutu bundle export'u (kontrol düzlemi üzerinden,
  imzalı, boyut-sınırlı parçalar) + `robodr-blackbox verify` ile aynı doğrulama
  mantığının Python portu veya WASM/CLI çağrısı.
- **A:** Kanıt saklama: bundle'lar MinIO'da `robot-evidence/` bucket, case'e manifest
  (hash, imza, zincir başı) eki; ek allowlist'ine `.robodr-bundle`/`.json`/`.sig`,
  robot kanıtı için ayrı boyut kotası (A3).
- **F:** UI: **Fleet** sayfası (robot listesi, site, son görülme, profil modu,
  güvenlik durumu, sağlık), **Robot detay** (bulgular zaman çizelgesi, kanıt,
  anahtarlar), case içinde **Robot bulgu paneli** (OCSF görünümü, taint vurgulu),
  RoboDR ikonları (`frontend/src/components/icons.tsx`).
- **AC:** Analist case'ten kanıt paketini indirip `robodr-blackbox verify` ile
  doğrulayabilir; UI'daki "doğrulandı" rozeti sunucu doğrulamasıyla aynı; Playwright
  smoke testleri.

### Sprint 5 — Kontrol düzlemi v2 (güvenli kanal, kalıcı durum)

- **R:** `robodr-control-plane/v2`: rustls mTLS (SOC client cert + Ed25519 istek
  imzası), istek durum journal'ı (restart sonrası korunur), replay penceresi + nonce
  deposu, bind→chmod yarışını düzelt, HTTP katmanı fuzz hedefi, yanıt imzası zorunlu.
- **R:** Kafka opsiyonel ihracına TLS + SASL/SCRAM (veya D7 kararı), idempotent
  producer; anchor receiver'a TLS.
- **A:** `tools.robodr.*` UDF'leri: `request_action`, `get_action_status`,
  `revert_action`, `export_evidence` — hepsi `requires_approval=True`, SOC imza anahtarı
  secret'ta, robot adresi `Robot` kaydından; `TRACECAT__OUTBOUND_ALLOWED_PRIVATE_CIDRS`
  / SSRF korumasıyla robot ağları için açık allowlist.
- **AC:** Ağ üzerinden (aynı host değil) AutoSecOps1 → robot istek/yanıt döngüsü;
  sertifikasız/yanlış imzalı/replay istekleri reddedilir ve robot tarafında
  `robot.agent.control_plane_*` bulgusu üretilir; agentd restart sonrası durum sorgusu
  tutarlı.

### Sprint 6 — Onay iş akışı ve Robot SOC agent'ı

- **A:** Onay modeline **onaylayıcı rolü + iki-kişi kuralı** (istek sahibi ≠ onaylayıcı,
  `two_person` aksiyonlarda iki farklı onay), onay süresi dolumu, audit kaydı; YAML
  template'ler için `requires_approval` alanı (veya robot aksiyonlarını UDF'de tut).
- **A:** "Robot SOC" agent preset'i + seed mekanizması (kurulumda opsiyonel yükleme),
  library skill'leri: `robodr-triage`, `robodr-containment`, `robodr-forensics`
  (kanıt zinciri okuma); robot aksiyon araçları preset'te daima onaylı.
- **A:** Workflow şablonları: "Robot incident triage", "Robot containment (approval)",
  "Rogue DDS participant", "Motion envelope violation", "Evidence collection".
- **F:** Onay kutusunda robot aksiyon kartı: robotun anlık güvenlik durumu, aksiyonun
  geri alınabilirliği, TTL, iki-kişi göstergesi.
- **AC:** Agent hiçbir robot aksiyonunu onaysız gönderemez (negatif test); iki-kişi
  aksiyonu tek kişiyle tamamlanamaz; injection korpusu agent'ı aksiyona yönlendiremez
  (eval geçme oranı %100).

### Sprint 7 — Executor v1 (geri alınabilir aksiyonlar)  → **Kapı 2: Private Beta**

- **R:** `robodr-agent::executor` gerçek implementasyonu, adapter arayüzü (her
  aksiyon: `precheck(safety_state)`, `apply`, `verify`, `revert`, TTL ile otomatik
  revert): `isolate_network` (nftables, yönetim/uplink kanalı muaf), `quarantine_node`
  (DDS participant GUID/IP bazlı drop), `record_evidence` (kara kutu işaret + bundle).
- **R:** Executor'ın güvenlik değişmezleri: güvenlik sistemini asla aşmaz, safety
  state'i yeniden kontrol eder, başarısız revert → High bulgu; systemd capability
  setinin (CAP_NET_ADMIN) minimum ve sadece executor sürecinde olması (ayrı süreç).
- **Q:** 2 tasarım ortağı robotta (S0 seçimi) kurulum; ilk saha yakalamaları.
- **Kapı 2 AC:** private beta paketi (`.deb` amd64+arm64, AutoSecOps1 imajları,
  kurulum kılavuzu taslağı) 1–2 tasarım ortağına; geri alınabilir aksiyonlar gerçek
  robotta uygulanır/geri alınır; 24 saat kesintisiz çalışma.

### Sprint 8 — Motion Firewall gateway + safe-pause adaptörleri

- **R:** ROS 2 in-path gateway (`robodr-firewall-gw`): `/cmd_vel` ve
  `JointTrajectory` remap'li ara katman; recording → `enforce` modları; watchdog
  (gateway ölürse fail-safe davranışı OEM politikasına göre: "stop" veya "pass-through"
  — varsayılan dokümante); jitter/latency ölçüm koşum takımı ve CI kapısı (p99 eşiği).
- **R:** `safe_pause` adaptörleri: Nav2 (navigation cancel + zero twist), ros2_control
  (controller switch / hold), PX4 (hold mode) — her biri OEM onaylı politika bayrağı
  `oem_validated=true` olmadan yürütmez.
- **AC:** Gateway gecikme bütçesi (ör. p99 < 1 ms ek gecikme, 100 Hz) ölçülmüş ve
  raporlanmış; `restrict_motion` gerçek robotta hız limitini uygular ve TTL sonunda
  geri alır; safe_pause yalnızca politika izinliyken çalışır.

### Sprint 9 — Filo yaşam döngüsü: kayıt, anahtar, güncelleme

- **A/F:** Robot onboarding akışı: UI'da robot ekle → tek kullanımlık kayıt token'ı →
  `robodr-enroll` (robotta) anahtarları üretir, açık anahtarları + profil özetini SOC'a
  kaydeder; anahtar rotasyonu ve iptal listesi (revocation v2) SOC'tan dağıtım.
- **R:** Profil yaşam döngüsü SOC'tan: imzalı profil yükleme/kilitleme, sürüm geçmişi,
  anti-rollback; "observe → enforce" geçişi onaylı.
- **R/D:** Güncelleme: `install-bundle.sh` dpkg ile gerçek hedefte test, rollback,
  kara kutu format uyumluluğu testi; staged rollout (halka 0/1/2) SOC'tan
  tetiklenen **bilgi** (yükleme robotta yerel/onaylı) — SECURE-DELIVERY 13a kapsamı.
- **AC:** 50 sanal robot (Gazebo/konteyner) onboard + anahtar rotasyonu + güncelleme
  ve geri alma, veri kaybı yok.

### Sprint 10 — Sertleştirme

- **R:** Elle yazılmış kriptoyu `sha2`/denetlenmiş crate'lere taşı; Reed-Solomon için
  denetlenmiş crate değerlendir; `#![forbid(unsafe_code)]` mümkün olan her crate'te,
  geri kalan `unsafe` blokları gözden geçir; `panic = "abort"` + systemd watchdog
  restart davranışı test; eksik fuzz hedefleri (diyot manifest/batch, kontrol düzlemi
  HTTP/JSON, correlate kural JSON, safety feed, Kafka wire, CDR) + her biri ≥1 saat
  libFuzzer koşusu CI-nightly.
- **R:** Anahtarlar: TPM 2.0 ile mühürleme (destekli donanımda), yoksa dosya +
  açık uyarı; donanım TPM ile NV counter anchor testi.
- **A:** `.env.example` güvenli varsayılanlar (A7), `env.sh` zorunlu güçlü sırlar,
  `APP_ENV=production` default, `temporal ui` sürüm sabitleme; rebrand artıkları (A6);
  MCP ikonlarını yerel varlıklara taşı (A8); lisans **üretim açık anahtarı** (A5).
- **D:** Bağımlılık taraması (cargo-deny, pip-audit/uv, pnpm audit, trivy imaj
  taraması) CI'da zorunlu; SBOM her iki ürün için.
- **AC:** sıfır High/Critical bulgu (SAST/SCA/imaj); fuzz 24 saat çökmesiz.

### Sprint 11 — Saha doğrulama + red-team  → **Kapı 3: Public Beta / RC**

- **Q:** 72 saat soak (her iki tasarım ortağı robotu + Gazebo filo), FP oranı ölçümü
  ve eşik ayarı (correlate kuralları dahil), bellek/CPU bütçesi (robotta ör. < %5 CPU,
  < 150 MB RSS) ölçümü; arm64 gerçek donanım (Jetson/RPi5 sınıfı) + eBPF arm64 yükleme.
- **Q:** Pulsar kurallarını gerçek Pulsar rules-engine'e yükle; pulsard'ı robotta
  multicast + DDS vendor eşzamanlılığıyla doğrula.
- **Q/Harici:** Red-team haftası: rogue participant, GUID spray, safety-state spoof,
  replay, kontrol düzlemi saldırıları, prompt-injection (ROS node adları), SOC
  tarafı yetki yükseltme. Harici pentest (AutoSecOps1 + RoboDR).
- **Kapı 3 AC:** FP < hedef (S0'da belirlenen, ör. < 1 yanlış alarm/robot/gün),
  red-team kritik bulgu 0 açık, soak'ta veri kaybı/sızıntı yok, RC sürümü (`v1.0.0-rc.1`)
  imzalı yayınlandı.

### Sprint 12 — Paketleme, kurulum, gözlemlenebilirlik

- **D:** RoboDR: release workflow'unun ilk gerçek koşusu (`v1.0.0-rc.*`), minisign
  anahtar yönetimi (offline root + release key), cosign/SLSA provenance,
  `robodr-anchor-receiver` `.deb` zorunlu listesine; AutoSecOps1'deki
  `scripts/third_party_notices.py` örneğiyle RoboDR için `THIRD_PARTY_NOTICES.md`
  (cargo-about/cargo-deny verisinden; Pulsar eBPF GPL-2.0 kaynak teklifi dahil) ve
  `.deb`/bundle içinde `/usr/share/doc/robodr/`; `.deb` + offline bundle; opsiyonel
  konteyner imajı.
- **D:** AutoSecOps1: RoboDR modülü dahil imajlar, Helm chart'ı **SingularityRD
  reposunda** (upstream'e değil), Fargate modülünde `name_prefix` geçişi, air-gapped
  kurulumda RoboDR yolu (diyot import dizini) dokümanlı.
- **A/R:** Gözlemlenebilirlik: agentd sağlığı → SOC'ta robot sağlık metrikleri
  (son heartbeat, spool derinliği, drop sayaçları), uyarı kuralları; OTel metrikleri.
- **AC:** Temiz bir müşteri ortamında (connected + air-gapped) kılavuzla < 2 saatte
  kurulum; yükseltme `rc.1 → rc.2` veri kaybısız.

### Sprint 13 — Dokümantasyon, uyum, ticari paket

- **Docs:** Müşteri dokümanları: Quick-start, Kurulum (robot + SOC + air-gap),
  Commissioning (profil öğrenme/kilitleme), Yanıt politikası yazımı, Operasyon
  runbook'ları, Sorun giderme, Destek matrisi, API/sözleşme referansı, Güvenlik
  beyaz kağıdı, Bilinen kısıtlar (dürüst liste: Zenoh, SROS2 payload, safety-rated değil).
- **L:** EULA, SLA/destek seviyeleri, fiyatlandırma (robot başına + SOC tier), lisans
  token üretim prosedürü (`scripts/license_tool.py` → üretim anahtarı, HSM/offline),
  ihracat kontrol beyanı, üçüncü taraf lisans bildirimleri (NOTICE, THIRD_PARTY dosyaları,
  her iki ürün).
- **Uyum:** IEC 62443-4-2 boşluk analizi + SDL kanıtları (4-1), CRA hazırlık (SBOM,
  güvenlik açığı bildirimi süreci, destek süresi), `SECURITY.md` PSIRT süreci.
- **AC:** Doküman sitesi yayında; hukuk tüm metinleri onayladı; lisans token akışı
  uçtan uca (üret → kur → entitlement → robot kotası).

### Sprint 14 — GA sertleştirme ve yayın  → **Kapı 4: GA**

- Yalnızca hata düzeltme (feature freeze S12 sonu). Tasarım ortaklarında RC → GA
  yükseltme provası. Son regresyon (tüm CI + soak 72 saat tekrar + uçtan uca
  contract test + kurulum testi). `v1.0.0` tag'leri (RoboDR + AutoSecOps1), imzalı
  artefaktlar, release notes, destek ekibi eğitimi, satış demo ortamı.
- **GA AC:** §4'teki tüm GA kapı kriterleri yeşil.

---

## 3a. Unitree platform paketi (Go2 / B2 / G1 / H1)

**Kısa cevap: evet, desteklenebilir — ve güçlü bir satış senaryosu**, ama bugünkü kod
yalnızca bir kısmını kutudan çıkar çıkmaz yapar. Unitree'nin SDK2'si ve `unitree_ros2`
paketi **Cyclone DDS 0.10.x** üzerinde çalışır (Go2, B2, H1, G1); RoboDR'ın RTPS
ayrıştırıcısı Cyclone trafiğini zaten gerçek yakalamalarla doğrulanmış şekilde okuyor.

| Yetenek | Bugün | Unitree için gereken |
|---|---|---|
| DDS grafiği, rogue participant / bilinmeyen yayıncı tespiti (`rt/lowcmd` vb.) | ✅ Protokol düzeyinde çalışmalı (Cyclone) — **Unitree trafiğiyle doğrulanmadı** | Gerçek Go2/G1 yakalamaları, profil öğrenme |
| Hareket içeriğini okuma (CDR) | ❌ Yalnız standart ROS tipleri (Twist, JointTrajectory, …) | Unitree IDL decoder'ları: `unitree_go::msg::dds_::LowCmd_/LowState_/SportModeState_`, `unitree_hg::msg::dds_::LowCmd_/LowState_` (G1/H1-2), `unitree_api::msg::dds_::Request_` (sport API, JSON parametreli) — tip adları lab'da doğrulanacak |
| Motion Firewall zarfı | ❌ Twist/trajectory zarfı | Eklem başına q/dq/tau/kp/kd sınırları, LowCmd CRC kontrolü, sport API `Move` hız sınırları; 500 Hz–1 kHz düşük seviye döngü için gecikme bütçesi |
| Host izleme (Pulsar) | Robot üstü Linux gerekir | Yalnız **EDU** modellerinde erişilebilen geliştirme bilgisayarı (Jetson, arm64); L4T çekirdeğinde BTF/eBPF doğrulanmalı. Ana hareket kontrolcüsü kapalı → kurulamaz |
| Agentless mod | Tasarım var (Sentinel Box) | Robotun 192.168.123.0/24 Ethernet'ine port-mirror / tap ile pasif sensör — firmware'e dokunmadan; Air/Pro gibi kapalı modeller için tek yol |
| Yanıt | ❌ | `quarantine_node`/`isolate_network` (dış kutuda nftables); `restrict_motion` sport API üzerinden; **insansıda `safe_pause` = düşme riski** → G1/H1'de GA'da yürütülmez, yalnız plan |

**Unitree'ye özgü tehditler (satış argümanı):** UniPwn (Eyl 2025) — BLE Wi-Fi
yapılandırma servisinde sabit anahtarlar ve komut enjeksiyonu (CVE-2025-35027) ile
root, solucan gibi yayılabiliyor (Go2, B2, G1, H1); G1'in kullanıcıya bildirmeden dış
sunuculara telemetri gönderdiği raporlandı; Go1'de daha önce uzaktan tünel arka kapısı
bulunmuştu. RoboDR'ın karşılığı: `wpa_supplicant_restart.sh` altından beklenmeyen kabuk
(Pulsar kuralı), robotun beklenmeyen dış bağlantıları (host + ağ sensörü), yeni DDS
katılımcısı / `rt/lowcmd`'ye yetkisiz yazıcı, imzalı kara kutu ile adli kanıt.

**Unitree işleri sprint planına:**
- **S0:** Go2 EDU + G1 EDU tedarik; firmware sürümlerini sabitle; ağ topolojisi ve
  onboard bilgisayar OS/çekirdek envanteri; Unitree kullanım şartları/garanti etkisi
  değerlendirmesi (robot üstü ajan kurulumu).
- **S2:** Gerçek Go2/G1 yakalamaları (`fixtures/captures/unitree/`, sentetik
  kimliklerle); `robodr-cdr`'a Unitree decoder'ları + vektör testleri + fuzz.
- **S3:** Unitree profil şablonları (`config/profile.unitree-go2.example.json`,
  `…-g1…`), Unitree kural paketi (`rules/robodr/unitree.toml`: BLE/wpa_supplicant
  kabuk, dış telemetri, bilinmeyen `rt/lowcmd` yazıcısı); AutoSecOps1'de "Unitree"
  workflow şablonu ve ikon.
- **S7:** Agentless sensör kutusu (arm64 mini PC + tap) referans imajı — Unitree için
  varsayılan kurulum modu.
- **S8:** LowCmd eklem zarfı + sport API hız zarfı; firewall gateway'in Unitree
  döngü hızında gecikme ölçümü; `restrict_motion` sport API adaptörü.
- **S11:** Go2 ve G1 üzerinde 72 saat soak, UniPwn benzeri saldırı senaryolarıyla
  red-team (izole lab, yetkili cihazlarda).
- **Kapsam dışı (GA):** Go1 (DDS değil, eski UDP SDK), Air/Pro üzerine ajan kurulumu,
  insansıda otomatik güvenli duruş, Go2 uygulama kanalı (WebRTC) içeriğinin çözümü.

---

## 4. GA çıkış kriterleri (Definition of Done)

**Fonksiyonel**
- [ ] Bulgular connected + air-gapped yollarda imzalı, tekil, doğru severity/alanlarla case olur.
- [ ] Kanıt paketi case'ten indirilir ve bağımsız doğrulanır.
- [ ] `restrict_motion`, `quarantine_node`, `isolate_network`, `record_evidence` gerçek robotta uygulanır, doğrulanır, TTL/elle geri alınır; `safe_pause` OEM-onaylı politikada çalışır.
- [ ] Hiçbir robot aksiyonu onaysız gönderilemez; iki-kişi kuralı uygulanır.
- [ ] Robot onboarding, anahtar rotasyonu/iptali, profil kilitleme, güncelleme/geri alma UI'dan yönetilir.
- [ ] Unitree Go2 EDU ve G1 EDU: tespit + kanıt + ağ tabanlı containment gerçek cihazda doğrulandı (agentless ve EDU ajan modları).
- [ ] RoboDR tescilli lisansla dağıtılıyor; üçüncü taraf bildirimleri ve eBPF GPL-2.0 kaynak teklifi pakette.

**Kalite**
- [ ] İki repoda CI yeşil (lint, typecheck, unit, integration, contract test, fuzz-nightly, migrations).
- [ ] 72 saat soak × 2 platform; FP hedefi tutuldu; kaynak bütçesi tutuldu.
- [ ] amd64 + arm64 gerçek donanım; eBPF her ikisinde yüklü.
- [ ] Harici pentest + red-team: açık Critical/High 0.

**Güvenlik / tedarik zinciri**
- [ ] Tüm ağ yolları TLS/mTLS; anahtarlar TPM'de (destekli donanımda).
- [ ] İmzalı, reproducible release; SBOM; cosign/SLSA provenance; SCA temiz.
- [ ] Üretim lisans anahtarı; dev anahtarı koddan kaldırıldı.

**Ticari / hukuk**
- [x] AutoSecOps1 lisans/menşe, Pulsar GPL eBPF ve ihracat kontrol için hukuki onay alındı (2026-10-25).
- [ ] Açık-çekirdek ayrımı uygulandı; ihracat sınıflandırmasının teslim koşulları satış sürecine işlendi.
- [ ] RoboDR için de üçüncü taraf bildirimleri (Rust crate'leri, Pulsar/eBPF GPL-2.0 kaynak teklifi) paketlerle gönderiliyor.
- [ ] EULA, SLA, fiyat, destek süreçleri, PSIRT, müşteri dokümanları yayında.

---

## 5. Risk kaydı

| Risk | Olasılık | Etki | Azaltma |
|---|---|---|---|
| ~~AutoSecOps1 lisans/menşe~~ | — | — | ✅ Hukuki onay alındı (2026-10-25). Bağımlılık lisans uyumu CI'da `test_third_party_notices.py` ile korunuyor; yeni GPL/AGPL bağımlılık eklenmesi review'da durdurulur |
| Gerçek robot erişimi gecikir | Orta | Yüksek | S0'da donanım satın alma; Gazebo filo + kiralık AMR yedek |
| Executor bir robotu güvensiz duruma sokar | Düşük | Kritik | Sadece geri alınabilir aksiyonlar GA'da; safety state yeniden kontrol; OEM politika bayrağı; güvenlik sistemi asla aşılmaz; saha testinde E-stop'lu ortam |
| Firewall gateway gecikmesi kontrol döngüsünü bozar | Orta | Yüksek | S8 ölçüm kapısı; varsayılan recording-only; enforce opt-in |
| FP oranı yüksek → müşteri güveni | Orta | Yüksek | Commissioning (observe mode) zorunlu; S11 ayar; correlate kuralları varsayılan kapalı/uyarı |
| Zenoh/SROS2 kullanan müşteri | Yüksek | Orta | Destek matrisinde açık; GA sonrası yol haritası; algılanınca görünür uyarı (mevcut) |
| İhracat kontrol / savunma müşterileri | Düşük | Yüksek | Sınıflandırma alındı; teslim koşullarına (ülke/son kullanıcı beyanı) satış sürecinde uyum; kontrollü repo ayrımı |
| CI maliyeti / billing | Düşük | Orta | S0'da çözülür; self-hosted runner seçeneği |

---

## 6. GA sonrası (v1.x / v2)

Sentinel Box (kapalı kontrolcüler, OPC UA/ABB), attestation (`robodr-attest`, Keylime,
measured boot), Bus Tap (CAN/EtherCAT/MAVLink), Lite SDK (RTOS), Zenoh decode, SROS2
payload desteği, depot/lease/OS A/B (SECURE-DELIVERY 13b/c, 14), `request_safe_state`
ve `rollback_config` yürütümü, AI Guard (LLM planner koruması), çok kiracılı MSSP modu,
OEM white-label konsol, IEC 62443-4-2 sertifikasyonu.
