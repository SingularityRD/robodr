# RoboDR: Satış Döngüsü Hazırlık Açıkları (birleştirilmiş, sıralı)

Durum: HEAD f84bfc1, `git tag` boş, VERSION 0.1.0-alpha.1.

İki bulgu bugün REST ile doğrulandı ve görev metniyle çelişiyor:
- **CI run 41136491301 (görevdeki "run 22") bitti ve kırmızı.** Tamamlanma saati 2026-10-30 22:11Z. Başarısız işler: Pure crates, iki Rocky RPM işi, cargo-deny ve Fuzz smoke. Package install smoke atlandı.
- **Depo görünürlüğü `public`.** Bu yüzden bazı dokümanlardaki "private repository" ifadesi (psirt-process.md:34-36, RELEASE/ADR-0009) yanlış. Bu durum C13'te ayrı bir hukuki karar olarak yer alıyor.

## 1. Özet

7 aşamadan gelen yaklaşık 190 ham bulgu birleştirildi; sonuç **131 tekil açık**.

| Önem | Adet |
|---|---|
| blocker | 16 |
| high | 53 |
| medium | 49 |
| low | 13 |

| Kategori | Adet |
|---|---|
| technical | 79 |
| validation | 15 |
| process | 14 |
| legal | 8 |
| hardware | 6 |
| commercial | 5 |
| people | 4 |

- **Bu repoda kodla veya dokümanla kapatılabilen: 93** (Bölüm A). Bunlardan yalnız biri blocker: kırmızı CI.
- **Donanım veya gerçek saha gerektiren: 13** (B.1). **AutoSecOps reposunda yapılması gereken: 4** (B.2).
- **Sahip kararı veya hukuk/ticari iş gerektiren: 21** (C). Bunların 10'u blocker.
- **Satışı en çok engelleyen 6 açık:** imzalı sürüm yok (C1), lisans/EULA/fiyat yok (C3/C4), dış pentest yok (C8), PSIRT ve destek modeli yok (C9/C10), demo SOC yok (S1), gerçek robotta doğrulama yok (B1-B4).

---

## 2. Bölüm A: Bu repoda kodla/dokümanla kapatılabilen açıklar

### Blocker

**T1. CI kırmızı (run 41136491301): sürüm ve PR birleştirme bunu bekliyor**
- Aşamalar: Teslim, Mühendislik, tüm aşamalar dolaylı
- Önem: blocker · Efor: M
- Alt işler:
  - **T1a cargo-deny:** RUSTSEC-2026-0387 açığı, crypto-bigint 0.5.5 üzerinden p256 0.13'ten geliyor (Cargo.toml:143, Cargo.lock:728-730, deny.toml:25-34). Çözüm: p256/elliptic-curve 0.14'e geçmek. O mümkün değilse, seal ECDH ve depot CA imzası için yazılı istismar analiziyle süreli bir `ignore` eklemek.
  - **T1b Pure crates test (exit 101):** deliverd adversarial suite root olmadan 15/22 başarısız. Neden: crates/robodr-deliverd/tests/common/mod.rs:407-420 içindeki test passwd dosyasında agentd kullanıcısı yok; safety.rs:151-163 bu kullanıcıyı arıyor. Çözüm: etkin uid ile agentd satırı eklemek veya `safety.agentd_user`'ı ayarlamak.
  - **T1c Rocky 9 RPM amd64/arm64 (exit 127):** Konteynerde PATH eksik (scripts/ci-setup.sh:55, ci-install-rustup.sh:42-43, ci.yml:590-656). Çözüm: job `env.PATH`'i açıkça tanımlamak ve bir `command -v` guard'ı eklemek. Ardından package-smoke yeşile döndürülmeli.
  - **T1d Fuzz smoke:** Nedeni bilinmiyor; sandbox'tan log alınamıyor (403). Actions UI'dan log çekilip düzeltilecek.
- Bitiş: tüm işler yeşil ve docs/BUILD.md'ye kaydedilmiş.

### High

**T2. Konumlandırma ve müdahale yetenekleri dokümanları kodla çelişiyor**
- Aşamalar: POC, Satın alma, İşletim, Devreye alma · Kategori: commercial/technical · Efor: S
- Kanıt:
  - README.md:10-11 ve :42-43 drone, endüstriyel kol, savunma UGV'si ve Sentinel Box'ı kapsamda gösteriyor. Sentinel Box GA sonrasına planlı (GA-ROADMAP:1075; SPRINTS:345-353 "not started").
  - Şu dokümanlar restrict_motion'ı "recorded only", safe_pause'u "never executed" diye anlatıyor: README:217-218, known-limitations:35-37, security-whitepaper:182/189, safety-positioning:59/139, executor README:13-16/372/839-842, decision.rs:31/653, engine.rs:115, GA-ROADMAP:21.
  - Oysa motion adapter'ları mevcut: executor motion/{adapters,mavlink,rtps,cdr}.rs ve README:168-240.
- Çözüm:
  - Kapsamı yalnız doğrulanmış olana indirmek: ROS 2/DDS, Unitree, Pulsar host. Gerisi Roadmap satırına taşınır.
  - Adapter'ları adıyla, `oem_validated` kapılarıyla ve doğrulama seviyeleriyle yazmak. Kaynak kod yorumlarını da düzeltmek.

**T3. Platform ve kurulum gereksinimleri birbirini tutmuyor (glibc 2.39 / 2.35, RPM, sürüm dokümanları)**
- Aşamalar: POC, Teslim, Devreye alma · Efor: S
- Kanıt:
  - 2.39 diyen yerler: quick-start:28/61-62, OPERATIONS:31-33/188-191, known-limitations:232-233, BUILD:725/794/802/825.
  - 2.35 diyen yerler: support-matrix:22-23, packaging/README:257, release.yml:185-195.
  - support-matrix:28 "No offline bundle" diyor; RELEASE:30-33 ve install-bundle.sh:56-67 RPM offline bundle'ı destekliyor.
  - RELEASE:147 "19 assets" diyor, :30 ise 21. RELEASE:259-260'daki `--version` notu, BUILD:875-882'deki düzeltmeyle uyumsuz.
- Çözüm: Tek bir gereksinim tablosu (glibc 2.35+, systemd 247+, 22.04/24.04, JP6, Debian 12, EL9; focal paketi 20.04/JP5 için). Buna `2.39` için bir CI grep kontrolü eklenecek.

**T4. Güvenlik, uyum ve durum dokümanları HEAD'in gerisinde**
- Aşamalar: POC, Satın alma, İşletim, Mühendislik · Kategori: process · Efor: S
- Kanıt:
  - security-whitepaper: :112 legacy HMAC "loads", :119-120 TPM "planned", :231-236 notices "not yet". §2 süreç tablosunda executor, firewall-gw, enroll, deliverd, depot, anchor-receiver ve seal yok.
  - 62443-4-2 gap analysis: GAP-05/06/21/24 "Open" olarak duruyor (:101,104,112,165,192-193,208,211).
  - Fuzz hedef sayısı: README:233, cra-readiness:44 ve gap:127 "23" diyor; gerçekte 37.
  - Kontrat sürümü: README:203 "findings 2.1" diyor, model.rs:36 2.4.0.
  - Lint durumu: OPERATIONS:1018 "indexing not denied" diyor; artık deny ediliyor.
  - Diğer: SECURITY.md:212-214 imzalı sürümlerden söz ediyor (henüz sürüm yok); eula-draft:39 "notices planned" diyor; known-limitations:69-70, :100-105 ve :187-189 kodla çelişiyor; GA-ROADMAP:18/42/136/202 ve README:189 "CI never run" diyor; README layout'ta 5 crate eksik.
- Çözüm:
  - Tek seferlik senkron.
  - Her uyum dokümanına "doğrulandığı commit" damgası.
  - `scripts/check-doc-facts.py`: kontrat sürümünü, üye sayısını, fuzz hedef sayısını ve aksiyon destek tablosunu CI'da kontrol eder.
  - RELEASE.md kontrol listesine "müşteri dokümanlarını tazele" maddesi.

**T5. SOC ajan canlılığını göremiyor: ölü veya kör ajan, sessiz robottan ayırt edilemiyor**
- Aşamalar: POC, İşletim, Destek/Yenileme · Efor: M
- Kanıt: agentd daemon.rs:18 ve :1455-1459'daki heartbeat yalnız black box'a gidiyor. findings ve ingest kontratlarında health/check-in kaydı yok. agentd_version yalnız enroll'da gönderiliyor. GA-ROADMAP:797-798 ve :822-823 de bunu açık olarak listeliyor.
- Çözüm:
  - İmzalı periyodik `robot.agent.health` kaydı. İçeriği: bileşen sürümleri, profil digest'i, girdi tazeliği, drop/spool sayaçları, black box durumu, executor/gateway/pulsard erişilebilirliği, safety_state, sertifika/CRL bitiş tarihleri.
  - uplink, Kafka ve diode üzerinden gönderilir; findings kontratında minor bump ve vektörler.
  - SOC tarafındaki "robot sessiz > N dk" kuralı S3'e bağlı.

**T6. Sertifika/CRL süresi dolmadan uyarı yok**
- Aşamalar: Devreye alma, İşletim · Efor: S
- Kanıt: known-limitations:170-173. crl.rs:45 nextUpdate'i zorluyor ama bu bilgi hiçbir status'ta görünmüyor. health.rs:44-78'de bitiş süresiyle ilgili kural yok.
- Çözüm:
  - agentd, uplink, kafka-publish, enroll, anchor-receiver ve depot status'larına `days_to_expiry` ve `crl_next_update` eklenir.
  - `robot.agent.credential_expiring` kuralı: 14 gün kala Medium, 3 gün kala High.
  - Air-gap ortamda CRL yenileme prosedürü yazılır.

**T7. Saat senkronu sağlık kontrolü ve zaman kaynağı rehberi yok (GAP-09)**
- Aşamalar: Satın alma, Devreye alma, İşletim · Efor: M
- Kanıt: gap:115/196, known-limitations:209-210. Kodda adjtimex veya STA_UNSYNC kullanımı yok.
- Çözüm:
  - `clock_synchronized` status alanı ve `clock_unsynced` (Medium) / `clock_jump` (High) kuralları.
  - Duvar saati black box head zamanından geriyse reddetme.
  - chrony+NTS ve PTP için baseline dokümanı.

**T8. Gateway aşırı yükü Critical `internal_fault` olarak raporlanıyor (2 saatte 1.364 Critical)**
- Aşamalar: POC, Devreye alma, İşletim · Efor: S-M
- Kanıt: RESULTS.md O1 (:454-471). gateway.rs:1273-1275 geç kalan paket için fault üretiyor; events.rs:152 InternalFault'u Critical'e eşliyor. Devam eden gateway düzeltmelerinin parçası değil.
- Çözüm: Dakikalık agregasyonlu `robot.gateway.overload` kuralı (Medium; eşik aşılırsa High). `internal_fault` gerçek hatalar için kalır. Kontrat minor bump ve status sayacı. AutoSecOps ile koordine edilmeli.

**T9. Paket yükseltmesi gateway ve executor'ı safety-state kapısı olmadan yeniden başlatıyor**
- Aşamalar: Teslim, İşletim · Efor: M
- Kanıt: deb postinst:158-166 ve rpm post:108-113 try-restart yapıyor. fail_closed modunda bu, kuyruktaki hareket komutlarının düşmesi demek (OPERATIONS:2171-2176). deliverd ise yalnız idle veya safe_state_active durumunda kurulum yapıyor.
- Çözüm:
  - install-bundle.sh'de: gateway aktifse `--allow-gateway-restart` verilmedikçe veya status.json idle/safe göstermedikçe reddet.
  - postinst gateway'i yeniden başlatmaz, yalnız "pending-restart" işaretler.
  - OPERATIONS §7'ye yazılır ve test eklenir.

**T10. systemd ile boot eden VM'de kurulum/yükseltme/geri alma testi yok**
- Aşamalar: Teslim, Destek · Kategori: validation · Efor: M
- Kanıt: ci.yml'de qemu-system/KVM işi yok. Smoke testleri konteyner ya da qemu-user üzerinde koşuyor. pkg-install-smoke.sh:24,172 yalnız aynı sürümü yeniden kuruyor.
- Çözüm:
  - KVM job: Ubuntu 20.04/22.04/24.04, Debian 12 ve Rocky 9 (SELinux enforcing, AVC kontrolü), ayrıca arm64.
  - Akış: install → `enable --now` → heartbeat → N-1→N upgrade (state korunuyor mu) → rollback → purge.
  - T52'deki deliverd self-upgrade testi de bu job'da koşar.

**T11. Motion Firewall zarf dosyası devreye alma ve imza zincirinin dışında**
- Dosyalar: firewall.json, joint_config, allowed_sources
- Aşama: Devreye alma · Efor: L
- Kanıt: firewall-gw runtime.rs:63-82 dosyayı düz `read_capped` + `from_json` ile okuyor. agentd config.rs:1275-1276'da da durum aynı: imza yok, anti-rollback yok.
- Çözüm:
  - robodr-commission yakalamadan taslak kanal dosyası üretir (OEM tavanıyla sınırlı aralıklar, gözlenen yazıcılar `allowed_sources` olur).
  - Dosya motion quorum sign-off'una girer ve kilitli profille imzalanır.
  - İmzasız dosyada `enforce` reddedilir.
- Not: gateway tarafı, devam eden gateway düzeltmeleri birleştikten sonra yapılır.

**T12. `oem_validated` imzasız bir boolean**
- Aşama: Devreye alma · Efor: M
- Kanıt: agentd config.rs:1234-1237 response policy'yi imzasız okuyor; executor motion/mod.rs:4 ve :215 de aynı.
- Çözüm:
  - Response policy ve executor motion bayrakları profil gibi imzalanır: sign-off, quorum, Ed25519, anti-rollback.
  - İmzasız policy'de `oem_validated` false sayılır ve bulgu üretilir.

**T13. Saha kabul self-testi ve exporter bağlantı kontrolü yok (GAP-11)**
- Aşamalar: Devreye alma, Teslim · Efor: M
- Kanıt: gap:198. uplink, kafka-publish, enroll ve anchor-receiver'da kontrol modu yok (robodr-uplink.rs:24-45).
- Çözüm:
  - `robodr-agentd selftest`: işaretli `robot.agent.selftest` bulgusunu boru hattına sokar ve uplink/Kafka/diode ack'ini bekler.
  - Exporter'lara `--check`: TLS + CRL + auth el sıkışması, veri göndermeden.
  - OPERATIONS §5 ve quick-start'ta kabul adımı olarak yazılır.

**T14. Paylaşımlı bellek (SHM) taşımaları görünmüyor ve bulgu da üretilmiyor**
- Kapsam: Fast DDS SHM varsayılan, Cyclone iceoryx, Connext SHM
- Aşama: Devreye alma · Efor: M
- Kanıt: capture lib.rs:90-97; rtps wire.rs:255 SHM locator'larını ham bırakıyor. Dokümanlarda SHM rehberi yok.
- Çözüm:
  - SPDP'deki SHM locator'ı ve /dev/shm segmentleri için `robot.capture.unsupported_transport` bulgusu ve learn-report uyarısı.
  - `FASTDDS_BUILTIN_TRANSPORTS=UDPv4` / Cyclone SHM kapalı ayarını devreye alma ön koşulu olarak belgelemek.
  - Lab yakalama testi.

**T15. Black box kanıtı varsayılan ayarla yaklaşık 13 saatte dönüyor ve dışa aktarılmamış kayıt sessizce düşüyor**
- Aşamalar: İşletim, Destek, Satın alma (GAP-08) · Efor: M
- Kanıt:
  - store.rs:676-677 Cyclic 8×8 MiB; soak'ta ölçülen yazım ~4,7 MB/saat.
  - BlackboxSection'da (config.rs:384-415) retention alanı yok. daemon.rs:699.
  - Kapasite uyarısı yok (GAP-08). `export_pending` var (store.rs:3990) ama CLI'si yok (OPERATIONS:2414-2421).
- Çözüm:
  - `blackbox.retention` ayarı (mode, segment sayısı, segment boyutu; boş disk alanına göre doğrulanır).
  - %80 kapasite uyarısı; dışa aktarılmamış veya açık bulguya bağlı segment dönerse bulgu.
  - `robodr-blackbox export-pending` + systemd timer (diode için RBBXBND1).
  - Boyutlandırma tablosu.

**T16. Day-2 ayarı yok: kural bazında bastırma, önem override'ı veya süreli istisna**
- Aşama: İşletim · Efor: M
- Kanıt: config.rs CorrelationSection'da suppress alanı yok. known-limitations:21-23.
- Çözüm:
  - Operatör imzalı, sürümlü, anti-rollback'li tuning dosyası: zorunlu bitiş tarihi ve gerekçe.
  - Bastırılan olaylar yine black box'a yazılır; periyodik "suppressed N" bulgusu üretilir.

**T17. Unitree için yerel safety-state kaynağı yok**
- Aşama: İşletim · Efor: M
- Kanıt: agentd'de sportmodestate/lowstate decoder'ı yok. safety_feed Unitree örnek config'lerinde bulunmuyor. Soak: safety_state 49/120 durumda unknown; restrict_motion 3/8 kez `safety_state_unavailable` ile reddedildi.
- Çözüm: `rt/sportmodestate` ve `rt/lowstate` decoder'ları (writer pinning ile) ve Unitree örnek config'leri. Durum eşlemesi B1'de gerçek robotta doğrulanır.

**T18. Executor ROS 2 adapter'ları yalnız rmw_cyclonedds destekliyor; tüm motion adapter'ları sadece sentetik peer'larla doğrulanmış**
- Aşamalar: İşletim, POC · Efor: L
- Kanıt: motion/mod.rs:86-90 `enum Rmw { Cyclonedds }`. executor README:779-788. RESULTS.md A0 "no answer from the peer".
- Çözüm: rmw_fastrtps request header'ı. CI'da konteyner peer'lar (Nav2+Gazebo, ros2_control hold controller, PX4 SITL; Humble ve Jazzy, iki RMW). restrict_motion, safe_pause ve request_safe_state uçtan uca, read-back ve revert ile.

**T19. Gateway kararları imzalı black box'a girmiyor (GAP-24)**
- Aşamalar: Satın alma, Devreye alma · Efor: M
- Kanıt: gap:112/211. firewall-gw/src'de black box referansı yok.
- Çözüm: Kararlar ve fault/hold/mode olayları kimlik doğrulamalı yerel soket üzerinden agentd'ye gider ve imzalı not olarak kaydedilir. Tamper testi eklenir. Gateway birleşmesinden sonra yapılır.

**T20. SBOM eksik (CRA/NTIA)**
- Aşamalar: Satın alma, Destek · Efor: M
- Kanıt: cra-readiness:42. RELEASE:29-31: RPM'in SBOM'u yok. metadata_to_cyclonedx.py std, musl ve eBPF bileşenlerini içermiyor.
- Çözüm: Her artefakt için CycloneDX 1.5+ SBOM. İçerik: eBPF objeleri (hash ve GPL-2.0), Rust std/core/alloc, musl/libunwind, toolchain (formulation). cyclonedx-cli ile doğrulanır, `/usr/share/doc/robodr/`'a konur, publish bu kontrole bağlanır.

**T21. Konsolide tehdit modeli yok (62443-4-1 SR-1/SR-2)**
- Aşama: Satın alma · Efor: M
- Kanıt: sdl-evidence:71-73, :85-87.
- Çözüm: `docs/compliance/threat-model.md`: bağlam, varlıklar, T1-T7 saldırganları, TB1-TB8 için DFD'ler, STRIDE, testlere bağlı mitigasyonlar, SL-C hedefleri. Her sürümde tarihli review RELEASE kontrol listesine eklenir.

**T22. Veri işleme ve gizlilik dokümanı yok**
- Aşama: Satın alma · Kategori: legal (doküman kısmı) · Efor: M
- Kanıt: robodr.findings.md:270-272, :745 (hostname, cmdline, operatör kimliği taşınıyor). eula-draft:85-91'de DPA yer tutucu.
- Çözüm: `docs/customer/data-handling.md`: akış bazında veri envanteri, saklama yeri, şifreleme, saklama süresi, silme ve "SingularityRD'ye hiçbir veri gitmez" beyanı. İsteğe bağlı: cmdline/kullanıcı adı redaksiyonu. DPA C3'te.

**T23. Release workflow yeşil CI'ya bağlı değil**
- Aşama: Mühendislik · Kategori: process · Efor: S
- Kanıt: release.yml prepare adımı (~104-184) yalnız tag ve sürüm tutarlılığına bakıyor.
- Çözüm: prepare, commit'in check-run'larını sorgular ya da ci.yml'yi `workflow_call` ile çağırır. Branch protection'da required checks açılır (ayar).

**T24. root, TPM ve netns gerektiren testler CI'da atlanıyor**
- Aşamalar: Mühendislik, Satın alma · Kategori: validation · Efor: M
- Kanıt: Workflow'larda ROBODR_SWTPM, ROBODR_REQUIRE_NETNS veya `--ignored` yok. İlgili testler: seal/tests/common, executor/tests/netns.rs, firewall-gw/tests/netns_e2e.rs, capture live_afpacket.rs. swtpm harness 3 denemenin 2'sinde "did not start" ile düştü.
- Çözüm: Zorunlu privileged ubuntu-24.04 job'u (swtpm, nftables, iproute2). "SKIPPED" çıktısında fail. swtpm için start retry ve readiness probe. FFI için sanitizer.

**T25. Gerçek Kafka broker testleri CI'da yok; KIP-360 epoch bump yok**
- Aşamalar: Mühendislik, İşletim, Devreye alma · Kategori: validation · Efor: M
- Kanıt: kafka_real_broker.rs `#[ignore]`. kafka-it.sh ve kafka-tls-it.sh hiçbir workflow'da çağrılmıyor. kafka/client.rs:72-103 InitProducerId v0-1 kullanıyor. known-limitations:235-241.
- Çözüm:
  - KRaft ile tek broker ve 3 broker, leader failover dahil. TLS, mTLS ve SCRAM CI job'ları.
  - InitProducerId v3+ ile UNKNOWN_PRODUCER_ID ve INVALID_PRODUCER_EPOCH durumlarında epoch bump; değer spool cursor ile birlikte saklanır.

**T26. arm64'te unit/integration testi yok**
- Aşama: Mühendislik · Efor: S
- Kanıt: pure ve pulsar job'ları yalnız ubuntu-24.04'te koşuyor. Elle tanımlanmış FFI sabitleri: deliverd fdio.rs, firewall-gw restrict.rs, agentd host.rs.
- Çözüm: ubuntu-24.04-arm bacağı (clippy+test). Sabitler için libc/rustix değerlendirilir.

**T27. eBPF/Pulsar hiç bir çekirdeğe yüklenmedi; `rules/robodr/*.toml` çalışan bir motorda denenmedi**
- Aşamalar: Mühendislik, POC · Kategori: validation · Efor: M
- Kanıt: ci.yml:206; known-limitations:133; support-matrix "rules ... V0"; README:251-253.
- Çözüm: VM job: .deb kurulur, pulsard başlatılır, exec/file/network fixture'ları tetiklenir, her kuralın bulgusunun agentd'ye ulaştığı doğrulanır. amd64 ve arm64.

**T28. Tek komutluk demo kiti yok**
- Aşama: POC · Efor: L
- Kanıt: Repoda compose dosyası veya demo script'i yok. ugv-demo `cargo run` gerektiriyor. tools/e2e root, netns ve AutoSecOps istiyor. Referans ingest yalnız test kodunda (export/tests/common).
- Çözüm: `demo/`:
  - jazzy baseline ve rogue capture'ları replay → agentd.
  - Geçici anahtarlarla learn/lock.
  - Paketlenmiş Kafka ya da `robodr-demo-soc` (imza ve black box doğrulaması yapan referans ingest/görüntüleyici).
  - Sürüm binary'leriyle çalışır. Hedef: ilk bulgu 10 dakikanın altında.

**T29. POC playbook yok**
- Aşama: POC · Kategori: process · Efor: M
- Kanıt: docs/customer'da POC/pilot dokümanı yok. GA-ROADMAP S14.
- Çözüm: `docs/customer/poc-guide.md`: ön koşullar (tap, sensör kutusu, middleware anketi), haftalık plan, ölçülebilir çıkış kriterleri (senaryo bazında tespit, POC sırasında ölçülen FP, CPU/RSS, tespit süresi), capture verisi kuralları, readout şablonu. spool-summary.py ve soak_report.py → `robodr-poc-report`.

**T30. Paketlenmiş saldırı simülatörü yok**
- Aşama: POC · Efor: M
- Kanıt: Senaryolar yalnız lab script'lerinde: redteam_net.py, redteam2.sh, rtlib.py, soak_traffic.rs. build-deb.sh:196 bunları paketlemiyor.
- Çözüm: Ayrı paket `robodr-attack-sim`. `--i-understand` bayrağı ve hedef allow-list ile korunur. Senaryolar: rogue SPDP/SEDP, cmd_vel zarf dışı, GUID spray, bozuk RTPS, LowCmd tork. Beklenen bulgu id'lerini basar, böylece POC raporu otomatik puanlanır. Kod T28 ile paylaşılır.

**T31. Performans veri sayfası yok; dokümanlar ölçülmüş lab değerlerini yansıtmıyor**
- Aşama: POC · Efor: S
- Kanıt: support-matrix:86-98 "unmeasured" diyor ve p99 ≈35 µs veriyor. RESULTS:291/309/310 ölçümleri: 1,9 % CPU / ~12 MiB, p99 129 µs, LowCmd p99,9 135 ms.
- Çözüm: `docs/customer/performance.md`: bileşen bazında tablo, ortam, commit ve yöntem; değerler "lab" etiketli; GA hedefleri ve durumları. support-matrix ve README buraya link verir.

**T32. agentd/correlate throughput benchmark'ı yok**
- Aşamalar: POC (sensör kutusu boyutlandırma) · Kategori: validation · Efor: M
- Kanıt: Repoda benches/ veya criterion yok. correlate README:201, responder README:296.
- Çözüm: `agentd_throughput` bench'i: artan hızda pcap replay, çok sayıda katılımcı ve topic, 1 kHz motion. Ölçülecekler: çekirdek başına maksimum datagram/s ve katılımcı sayısına göre RSS. CI regresyon kapısı olur, eğri yayımlanır.

**T33. ROS 2 Humble yalnız sentetik fixture'larla doğrulanmış**
- Aşamalar: POC, Devreye alma · Kategori: validation · Efor: M
- Kanıt: support-matrix:45 V1. tools/lab-capture/Dockerfile:1 jazzy kullanıyor.
- Çözüm: lab-capture distro'ya göre parametrelenir. Fast DDS ve Cyclone ile baseline, rogue, frag, multi ve Gazebo capture'ları alınır; replay testleriyle `fixtures/captures/ros2-humble`'a konur; seviye V2'ye çıkar.

**T34. Secure-delivery zinciri (RPK, 2-of-N) release pipeline'a bağlı değil**
- Aşama: Teslim · Efor: M
- Kanıt: release.yml'de RPK veya robodr-release adımı yok. SECURE-DELIVERY:1351.
- Çözüm: robodr, robodr-focal ve rules için imzasız RPK ve bundle manifest üreten bir job. RELEASE.md'ye 2-of-N offline imza ve delivery-root bölümü. Seremoninin kendisi C1'de.

**T35. Hizmetten çıkarma (decommission) prosedürü eksik**
- Aşamalar: EOL · Efor: M
- Kanıt: OPERATIONS §9 (~2980-2993):
  - Yalnız 2 servisi kapatıyor.
  - Yalnız `apt purge` anlatıyor.
  - Flash bellekte `shred` kullanıyor.
  - prerm:9-10'a göre gateway kuralları fail_closed halde yolda kalıyor.
  - TPM NV undefine, `robodr-depot unit revoke` ve anchor-receiver anahtar silme adımları yok.
  - enroll.rs:57 var olmayan "OPERATIONS 8.6" bölümüne referans veriyor.
- Çözüm: Tam kontrol listesi. Sıra: export+verify → tüm robodr-* birimlerini kapat → gateway'i yoldan çıkar → depot revoke → anchor-receiver anahtarını sil → tpm2_nvundefine → seal erase → paket tipine göre purge → NIST 800-88. İsteğe bağlı `robodr-enroll decommission` yardımcısı imzalı rapor üretir.

**T36. Devreye alma ve sürüm anahtarları düz dosya; PKCS#11/HSM yok**
- Aşama: Devreye alma · Efor: L
- Kanıt: robodr-release README:113; OPERATIONS §5 adım 3. Kodda pkcs11/cryptoki yok.
- Çözüm: PKCS#11 Ed25519 backend'li signer soyutlaması (YubiKey/Nitrokey/HSM). robodr-commission ve robodr-release kullanır.

**T37. Zenoh (rmw_zenoh) tespit ediliyor ama decode edilmiyor**
- Aşamalar: POC, Devreye alma · Efor: XL
- Kanıt: support-matrix:51-52.
- Çözüm: Kısa vadede POC nitelendirme sorusu (C21). Uzun vadede mevcut zenoh capture'larından session/scouting decoder'ı.

**T38. Kontrat sürümleme AutoSecOps'la operasyonel olarak güvenli değil**
- Aşamalar: Mühendislik, Destek · Efor: M (kod kısmı)
- Kanıt: model.rs:36 producer'ı 2.4.0'a sabitliyor; `max_contract_minor` ayarı yok. ingest ve fleet dokümanları "draft v1". support-matrix'te AutoSecOps sürüm eşlemesi yok.
- Çözüm:
  - Producer cap ayarı.
  - support-matrix ve CHANGELOG'da "RoboDR sürümü ↔ kontrat major.minor ↔ min AutoSecOps" tablosu.
  - Tablodaki satır release.yml prepare'de kontrol edilir.
  - v1 kontratları GA öncesi dondurulur.
  - Çapraz repo CI S4'te.

### Medium

| ID | Başlık | Aşamalar | Efor | Kanıt | Çözüm |
|---|---|---|---|---|---|
| T39 | Control-plane pre-auth slotları slowloris ile tüketilebiliyor (W2-4) | POC, Devreye alma, İşletim | S-M | control/mod.rs:1233-1240 (eviction yok); RESULTS:418, :443-452 | En eski pre-auth bağlantıyı düşür; SOC allow-list için ayrılmış slot; S2 regresyon testi (SOC 20/20) |
| T40 | Disk dolmadan erken uyarı yok; ENOSPC/EIO testleri yok | İşletim | M | agent README:344-346; SPOOL_FULL yalnız drop'tan sonra | Black box, spool ve state dizinleri için statvfs eşikleri; tmpfs/dm-error ile fault injection |
| T41 | Executor erişilemezken bulgu yok; pulsard watchdog yok | İşletim | S | health.rs:44-78; pulsard.service:57 | `robot.agent.executor_unreachable` (High); pulsard WATCHDOG=1 veya sessizlik bulgusu |
| T42 | Nav2/PX4 safe_pause mandal değil; yeni hedef robotu yeniden hareket ettiriyor | İşletim | M | executor README:788 | Pause boyunca yeniden uygula ve override'da High bulgu üret, ya da gateway kısıtıyla eşleştirmeyi config'de zorunlu kıl |
| T43 | Config reload yok (gateway, agentd profil/policy) | Devreye alma, İşletim | L | SIGHUP/ExecReload yok; OPERATIONS:2166-2178, §8.6 | Gateway'de atomik hot reload (writer map korunur); agentd'de ExecReload. Gateway birleşmesinden sonra |
| T44 | Gateway VLAN, IPv6 ve PPPoE trafiğini düşürüyor | Devreye alma | M | firewall-gw README:1060 | 802.1Q vlan_filtering ve check-config'de doğrulanan pass-through listesi; netns e2e. Gateway birleşmesinden sonra |
| T45 | Tüm Pulsar tespitleri tek kural id'sinde (`robot.host.pulsar_threat`) | Devreye alma, İşletim | S | host.rs:75 | Kural bazında `robot.host.<rule>` id'leri; fallback korunur; kontrat minor bump |
| T46 | Operasyonel bağlam (mod, faz, bağlantı) statik config | Devreye alma | M | known-limitations:119-122 | Unitree sport mode, Nav2 lifecycle ve uplink durumundan canlı girdi |
| T47 | Devreye alma incelemesi elle JSON düzenlemekten ibaret; rapor ve kayıt şablonu yok | Devreye alma | M | OPERATIONS:584; commission main.rs:85 yalnız report.json üretiyor | report.json'dan HTML/PDF rapor; `commissioning-record-template.md` |
| T48 | POC hızlı yolu ve `poc-init` yok | POC | S | quick-start §4 | Starter profiller; tek operatörlü lab quorum; profilsiz çalışan tespitlerin listesi; adım bazında efor |
| T49 | Paket müşteri dokümanı ve demo verisi içermiyor | POC | S | build-deb.sh:339-345, :370-372 | Taslak olmayan customer/*.md dosyaları ve 1-2 küçük capture `/usr/share/doc/robodr/`'a; RPM ve offline bundle'da da |
| T50 | install-bundle'da kurulum sonrası sağlık kontrolü, auto-rollback ve prune yok | Teslim, İşletim | M | install-bundle.sh'de grep 0 sonuç; postinst:165 `|| true` | Aktif birimler ve taze heartbeat beklenir; başarısızlıkta rollback; `--keep N` |
| T51 | `ROBODR_ALLOW_UNSIGNED=1` bypass'ı ve robotta minisign bağımlılığı | Satın alma, Teslim | S | install-bundle.sh:61, :232, :692-693; OPERATIONS:158-160 | Pakete Rust minisign verifier; verifier varsa bypass reddedilir; secure-defaults tablosu |
| T52 | deliverd self-upgrade kendi postinst'i tarafından öldürülebilir (opt-in yol) | Teslim | M | runner.rs:441-450; postinst:165; unit'te KillMode yok | `systemd-run --scope` veya env marker; T10'daki VM job'unda test |
| T53 | deliverd ve depot RPM teslim edemiyor | Teslim | L (geçici S) | deliverd/pkg'de rpm yok; service:3-5 | RPK `rpm` türü; geçici olarak "deb-only" diye belgele |
| T54 | Paket deposu kanalı yok: rpmsign, InRelease ve repomd.xml.asc yok | Teslim, Destek | M | RELEASE:155-164 | Workflow kodu; OpenPGP anahtarı C1'de |
| T55 | SLSA/in-toto provenance yok | Satın alma, Teslim | S-M | release.yml:52-55 TODO(cosign); GAP-12 | minisign imzalı in-toto SLSA v1 ve/veya SHA-pinli attest-build-provenance; OPERATIONS §2 |
| T56 | VEX/CSAF yok; yayımlanmış tag'ler zafiyet açısından izlenmiyor | Satın alma, Destek | M | ci.yml:18-20 yalnız default branch'i tarıyor | Zamanlanmış job: tag'lerin Cargo.lock'u ve SBOM'u cargo-deny/osv-scanner ile; sürüm başına OpenVEX; CSAF üreteci |
| T57 | Dependabot/Renovate ve CODEOWNERS yok | Mühendislik | S | .github/ altında yalnız workflows/ var | dependabot.yml (cargo, actions, submodule); kripto, parser ve paketleme için CODEOWNERS |
| T58 | Fuzz derinliği yetersiz; bazı parser'ların harness'ı yok | Satın alma, Mühendislik | M | ci.yml:349-388 hedef başına 60 sn; corpus yok; uplink http.rs, kafka/sasl.rs, executor proto.rs/soc.rs için harness yok | Nightly ≥1 saat, cache'lenmiş corpus, crash issue'su; 24 saatlik kampanya; 3 yeni hedef; dokümandaki sayı fuzz/'dan üretilir |
| T59 | Overflow ve indexing lint'leri eksik | Mühendislik | L | Release profilinde overflow-checks yok; arithmetic_side_effects yalnız cdr'de; indexing_slicing diode, blackbox, seal, ocsf, firewall ve motion'da yok | Modül modül deny (diode/fec.rs önce); checked/saturating aritmetik |
| T60 | Elle yazılmış protokol/kripto envanteri eksik | Mühendislik | M | known-limitations:196-200; listede yok: SCRAM/PBKDF2/base64, uplink HTTP client, depot X.509 DER, TPMS_ATTEST, FFI | Envanter ve test oracle'ları; SCRAM için hmac/pbkdf2, base64 crate'i, libc |
| T61 | OCSF ve JSON Schema resmî validator ile doğrulanmamış; ATT&CK ICS id'leri bellekten | POC, Devreye alma, Mühendislik | M | ocsf README:160-163, :205-211; model.rs'de 7 OCSF-UNCERTAIN; contract.rs'de kendi alt-küme validator'ı | Pinlenmiş OCSF şeması, CI'da validator ve check-jsonschema 2020-12; UNCERTAIN alanların çözümü |
| T62 | SIEM entegrasyon içeriği yok | POC, Devreye alma | M | integrations/ dizini yok | Splunk add-on, Elastic pipeline, Sentinel/Logstash; imza doğrulama rehberi |
| T63 | Müşteriye dönük tespit kataloğu yok | POC | S | Bilgi rules/README, builder.rs ve crate README'lerine dağılmış | OCSF kataloğundan üretilen `detection-catalog.md` ve sapmada fail eden test |
| T64 | Tespit süresi ve SOC'a ulaşma süresi ölçülmemiş | POC | M | 4-2 gap:157 | Enjeksiyon zaman damgası → black box/spool/Kafka ack yüzdelikleri; T31'e yazılır |
| T65 | Rakiplerden farklılaşma iddiaları kanıtsız | POC | M | README:30-43 | Red-team senaryoları yalnız Pulsar'a karşı koşulur; tekrarlanabilir karşılaştırma tablosu ve battlecard |
| T66 | Robot tarafındaki anahtarlar TPM'de değil | Satın alma, Teslim, Devreye alma | L | known-limitations:174-179; GAP-04 Partial | robodr-seal veya LoadCredentialEncrypted+tpm2; dosya fallback'i status.json'da işaretlenir; swtpm testleri |
| T67 | SOC anahtarlarında aksiyon kapsamı yok; robot iki kişili onayı doğrulamıyor | Satın alma | M | GAP-07 Partial; allowed_actions yok | Anahtar başına izinli aksiyonlar ve max TTL; agentd ve executor'da zorlanır; isteğe bağlı ikinci imza |
| T68 | İlk açılış kurulumu ve host preflight kontrolü yok | Teslim | M | quick-start §2-§6 elle 12 civarı adım | `robodr-setup`: preflight (BTF, bpffs, nf_tables, systemd, glibc, saat, disk), anahtar üretimi, rol config'i, parmak izleri; install-bundle bunu çağırır |
| T69 | Destek paketi (support bundle) toplayıcısı yok | Teslim, Destek | S-M | grep 0 sonuç | `robodr-support-bundle`: sürümler, unit/journal, status.json, nft, redakte config; manifest ve SHA-256; anahtar ve kanıt asla dahil edilmez |
| T70 | Metrik endpoint'i yok | İşletim | M | Prometheus/OTel yok; GA-ROADMAP:797 | Yerel OpenMetrics veya textfile exporter ve örnek alarm kuralları |
| T71 | Çok robotlu kapasite testi yok; anchor-receiver tek instance ve statik liste | İşletim, Devreye alma | M | RESULTS (1-3 robot); anchor-receiver.rs:18-32 | Netns/konteyner filo simülatörü ile 50/500/5000; unit list reload; 50 birimlik enroll/rotate/revoke harness'ı; toplu token modu |
| T72 | Fleet API'de decommission akışı yok | EOL, Yenileme | M | fleet-api §1; robodr-enroll.rs:32-46 | İmzalı decommission-request/answer (online ve dosya modu) ve vektörler; SOC tarafı ADR-0008 kararına bağlı |
| T73 | Release yalnız main'deki tag'leri imzalıyor; LTS yaması çıkarılamıyor | Destek | S | release.yml:79, :122, :677 | Korumalı `release/X.Y` branch'lerine izin; eski hatlar için `make_latest=false` |
| T74 | Release toolchain girdileri kayıyor (Rocky clang, apt.llvm.org) | Teslim | M | BUILD:106, :202-204 | Hash'le pinlenmiş mirror; REPRODUCIBILITY dosyasına kayıt |
| T75 | Pulsar için due diligence kaydı yok | Satın alma | M | cra-readiness:60; deny.toml:25-34 | `third-party-due-diligence.md` ve her sürümde review |
| T76 | pulsard'da MemoryMax/CPUQuota yok; OOMScoreAdjust=-500 | Teslim | S | pulsard.service:65 | Limitler eklenir; nihai değerler B6 ölçümlerinden |
| T77 | Sensör kutusu imaj tarifi yok (yalnız iki örnek dosya var) | Teslim, Devreye alma | M | packaging/sensor-box/ | mkosi/debos tarifi: imzalı bundle, read-only root, first-boot anahtar üretimi. Donanım doğrulaması B7'de |
| T78 | SROS2/DDS-Security test edilmemiş | Devreye alma | L | support-matrix:51 | Konteyner lab capture'ları; permissions/governance'tan profil girdisi |
| T79 | Güvenlik anketi paketi yok (SIG Lite, CAIQ) | POC, Satın alma | M | docs/ altında yok | Kanıt linkli `security-questionnaire.md`; NDA'lı trust bundle |
| T80 | E2E, red-team ve soak testleri yalnız elle koşuluyor | Mühendislik | L | tools/e2e hiçbir workflow'da yok | Nightly root workflow; sonuç artefaktı; regresyonda fail |

### Low

| ID | Başlık | Efor | Kanıt | Çözüm |
|---|---|---|---|---|
| T81 | Her agentd başlangıcında yanlış High `control_plane_unauthenticated` (O3) | S | auth.rs:124; health.rs:62; RESULTS:472-476 | Fenced durumu ayrı sayılır; `control_plane_request_fenced` (Low/Info) |
| T82 | Gateway feed'inde flood folding ve rate limit yok (W2-5) | S | gateway_feed.rs; RESULTS:453-457 | flood.rs (rule, channel) bazında; Critical için tavan |
| T83 | Exporter state dizinleri kısmen budanıyor | S | known-limitations:242-244 | reinject ledger, rejected/ ve importer out/ budanır; boyutlar status'ta |
| T84 | Evidence inventory çağrısı agentd RSS'ini ikiye katlıyor (O2) | S | RESULTS:467-471 | Seal sırasında segment indeksi veya streaming |
| T85 | Yedekleme elle yapılan tar/age prosedürü | M | OPERATIONS §14 | `robodr-backup create\|restore` ve restore testi |
| T86 | robodr-focal arm64 non-PIE | S-M | build-static.sh:36-39 | static-pie; check-packages'ta ET_DYN kontrolü |
| T87 | executor ve firewall-gw man sayfaları yok; modules-load yok | S | man/; packaging | İki man sayfası ve modules-load.d örneği. Gateway sayfası birleşmeden sonra |
| T88 | `--version` build'i tanımlamıyor | S | agentd.rs:71, executor.rs:199 | Commit, SOURCE_DATE_EPOCH ve triple |
| T89 | MSRV job'u `continue-on-error` | S | ci.yml:252-256 | Kaldır |
| T90 | Coverage ölçümü yok | S | Yok | cargo-llvm-cov ve nextest JUnit |
| T91 | pulsar.toml'da offline check-config yok | S | ros2-pipeline config.rs:5-7 | `robodr-ros2-watch --check-config` |
| T92 | Release dry-run güncel workflow'la uyumsuz | M | RELEASE:166-168 | workflow_dispatch dry-run (geçici anahtarla, yayımlamadan) |
| T93 | Elle yazılmış HTTP sunucu ve Kafka istemcisi kritik yolda | L | ADR-0007; R8 | hyper ve bakımlı bir Kafka istemcisine geçiş, ya da dış review ve fuzz'da öncelik |

---

## 3. Bölüm B: Donanım, gerçek saha veya diğer repo gerektirenler

### B.1 Donanım ve saha

| ID | Başlık | Önem | Aşamalar | Ne koşulmalı |
|---|---|---|---|---|
| B1 | Gerçek Unitree robot ve capture yok; devreye alma hiç uçtan uca yapılmadı | blocker | POC, Devreye alma | Go2 EDU ve G1 EDU alınır, firmware pinlenir. sport/lowcmd/loco/arm trafiği yakalanır. Gerçek capture'la learn → sign-off → lock → check. Scrub edilmiş capture'lar `fixtures/captures/unitree-*` + real_captures testlerine girer. T17 durum eşlemesi doğrulanır. support-matrix V3'e çıkar |
| B2 | rt/lowcmd QoS ve komut akışı kesildiğinde motor kartı davranışı bilinmiyor (GAP-25) | blocker (inline enforce için) | Devreye alma, POC | Model başına OEM yazılı teyidi veya akış kesme ölçümü; UNITREE.md 5.1. Kod tarafı: model başına onaylanmamışsa firewall-gw check-config `enforce`'u reddeder. Observe-only POC bu arada yapılabilir |
| B3 | Saha doğrulaması yok: 72 saat soak, FP/robot/gün | blocker | İşletim, POC | Go2, G1 ve Nav2 AMR üzerinde gerçek görevde 72 saat soak2.sh. Kural bazında FP/robot-gün ölçülür (Kapı 3: <1), eşikler ayarlanır, RESULTS'a yazılır. O zamana kadar POC'ta FP sayısı vaat edilmez |
| B4 | Hedef donanımda kurulum, yükseltme ve rollback hiç yapılmadı; S12 kabul kriterleri ölçülmedi | blocker | Teslim, İşletim | Jetson Orin (JP6), JP5 EDU ve sensör kutusunda yayımlanmış bundle'larla ilk kurulum, anahtar üretimi, devreye alma, rc→rc upgrade ve rollback. Ekip dışından biri bağlantılı ve air-gap sitede <2 saat hedefini ölçer; state'in korunduğu doğrulanır |
| B5 | arm64/Jetson'da hiç koşulmadı; L4T için BTF yok; eBPF arm64'e hiç yüklenmedi | high | POC, Teslim, Devreye alma | arm64 .deb ve focal JP6/JP5'e kurulur. L4T 36.3/36.4.x için BTF üretilir ve imzalı `robodr-btf-l4t` paketi olarak sunulur. Probe ve kurallar yüklenir, olayların geldiği doğrulanır. İmaj bazında uyumluluk tablosu |
| B6 | Hedef donanımda ve RT kernel'de kaynak ve gecikme ölçülmedi (GAP-20) | high | POC, Devreye alma, İşletim | PREEMPT_RT sensör kutusu ve EDU'da soak2_monitor ve `gw_latency --budget-p99-ns`. CPU, RSS, fd ve p99 performance.md'ye yazılır. Buradan MemoryMax ve boyutlandırma kuralı çıkar; p99 devreye alma kapısı olur |
| B7 | Referans sensör kutusu donanımı ve BOM yok; inline gateway tek hata noktası | high | POC, Teslim, İşletim | 1-2 fansız SKU (≥2 Intel NIC + pasif tap) seçilir. T77 imajı doğrulanır. Watchdog bypass rölesi veya yedekli çift tasarlanır. POC için ödünç cihazlar |
| B8 | Gateway ve executor'ın saha veya OEM güvenlik doğrulaması yok | high | Satın alma, İşletim | E-stop'lu gerçek robotta p99, fail_closed ve motion adapter'ları ölçülür. Gateway FMEA ve safety-interface notu yazılır |
| B9 | TPM sealing ve NV anchor yalnız swtpm'de doğrulandı | medium | POC, Satın alma | Jetson fTPM ve ayrık TPM'li kutuda seal, PCR policy, erase ve NV anchor. Sonuçlar yayımlanır |
| B10 | Robot↔SOC gerçek ağda hiç koşulmadı; control-plane v2 ile AutoSecOps client'ı birbirine karşı hiç denenmedi | high | POC, Devreye alma | AutoSecOps bulut VM'de, agentd ve executor lab kutusunda. Akış: onay → imzalı istek → uygula → imzalı cevap → kanıtın vakaya aktarılması. Enroll da denenir. Sonra nightly çapraz repo job'u (S4). S1'e bağlı |
| B11 | Diode yalnız in-process test edildi | medium | Devreye alma | Ticari dosya diode'u üzerinden uçtan uca. 3-broker kısmı T25'te |
| B12 | RTI Connext hiç yakalanmadı | medium | Devreye alma | Değerlendirme lisansıyla rmw_connextdds capture'ları; V2 |
| B13 | Wi-Fi, hücresel ve Go2 app (WebRTC) yolu görünmüyor | medium | Devreye alma | Devreye alma ön koşulu: robot Wi-Fi'ı kapalı veya kilitli; kör nokta teklifte yazılır |

### B.2 AutoSecOps reposu (burada düzeltilemez)

| ID | Başlık | Önem | Ne yapılmalı |
|---|---|---|---|
| S1 | robot_edr/ingest yayımlanmamış branch'te; D1/D1b kanıt export'u 403 veriyor ve audit yazımı hatayı yutuyor; demo SOC yok | blocker | D1 (`robot:read` scope + gerçek token testi) ve D1b (`_record_access` hatada yüksek sesle düşmeli) düzeltilir. `claude/robodr-ingest` main'e birleştirilir. Sürümlü imajlar ve hosted demo tenant (demo robotlar, örnek vaka) kurulur |
| S2 | Fleet API ve konsolu bitmemiş: enroll, rotate, CRL push, profil dağıtımı robot başına elle | high | Konsol yayımlanır. Bu repodaki parçalar: T71 harness'ı ve seal sınırında online black box rotation |
| S3 | SOC'ta robot sağlık görünümü ve alarm kuralı yok | high | T5 kaydını tüketen sağlık sayfası, "robot sessiz > N dk" kuralı ve sertifika bitiş görünümü |
| S4 | Çapraz repo kontrat CI'ı yok | high | Pinlenmiş AutoSecOps imajıyla ingest, fleet ve control-plane vektör testleri; T8 ve T5 kontrat bump'larının koordinasyonu |

---

## 4. Bölüm C: Sahip kararları (hukuk, ticari, süreç, insan)

| ID | Başlık | Önem | Aşamalar | Karar / iş |
|---|---|---|---|---|
| C1 | Anahtar seremonisi yok; hiç imzalı sürüm yok | blocker | Tüm aşamalar | RELEASE §2'ye göre iki kişilik air-gapped root ve release anahtarı. `release` environment'ı: secret, ROBODR_MINISIGN_PUBKEY, ROBODR_MAINTAINER, reviewer'lar, v* tag ruleset. Anahtar saklama politikası seçilir: süre sınırlı CI anahtarı ya da offline HSM/YubiKey. OpenPGP repo anahtarı ve RPK 2-of-N anahtarları da bu seremonide. Sonra T1 ve C2 tamamlanınca v0.1.0-rc.1 çıkar; root pub out-of-band teslim edilir |
| C2 | Release'e hazır kod main'de değil (origin/main'den 50 commit ileride) | high | Teslim | Gateway düzeltmeleri birleşince PR açılır, CI yeşil olur, merge edilir, release main'den kesilir |
| C3 | Hukuki çerçeve yok: LICENSE hiçbir hak vermiyor; EULA/SLA taslak; değerlendirme lisansı, NDA, DPA ve sipariş formu yok | blocker | POC, Satın alma, Yenileme, EOL | Master lisans, POC/değerlendirme lisansı (geri bildirim, capture ve black box kanıtının işlenmesi, gateway/executor güvenlik feragati), karşılıklı NDA. DPA. EOL sonrası doğrulama araçlarını kullanma hakkı. Pakette lisans işaretçisi |
| C4 | Fiyat ve lisans modeli yok: ADR-0008 "Proposed"; max_robots ve kota aşımı belirsiz; kullanım/true-up raporu yok | blocker | POC, Yenileme | Robot başı + SOC katmanı fiyatı ve POC→ücretli dönüşüm teklifi. ADR-0008 kabul edilir (kota aşımında bulgular asla düşürülmez). AutoSecOps'ta üretim lisans anahtarı. Air-gap siteler için imzalı kullanım beyanı |
| C5 | Destek süresi ve LTS belirsiz; SECURITY.md'deki 6 ay, CRA'nın ≥5 yıl beklentisiyle çelişiyor | blocker | Satın alma, Destek | Major sürüm başına ≥5 yıl güvenlik yaması; SECURITY.md, SLA §4, EULA ve CHANGELOG'da EOL tarihleri |
| C6 | CRA 24 saat/72 saat ENISA raporlama prosedürü ve sahibi yok; yükümlülük 11 Eyl 2026'dan beri geçerli | blocker (AB) | Satın alma, Destek | Koordinatör CSIRT, runbook, şablonlar, ENISA hesabı, sahip ve vekil; tatbikat |
| C7 | İhracat kontrolü: sınıflandırma kaydı yok; ADR-0010 sealing'i (XChaCha20-Poly1305) kapsamıyor | blocker | Satın alma | seal, TLS ve secure delivery dahil yeniden inceleme. 5A002/5D002 veya Note 3 kararı ADR-0010'a. EULA'ya ve teklif şablonuna madde; satış süreçlerine tarama |
| C8 | Dış pentest ve insan güvenlik incelemesi yok (incelemeler yalnız AI ajanlarıyla yapıldı) | blocker | POC, Satın alma, Mühendislik | Kapsam: control plane v2, executor, gateway, uplink/enroll/ingest, seal/depot, install-bundle, release pipeline, elle yazılmış HTTP/Kafka/RS. Critical ve High bulgular kapatılır; NDA altında attestation mektubu |
| C9 | PSIRT çalışmıyor: dışarıdan bildirim kanalı yok, roller boş, CNA yok, tatbikat yok; private vulnerability reporting kapalı | blocker | Satın alma, Destek | security@ adresi ve PGP, RFC 9116 security.txt, private reporting'in açılması, advisory sayfası, CVSS v4 ve fiziksel etki modifier'ı, tracker, tatbikat |
| C10 | Destek işletim modeli yok: SLA rakamları yer tutucu, on-call yok, ticket sistemi yok, analist runbook'u yok; paketlerde `robodr-maintainers@invalid` | blocker | İşletim, Destek | Katmanlar ve hedef süreler, nöbet rotası, destek portalı, rule-family bazında runbook'lar; DEB_MAINTAINER, quick-start ve SECURITY.md'de gerçek iletişim |
| C11 | CRA ürün sınıfı ve uygunluk yolu belirsiz; teknik dosya ve DoC yok | high | Satın alma, Destek | Annex III/IV için hukuki görüş (firewall/IDS sınıfı olabilir). Sürüm başına teknik dosya indeksi. Sınıf gerektirirse notified body; son tarih 11 Ara 2027 |
| C12 | Makine Yönetmeliği 2023/1230 ve PLD 2024/2853 değerlendirmesi yok | high | Satın alma | Gateway'in Annex II anlamında güvenlik bileşeni olup olmadığı ve PLD yazılım sorumluluğu için görüş. safety-positioning ve EULA'ya yazılır. Gerekirse inline mod OEM onaylı entegrasyonlarla sınırlanır |
| C13 | Tescilli ürün kaynağı public GitHub reposunda (REST ile doğrulandı) | high | Mühendislik, Satın alma | Private yap (arm64 runner bütçesiyle) ya da source-available lisansa geç. Geçmiş secret ve capture için taranır. Dokümanlardaki "private" ifadeleri düzeltilir |
| C14 | Müşteri dağıtım ve advisory kanalı yok | high | Satın alma, Teslim, Destek | Kimlik doğrulamalı portal veya registry; imzalı apt/dnf hosting; public advisory sayfası. Workflow tarafı T54 |
| C15 | Pre-sales ve solutions engineering kapasitesi yok | high | POC | Tasarım ortaklarına SE atanır. T28 ve S1 üzerine 30 dakikalık senaryolu demo |
| C16 | Eğitim, doküman sitesi, entegratör materyali ve devreye alma hizmet paketi yok | high | Devreye alma, Destek | Rol bazında doküman sitesi; lab üzerinde kurs; fiyatlı devreye alma paketi ve FAE |
| C17 | FP toleransı ve monitor eşikleri karara bağlanmamış | high | Devreye alma, POC | FP hedefi, gecikme ve kalıcılık pencereleri; varsayılanlara yazılır, B3'te ölçülür |
| C18 | 62443-4-1 SDL plan, isimli güvenlik sorumlusu, eğitim kaydı ve kodlama standardı yok | high | Satın alma | Dokümanlar repoda taslaklanabilir; isimler gerekir |
| C19 | 62443 uyumu yalnız öz-değerlendirme | medium | Satın alma | Danışman doğrulaması, SL-C hedefi; GA sonrası ISASecure veya TÜV |
| C20 | GPL-2.0 kaynak teklifindeki iletişim adresi onaylanmadı | medium | Satın alma, Teslim | Hukuk sabit posta ve e-posta adresini onaylar; ardından third_party_notices.py:569 ve EULA güncellenir |
| C21 | POC nitelendirme listesi yok | medium | POC, Devreye alma | RMW (Zenoh, SHM), SROS2, Wi-Fi/WebRTC, tap imkânı, OEM modeli; teklif kapsam dışı maddeleri |

---

## 5. Bölüm D: Devam eden işler

- **Motion gateway review düzeltmeleri (branch'te, birleşmemiş):**
  - INFO_DST / sahte SEDP downgrade (CRITICAL)
  - writer-map eviction
  - Go2 obstacles_avoid ve uwbswitch codec'leri
  - TwistStamped ileri tarihli stamp
  - kp=0 step-limit bypass'ı
  - sport/HighCmd için default-deny
  - builtin entity id'leri
  - restrict TTL için monotonic saat
  - state_file izinleri
- **Gateway birleşmesini bekleyen işler** (firewall-gw dosyalarına dokunuyor): T8 (emisyon kısmı), T11 (gateway tarafı), T19, T43, T44, T82, T87 (gateway man sayfası).
- **CI:** Run 41136491301 tamamlandı ve kırmızı. Görevdeki "devam ediyor" bilgisi güncel değil. T1a-d bunu kapatır.
  - Geçen işler: amd64 ve arm64 .deb, iki musl build, reproducible, SBOM, Pulsar-bound, MSRV.
  - main'deki önceki iki run (41079445905, 40479312736) billing hatasıyla düşmüştü.

---

## 6. Bölüm A için uygulama sırası (paralel iş paketleri)

**Faz 0 (hemen, 2 kişi; her şeyin ön koşulu)**

| Paket | Kalemler | Dosyalar |
|---|---|---|
| WP0a | T1a, T1d | Cargo.toml, Cargo.lock, deny.toml; crates/robodr-seal, robodr-depot, robodr-release (p256 kullanımı); fuzz/ |
| WP0b | T1b, T1c | crates/robodr-deliverd/tests/common/mod.rs; ci.yml'deki rpm job'u; scripts/ci-setup.sh, ci-install-rustup.sh |

**Faz 1 (paralel)**

Kural: `crates/robodr-agentd/src/config.rs` ve `crates/robodr-ocsf` katalogu ortak sıcak dosyalar. Yeni bulgu id'lerinin tamamı WP2'de tek bir kontrat bump'ı olarak eklenir. Diğer paketler kendi config bölümlerini ayrı modülde tanımlar; config.rs'e ekleme tek bir küçük PR'da toplanır.

| Paket | Kalemler | Dosya sahipliği |
|---|---|---|
| WP1a Müşteri dokümanları | T2, T3, T31, T63 (doküman), T48 (doküman), T29, T38 (tablo) | README.md, docs/customer/*, docs/BUILD.md, docs/RELEASE.md (yalnız düzeltme bölümleri) |
| WP1b Uyum dokümanları | T4, T21, T22, T75, T79 | docs/compliance/*, SECURITY.md, docs/GA-ROADMAP.md, docs/adr/* (yalnız metin), scripts/check-doc-facts.py |
| WP1c Operasyon dokümanları | T35 (doküman), T47 (şablon), executor README, decision.rs/engine.rs yorumları (T2'nin kod-yorumu kısmı) | docs/OPERATIONS.md, docs/UNITREE.md, crates/robodr-executor/README.md. Yorum değişiklikleri WP5 ile sıralanır |
| WP2 Sağlık ve kontrat | T5, T6, T7, T40, T41, T45, T38 (producer cap); T8, T81, T13 rule id'leri | crates/robodr-ocsf (catalog, model.rs), docs/contracts/robodr.findings.md + ingest-api, crates/robodr-agentd/src/{health.rs, host.rs, daemon.rs status}, crates/robodr-export uplink ve diode health gönderimi |
| WP3 Control plane | T39, T81, T67 (agentd kısmı) | crates/robodr-agentd/src/control/{mod.rs, auth.rs} |
| WP4 Black box | T15, T84, T85 | crates/robodr-blackbox (store.rs, yeni export-pending ve backup bin'leri), packaging/systemd timer |
| WP5 Executor | T18, T42, T67 (executor kısmı) | crates/robodr-executor/src/motion/{adapters, rtps, mavlink}.rs, proto.rs, soc.rs; tools/e2e peer konteynerleri |
| WP6 Devreye alma ve imza | T11 (commission ve agentd kısmı), T12, T47 (renderer), T48 (`poc-init`) | crates/robodr-commission, profile_trust modülü, agentd policy yükleme, executor motion/mod.rs config yükleme (WP5'le aynı crate, farklı dosya) |
| WP7 Capture ve parser | T14, T33, T78, T91, T37 (uzun vadeli) | crates/robodr-capture, crates/robodr-rtps, crates/robodr-ros2-pipeline, tools/lab-capture, fixtures/captures/ |
| WP8a Kurulum yolu | T9, T50, T51 | packaging/install-bundle.sh, packaging/deb/{postinst, prerm}, packaging/rpm/post, verifier (robodr-release veya robodr-pkg içinde) |
| WP8b Yeni araçlar ve paket içeriği | T68, T69, T70, T49, T76, T77, T87 (executor sayfası) | yeni robodr-setup, support-bundle ve metrics araçları; packaging/build-deb.sh (doküman ve demo kurulumu), packaging/systemd/robodr-pulsard.service, packaging/sensor-box/, man/ |
| WP9a CI workflow | T10, T24, T25 (CI), T26, T27, T80, T89, T90, T57, T58 (nightly workflow ve hedefler) | .github/workflows/ci.yml, yeni nightly-*.yml, .github/dependabot.yml, CODEOWNERS, fuzz/fuzz_targets (yeni hedefler) |
| WP9b Release workflow | T20, T23, T34, T54, T55, T56, T73, T74, T86, T88, T92 | .github/workflows/release.yml, scripts/metadata_to_cyclonedx.py, scripts/build-static.sh, scripts/release-dry-run.sh, gha-local-run.py, build.rs |
| WP10 POC ve demo | T28, T30, T32, T64, T65, T62, T61, T63 (generator) | yeni demo/, yeni robodr-attack-sim, yeni robodr-demo-soc (export/tests/common'dan kopya), benches/, integrations/, tools/e2e rapor script'leri, crates/robodr-ocsf/tests (yalnız test dosyaları) |
| WP12 Unitree ve bağlam | T17, T46 | yeni crates/robodr-agentd/src/safety_feed/ modülleri, config/*unitree*.example.json |
| WP13 Filo | T72, T71, T13 (`--check` bayrakları), T35 (enroll.rs referansı) | crates/robodr-fleet, docs/contracts/robodr.fleet-api.md, exporter, enroll ve anchor-receiver bin'lerinin argüman parse kısmı |
| WP14 Delivery | T52, T53 | crates/robodr-deliverd (runner.rs, install.rs), crates/robodr-pkg |
| WP15 Anahtar sağlayıcıları | T36, T66 | yeni signer crate'i, crates/robodr-seal entegrasyonu; commission ve release yalnız signer çağrısıyla değişir |
| WP16 Kafka | T25 (KIP-360), T60 (SCRAM/base64/libc), T83 | crates/robodr-export/src/kafka/{client.rs, sasl.rs}, retention modülü |

**Faz 2 (gateway düzeltmeleri birleştikten sonra)**

| Paket | Kalemler | Dosyalar |
|---|---|---|
| WP11 Gateway | T8 (emisyon), T11 (gateway yükleme), T19, T43, T44, T82, T87 (gateway man sayfası) | crates/robodr-firewall-gw, crates/robodr-agentd/src/gateway_feed.rs |

**Faz 3 (diğer paketler indikten sonra, crate sahipleri tarafından)**
- T59: crate crate lint sıkılaştırması.
- T93: HTTP/Kafka kütüphane değişimi; dış review sonucuna göre.

**İlk iki haftanın satış önceliği:**
1. WP0
2. WP1a ve WP1b (T2-T4)
3. WP2 (T5)
4. WP11 öncesi hazırlık olarak T8'in kontrat kısmı
5. WP10 (T28, T29, T31)
6. WP9b (T20, T23)

Bunlar C1 ve S1'le birlikte ilk değerlendirilebilir imzalı sürümü ve POC'u açar.