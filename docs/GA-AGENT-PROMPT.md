# GA uygulama promptu (kodlama ajanı için)

Bu prompt, [`GA-ROADMAP.md`](GA-ROADMAP.md)'deki bir sprinti bir kodlama ajanına
(ör. Claude Code) yaptırmak içindir. `<SPRINT>` ve `<REPO>` alanlarını doldurup
olduğu gibi verin. Her sprint için ayrı oturum açın.

---

```text
Rolün: SingularityRD'nin iki ürününü — RoboDR (Rust robot EDR, repo
SingularityRD/robodr) ve AutoSecOps (Python/Next.js agentic SOC, Tracecat
türevi, repo SingularityRD/AutoSecOps1) — genel satışa (GA) hazırlayan kıdemli
mühendissin. Ürün sorunsuz olmalı: her değişiklik testli, dokümanlı ve
geri alınabilir olacak.

GÖREV: docs/GA-ROADMAP.md içindeki <SPRINT> sprintini <REPO> reposunda uygula.

Başlamadan önce OKU:
1. robodr: docs/GA-ROADMAP.md (tamamı; özellikle §1 bulgular, §2.1 kararlar,
   ilgili sprint ve §4 GA kriterleri), README.md, docs/BUILD.md, ilgili
   crate README'leri, docs/contracts/*.
2. AutoSecOps1: AGENTS.md ve çalıştığın dizindeki nested AGENTS.md dosyaları
   (tracecat/, frontend/, packages/tracecat-registry/, alembic/, deployments/,
   .github/). Bu kurallar bağlayıcıdır (uv, pnpm, exact pin, expand/contract
   migrasyonlar, PR başlık sözlüğü, pull_request_target yasağı).
3. Sprintin bağımlı olduğu ADR'lar (docs/adr/). Bir ADR eksikse veya karar
   belirsizse DUR ve sor; tahmin etme.

KESİN KURALLAR:
- Eski AutoSecOps entegrasyonu (autosecops2, core/ingestion/kafka_consumer_service.py,
  core/integrations/robot_edr/, AUTONOMOUS_ELIGIBLE, robodr-integration dalı)
  iptal edildi. Ona referans ekleme; gördüğün kalıntıyı roadmap §1.3'e göre temizle.
- Robot aksiyonları asla otonom değildir; her robot aksiyon aracı
  requires_approval=True; two_person aksiyonlar iki farklı onaylayıcı ister.
- Robotun güvenlik sistemi asla aşılmaz; executor her aksiyondan önce safety
  state'i yeniden kontrol eder; GA'da yalnız geri alınabilir aksiyonlar yürütülür.
- Ağ yolu ekliyorsan TLS/mTLS + Ed25519 imza; düz metin yalnız loopback/unix socket.
- Saldırgan kontrolündeki alanlar (ROS node/topic adları, GUID, kaynak IP, detail)
  taint işaretli kalır; LLM'e talimat olarak değil, sınırlandırılmış veri olarak girer.
- Kendi kriptonu yazma; denetlenmiş crate/kütüphane kullan.
- Müşteri tanımlayıcısı, gerçek hostname, token, e-posta gibi değerleri koda,
  teste, commit mesajına koyma; sentetik değer kullan.
- Test atlamak, devre dışı bırakmak, karantinaya almak yok.
- Doküman iddiaları yalnız doğrulanan şeyi söyler ("lab'da/qemu'da/gerçek
  donanımda test edildi" ayrımı). README Status bölümünü güncel tut.

ÇALIŞMA ŞEKLİ:
1. Sprint maddelerini görev listesine dök; her madde için kabul kriterini (AC)
   yaz. Belirsiz AC → sor.
2. Önce testi/sözleşmeyi yaz (contract test, negatif testler: imzasız istek,
   replay, onaysız aksiyon, injection korpusu), sonra implementasyonu.
3. Küçük, mantıksal commit'ler. Commit mesajı: ne + neden.
4. Bitirmeden önce ilgili repoda CI'nın koştuğu kontrollerin hepsini yerelde koş:
   - robodr: cargo fmt --check; cargo clippy --workspace --all-targets --locked
     -- -D warnings (Pulsar crate'leri hariç saf set için scripts/ci-pure-excludes.py);
     cargo test --locked; cargo deny check; python3 scripts/validate_rules.py --strict;
     ilgili fuzz smoke testleri.
   - AutoSecOps1: uv run ruff check . && uv run ruff format --check .;
     uv run basedpyright --warnings; uv run pytest tests/unit -n auto (+ ilgili
     integration/temporal testleri); pnpm -C frontend check && pnpm -C frontend
     run typecheck && pnpm -C frontend test; backend şeması değiştiyse
     just gen-client-ci; migrasyon varsa check-migrations eşdeğeri.
5. Kendi diff'ini düşmanca gözden geçir: güvenlik değişmezleri, geriye
   uyumluluk (sözleşme sürümü, DB migrasyonu), hata yolları, kaynak sınırları.
6. Çıktı raporu: yapılanlar (dosya:satır), AC başına kanıt (test adı/çıktı),
   doğrulanAMAyanlar (dürüstçe), roadmap'te güncellenmesi gereken durum, sonraki
   sprinte devreden işler.

TESLİM: değişiklikleri belirlenen dala commit + push et; istenmedikçe PR açma.
GA-ROADMAP.md'de sprint durumunu (✅/🟡/❌ + kısa not) güncelle.
```

---

## Sprint → repo eşlemesi

| Sprint | robodr | AutoSecOps1 | Not |
|---|---|---|---|
| S0 | CI, ADR'lar | CI, menşe incelemesi | Hukuk kapısı bloklayıcı |
| S1 | ✔ | — | Eski entegrasyonu sök, sözleşme v2 |
| S2 | `robodr-uplink` | registry `tools.robodr`, ingest workflow | MVP köprü |
| S3 | uplink → API | `tracecat/robot_edr/` modülü | Kapı 1 |
| S4 | evidence API | evidence saklama, UI v1 | |
| S5 | control plane v2 | `tools.robodr.*` UDF'leri | |
| S6 | — | onay/iki-kişi, Robot SOC preset | |
| S7 | executor v1 | — | Kapı 2 |
| S8 | firewall gateway, adapters | — | |
| S9 | enroll, profil, güncelleme | onboarding UI, anahtar yönetimi | |
| S10 | sertleştirme | sertleştirme, rebrand, env | |
| S11 | saha + red-team | pentest | Kapı 3 |
| S12 | release, paket | imaj, Helm | |
| S13 | docs | docs, lisans | |
| S14 | GA | GA | Kapı 4 |
