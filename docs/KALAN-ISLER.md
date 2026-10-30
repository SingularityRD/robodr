# RoboDR + AutoSecOps: kalan işler (2026-10-30)

Ajanlarla devam etmek için ayrıntılı görev tanımı: `docs/HANDOFF.md`.

Durum: RoboDR main b05b271, AutoSecOps main 056e2fb. W2-4 ve W2-5 düzeltildi
ve çalışma dalına birleştirildi (8d064e2), main'e değil. İnceleme bulguları
bekliyor (docs/HANDOFF.md, P0).

## A. Yazılımla kapatılabilecekler (ajanlarla yapılabilir)

1. **W2-4 yavaş bağlantı saldırısı.** İlk düzeltme çalışma dalında (8d064e2),
   ama bağımsız inceleme 4 orta seviye açık buldu: tek bir tam ClientHello
   ile süre sınırı atlatılabiliyor, dolgulu bağlantı yağmuru güvenlik
   merkezinin bağlantısını düşürebiliyor, sessiz kaynak muafiyeti ve kaynak
   tablosu doluluğu hız sınırını boşa çıkarıyor. Bu açıklar ancak güvenlik
   merkezi öncelikli listede değilse geçerli. Bundan sonra:
   - incelemenin bulguları düzeltilecek (ayrıntılar ve PoC'ler:
     docs/HANDOFF.md P0, tools/e2e/review-w2-4/);
   - iş RoboDR'a birleştirilip PR açılacak;
   - `robot.agent.control_plane_pressure` AutoSecOps'a eşitlenecek.
2. **W2-5 ağ geçidi bildirim hattı.** Düzeltildi, ama incelemede bir sorun
   çıktı: gürültülü kurallar kritik bir bulguyu 60 saniyeye kadar
   geciktirebiliyor. Bu da P0'da düzeltilecek.
3. **Saha deposu anahtarları.** Diskte dosya olarak duruyor; TPM ya da HSM'ye
   taşınmalı (PKCS#11 / TPM ile imzalama).
4. **14c: işletim sisteminin A/B güncellemesi.** Disk görüntüsü türü,
   güncelleyici ve açılış hatasında eski sürüme dönüş. Sanal makinede
   yapılabilir; gerçek donanım ayrı iş.
5. **Silme tetikleyicileri.** Kiralama süresi dolunca otomatik silme ve imzalı
   uzaktan silme komutu bağlı değil (SECURE-DELIVERY §11 madde 7).
6. **Tek saha deposu sınırı.** Bir sahada birden fazla depo ya da yedekli
   depo yok.
7. **Ölçülmüş önyükleme.** TPM kanıtında olay günlüğü (event log)
   doğrulaması yok; yalnızca PCR değerleri karşılaştırılıyor.
8. **Kayıt anahtarıyla taban düşürme.** Robotta kök yetkisi ve kayıt anahtarı
   olan biri, eski sürüme dönüşü engelleyen tabanları düşüren yeni bir kayıt
   yazabiliyor (13b'den kalma).
9. **Go1 sıkıştırılmış durum mesajı** (LowState, 807 bayt) çözülmüyor.
10. **JetPack 5'te pulsard yok.** Eski glibc ve BTF'siz çekirdek yüzünden;
    harici BTF ile denenebilir.
11. **agentd'nin pasif yakalaması WebRTC'yi izlemiyor.** WebRTC yalnızca satır
    içi ağ geçidinde izleniyor.
12. **Ağ geçidi:** birden fazla DATA paketine bölünmüş yörüngeler, Fast DDS
    servis istekleri, MAVLink imzalı çerçeveler ve ACKNACK işleme yok.
13. **Kısıtlama sınırları.** `restrict_motion` alt seviye `LowCmd`, kol ve el
    kanallarını kısıtlamıyor. Unitree'de kısıtlama geri alınınca hız seviyesi
    eski değerine değil 0'a dönüyor.
14. **Nav2 ve PX4 duraklatması kalıcı değil.** Başka biri yeni bir hedef ya
    da mod verirse duraklatma kalkabiliyor.
15. **Geri alınamaz aksiyonlar.** `request_safe_state` ve `rollback_config`
    katalogda hâlâ "sadece plan" olarak duruyor. Bu bir politika kararı (ADR).
16. **RPM imzası ve paketleme.** RPM'ler OpenPGP ile imzalı değil ve RPM için
    çevrimdışı paket (bundle) yok. Sürüm provası (`release-dry-run`) yeni
    konteyner işlerini kapsamıyor.
17. **Uzun fuzz kampanyası.** Yeni fuzz hedefleri yalnızca kısa denemeyle
    koşuldu; uzun libFuzzer kampanyası yapılmadı.
18. **72 saatlik dayanıklılık testi** yapılmadı. Ayrıca Kafka SASL, broker'ın
    yeniden başlaması ve `robodr-depot serve` ikilisi dayanıklılık testinde
    yoktu.
19. **AutoSecOps uçtan uca alma testi (R7)** bu turda yeniden koşulmadı.
20. **Yanıltıcı bulgu adı.** Aşırı yük altında geç kalan paket "internal_fault"
    olarak raporlanıyor; ad yanıltıcı.
21. **Açılış bulgusu.** agentd açıldıktan sonraki ilk 30 saniyede güvenlik
    merkezinden gelen istek reddediliyor ve bu ret saldırı gibi görünen yüksek
    önemli bir bulgu üretiyor; dili düzeltilmeli.
22. **Onaylayan adları.** Aynı posta kutusunun takma adları (`bob+1@` ve
    `bob+2@`) robotun iki kişilik kontrolünü geçiyor. AutoSecOps değişmeyen
    kullanıcı kimliği gönderiyor, ama başka bir güvenlik merkezi entegrasyonu
    bu kontrolü atlatabilir.
23. **AutoSecOps uyarıları ve ayarları.**
    - Main dalında GitHub 4 bağımlılık açığı uyarısı gösteriyor (1 yüksek).
      Bunlara bakılmalı.
    - Yerel `.env` dosyası eski `TRACECAT__` adlarını kullanıyor.
24. **Ek modüller (kodu hiç yok).**
    - Sentinel Box: ABB, KUKA, FANUC, Yaskawa, OPC UA.
    - Bus Tap: CAN, EtherCAT, MAVLink, MIL-STD-1553.
    - Lite SDK (RTOS).
    - Zenoh ve SROS 2 çözümü.
    - AI Guard.
    - MSSP ve OEM sürümü.
    - Ölçülmüş önyükleme kanıtı (Keylime).

## B. Yazılımla kapatılamayanlar (karar, satın alma, donanım)

1. **CI faturalaması.** RoboDR'da GitHub Actions faturalamasını açmak ya da
   self-hosted runner kurmak gerekiyor. Ardından CI main'de baştan çalıştırılmalı.
2. **Gerçek donanımda doğrulama:**
   - Go2 EDU, G1 EDU ve bir Nav2 robotu;
   - hedef sensör kutusu, gerçek zamanlı çekirdek, arm64 ve Jetson;
   - gerçek TPM ve gerçek üretici EK sertifika zinciri;
   - gerçek kurcalama sensörü ve gerçek veri diyotu.
3. **Ölçümler.** Gecikme hedefi (p99 < 1 ms) ve yanlış alarm hedefi (robot
   başına günde 1'den az) sahada ölçülmeli.
4. **Üretici teyidi.** Unitree `rt/lowcmd` QoS'u, motor kartının akış
   kaybındaki davranışı ve A2/AS2'nin gerçek mesaj türü.
5. **Anahtar töreni ve üretim lisans anahtarı.** Sürüm imzalama anahtarları
   (minisign kök ve sürüm anahtarı) için tören yapılmalı; AutoSecOps için
   üretim lisans anahtarı oluşturulmalı.
6. **Hukuk ve uyum.**
   - EULA, SLA ve PSIRT onayı.
   - CRA sorumlusu.
   - Destek süresi.
   - Fiyat.
7. **Sertifika ve pentest.**
   - IEC 62443-4-2 ve benzeri sertifikalar.
   - Bağımsız insan pentesti.
8. **Ortaklıklar.** Spot, Digit, Figure gibi robot üreticileriyle ortaklık.
9. **Ürün kararları.**
   - İzleme toleransları.
   - Geri alınamaz aksiyon politikası (A.15).
