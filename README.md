<div align="center">

# Taygun

**Cloaker arkasında gizlenen black page'leri ortaya çıkaran komut satırı aracı.**

Tek bir hedef URL'yi 25 farklı ziyaretçi profili ile (insan + arama motoru botları + sosyal medya önizleme botları + reklam tıklama simülasyonları + Türkiye CERT/BTK imzaları + farklı coğrafyalar) eş zamanlı olarak çeker, içerik parmak izlerini karşılaştırır, sapma sinyallerini ağırlıklandırarak risk skoruna dönüştürür. İsteğe bağlı olarak her profil için **headless Chrome ile ekran görüntüsü** alır.

[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macOS-lightgrey)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## Cloaking nedir, neden tespit gerekir?

Cloaking, aynı URL'nin ziyaretçinin kim olduğuna (User-Agent, IP, coğrafi konum, referer, cookie, JS challenge sonucu) bakarak **iki tamamen farklı sayfa** sunmasıdır:

- **White page** — Google, antiphishing tarayıcıları, güvenlik araştırmacıları, reklam ağı denetleyicileri görür. Genellikle masum bir e-ticaret, blog veya kurumsal site klonu.
- **Black page** — Reklamı tıklayan gerçek kurban görür. Genellikle banka / market / kargo / e-devlet sahteciliği, kart bilgisi veya OTP toplayan form.

Taygun, aynı URL'yi farklı kimliklerle ziyaret ederek bu iki sayfa arasındaki farkı **ölçer ve sınıflar**. Phishing avcıları, takedown ekipleri, threat intelligence analistleri ve ödeme kartı dolandırıcılığı araştırmacıları için tasarlandı.

## Özellikler

- **25 ziyaretçi profili**: 3 insan tarayıcı + 7 arama motoru botu + 7 sosyal medya/önizleme botu + 3 Türkiye CERT/BTK imzası + 4 reklam tıklama simülasyonu + 1 yabancı IP profili
- **3 eksenli imza**: User-Agent + Referer + (X-Forwarded-For / CF-IPCountry / Sec-CH-UA) coğrafi başlıkları
- **Eş zamanlı çekim**: Konfigüre edilebilir paralel istek sınırı, her profilin kendi cookie jar'ı
- **Tam yönlendirme zinciri**: Her hop, her Set-Cookie, final URL kayıt altında
- **DOM tabanlı parmak izi**: title, meta description, H1 listesi, form action'ları, password input varlığı, iframe kaynakları, script host listesi
- **Marka sızıntı tespiti**: 50+ Türk bankası / market / kargo / e-devlet markası için içerik tarama (özelleştirilebilir)
- **Şüpheli JS kalıpları**: kart numarası, CVV, OTP, TCKN, Telegram bot exfiltration desenleri
- **Risk skorlama**: 0–100 arası ağırlıklı skor, dört kademeli verdict (TEMİZ / ZAYIF FARK / ŞÜPHELİ / CLOAKING TESPİT EDİLDİ)
- **Diagnostic katmanı**: Cloaking görülmediğinde "neden görmedik" sorusuna kantitatif cevap
- **Headless Chrome screenshot** (`-screenshot`): Her profil için PNG; saf HTTP'nin göremediği JS-render sonrası black page'leri yakalar
- **JSON rapor**: CI/pipeline entegrasyonu için makine okunabilir çıktı
- **Body dump**: `-dump` ile her profilin HTML'sini diske kaydet, manuel diff için
- **Toplu tarama**: `-file` veya `-stdin` ile bir liste üzerinde otomasyon
- **Tek binary**: CGO yok, Linux + Windows + macOS

## Önemli uyarılar

> **Path doğruluğu — %100 güvenilirlik vermez.**
> Cloaker'ın aktif olduğu URL genellikle `/`, `/index.php`, `/Indirim/index.php` gibi spesifik bir path olabilir. Yanlış path'te 404 dönmesi cloaking yokluğu anlamına **gelmez**; o endpoint pasiftir. Aday path'leri (ana sayfa + reklamdaki tam URL + yaygın phishing landing'leri) ayrı ayrı tarayın. Tek path taraması veya tüm yanıtların aynı dönmesi tek başına temiz raporu vermez — diagnostic bölümü olası kör noktaları listeler.

> **USOM / TR-CERT / BTK profilleri sentetiktir.**
> Bu üç profil, USOM (Ulusal Siber Olaylara Müdahale Merkezi) veya BTK'nın resmî tarayıcı imzaları **DEĞİLDİR**. Kamuya açık bir resmî USOM crawler User-Agent'ı yoktur ([USOM-Blocklists](https://github.com/elliotwutingfeng/USOM-Blocklists) sadece statik liste yayınlar). Bu profiller yalnızca `USOM`, `TR-CERT`, `.gov.tr` anahtar kelimelerine reaktif paranoid cloaker'ları tetiklemek üzere tasarlanmıştır.

## Kurulum

### Hazır binary (önerilen)

[Releases sayfasından](../../releases/latest) işletim sisteminize uygun arşivi indirip çıkartın.

### Go ile kurulum (Go 1.26+)

```bash
go install github.com/Mert-Zengin/taygun@latest
```

### Kaynaktan derleme

```bash
git clone https://github.com/Mert-Zengin/taygun.git
cd taygun
go build -o taygun .
```

Cross-compile:

```bash
GOOS=linux   GOARCH=amd64 go build -o dist/taygun-linux-amd64
GOOS=linux   GOARCH=arm64 go build -o dist/taygun-linux-arm64
GOOS=windows GOARCH=amd64 go build -o dist/taygun-windows-amd64.exe
GOOS=darwin  GOARCH=arm64 go build -o dist/taygun-darwin-arm64
```

### Screenshot için ön koşul

`-screenshot` özelliği headless Chrome/Chromium kullanır:

- **Linux**: `apt install chromium-browser` veya `apt install google-chrome-stable`
- **Windows**: Google Chrome veya Microsoft Edge yüklü olması yeterli (otomatik bulunur)
- **macOS**: `brew install --cask google-chrome`
- Özel yol için: `taygun -screenshot -chrome-path "/path/to/chrome"`

## Kullanım

### Tek hedef

```bash
taygun -url https://supheli-site.example/
```

### Birden fazla path'i sırayla tara

```bash
taygun -url https://supheli-site.example/
taygun -url https://supheli-site.example/Indirim/index.php
taygun -url https://supheli-site.example/login.php
```

### Toplu tarama + JSON rapor

```bash
taygun -file phishing_listesi.txt -json rapor.json -timeout 20s
```

### Pipe / stdin

```bash
echo "https://supheli-site.example" | taygun -stdin -quiet
```

### Body + screenshot dump

```bash
taygun -url https://supheli-site.example -screenshot -dump ./kanıt
# ./kanıt/supheli-site.example_<timestamp>/
#   Human_Chrome_(Windows).html + .png
#   Googlebot_Desktop.html + .png
#   USOM_Inspector_(sentetik).html + .png
#   ... (25 profil × 2 dosya)
```

### Tüm bayraklar

```
-url string                Tek hedef URL
-file string               Her satırda bir URL içeren dosya
-stdin                     URL'leri stdin'den oku
-json string               JSON rapor dosyası
-dump string               Profillerin HTML gövdelerini bu klasöre dök
-screenshot                Her profil için headless Chrome ile PNG ekran görüntüsü al
-screenshot-timeout        Screenshot başına zaman aşımı (varsayılan 30s)
-screenshot-parallel int   Eş zamanlı screenshot sayısı (varsayılan 2)
-chrome-path string        Chrome/Chromium binary yolu (boşsa otomatik)
-timeout duration          Tek HTTP isteği zaman aşımı (varsayılan 15s)
-concurrency int           Eş zamanlı HTTP isteği sınırı (varsayılan 8)
-insecure                  TLS doğrulamasını yoksay (varsayılan true)
-brands string             Virgülle ayrılmış ek marka listesi
-quiet                     Sadece tek satırlık özet yazdır
-version                   Versiyon bilgisi
```

## Çıkış kodları (CI uyumlu)

| Kod | Anlam |
|-----|-------|
| `0` | Cloaking tespit edilmedi (skor < 70) |
| `1` | En az bir hedefte CLOAKING TESPİT EDİLDİ veya tarama hatası |
| `2` | JSON yazma / argüman hatası |

## Örnek çıktı

```
╔══════════════════════════════════════════════════════════════════════╗
║                          TAYGUN  RAPORU                             ║
╚══════════════════════════════════════════════════════════════════════╝
  Hedef         : https://klon-site.example/
  Baseline      : Human Chrome (Windows)
  Sonuç         : CLOAKING TESPİT EDİLDİ   (skor: 88/100)

┌─ PROFİL ÖZETİ ──────────────────────────────────────────────────────
  Profil                       HTTP   Boyut        Skor      Verdict
  ──────────────────────────────────────────────────────────────────
  Human Chrome (Windows)       200    25.8 KB      0         baseline
  Googlebot Desktop            200    25.8 KB      0         TEMİZ
  USOM Inspector (sentetik)    200    25.8 KB      0         TEMİZ
  TR Kullanıcı (Google Ads)    200    142.0 KB     88        CLOAKING TESPİT EDİLDİ
  ...

┌─ EN BÜYÜK SAPMA: TR Kullanıcı (Google Ads click) ────────────────────
  • [TITLE_DIFF +25] Baseline: "Peyser Market" | Bu profil: "A101 Hediye Çeki"
  • [BRAND_HIT +25] Baseline'da geçmeyen marka bu profilde 12 kez geçiyor: a101
  • [PASSWORD_INPUT_ONLY_HERE +25] Bu profilde <input type=password> var.
  • [SUSPICIOUS_JS +15] Bu profile özel kart/OTP kalıbı: (?i)cvv|cvc|cvv2
```

## Cloaking görülmediğinde ne yapılır?

Tüm profiller aynı içeriği döndürüyorsa cloaker **pasif değil de gizli** olabilir. Diagnostic bölümü olası nedenleri ve sonraki adımları listeler:

1. **Path değiştir**: Reklam URL'sinin tam olarak verdiği path'i kullan (`/Indirim/index.php`, `/login`, `/checkout` gibi).
2. **Gerçek `gclid`/`fbclid`**: Reklam tıklama linkindeki orijinal token'ı dahil et.
3. **TR çıkışlı VPN**: Cloaker IP-tabanlı çalışıyorsa coğrafi tetikleme zorunlu.
4. **Screenshot ekle**: `-screenshot` ile JS challenge sonrası enjekte edilen black page'leri yakala.
5. **Saatlerce sonra tekrar dene**: Cloaker zaman pencereli aktif olabilir (Türkiye mesai saatleri yaygın).

## Yol haritası

- [x] 25 ziyaretçi profili (insan + bot + CERT + ad-click + geo)
- [x] DOM fingerprint + risk skor + diagnostic
- [x] JSON çıktı + body dump
- [x] Headless Chrome screenshot
- [ ] gclid/fbclid/utm parametre fuzzing
- [ ] urlscan.io / VirusTotal / PhishTank entegrasyonu
- [ ] TLS JA3 fingerprint kontrolü
- [ ] Periyodik izleme moduyla (`watch`) saatlik diff alarmı
- [ ] HTML diff görselleştirici (HTML rapor çıktısı)

## Etik kullanım

Taygun **savunma amaçlıdır**. Yalnızca aşağıdaki durumlarda kullanın:

- Sahibi olduğunuz veya tarama izniniz olan altyapılar
- Phishing/scam ihbarı edilmiş kamuya açık URL'ler
- Threat intelligence, takedown, brand-protection görevleri kapsamında

Aracı saldırgan amaçla, yetkisiz tarama veya kötü niyetli reverse-engineering için kullanmayın. Geliştirici, aracın amaç dışı kullanımından sorumlu değildir.

## Katkı

PR'lar açıktır. Yeni profil eklerken `internal/profiles/profiles.go` içine kaynak ve gerekçe ile birlikte ekleyin. Yeni risk sinyali eklerken `internal/analyzer/analyzer.go` içindeki `diff` fonksiyonuna ekleyin ve ağırlığı (0–30 arası) gerekçelendirin.

## Lisans

[MIT](LICENSE)
