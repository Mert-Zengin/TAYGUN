// Package analyzer, fetcher tarafından toplanan profile sonuçlarını alıp
// cloaking sinyallerini çıkarır. Bir baseline (insan) profili belirler, diğer
// tüm profilleri buna kıyaslar ve her biri için risk skoru üretir.
package analyzer

import (
	"bytes"
	"regexp"
	"sort"
	"strings"

	"github.com/Mert-Zengin/taygun/internal/fetcher"
	"golang.org/x/net/html"
)

// Fingerprint, bir HTTP yanıtından çıkarılan karşılaştırılabilir özelliklerdir.
type Fingerprint struct {
	Title         string
	MetaDesc      string
	H1            []string
	LinksHost     map[string]int // tekil host → link sayısı
	ScriptsHost   map[string]int // tekil host → script sayısı
	FormsAction   []string
	IframesSrc    []string
	WordCount     int
	HasLogin      bool
	HasPassword   bool
	BrandHits     map[string]int // ör. {"a101": 12, "garanti": 0}
	SuspiciousJS  []string       // dikkat çeken inline JS desenleri
	IsSoftRedir   bool           // <meta http-equiv="refresh">, location.href vs.
	SoftRedirTo   string
	BodyHashShort string // ilk 12 hex
}

// Signal, baseline ile profile arasında bulunan tek bir farklılık.
type Signal struct {
	Code    string // kısa kod (TITLE_DIFF, BRAND_HIT, ...)
	Weight  int    // risk skoruna katkı (0-100)
	Detail  string // insan tarafından okunabilir açıklama
}

// ProfileReport, tek bir profil için analiz sonucu.
type ProfileReport struct {
	Result      fetcher.Result
	Fingerprint Fingerprint
	Signals     []Signal
	Score       int    // 0-100; baseline daima 0
	Verdict     string // "temiz" | "şüpheli" | "cloaking"
	IsBaseline  bool
}

// Report, tüm tarama çıktısı.
type Report struct {
	Target          string
	Baseline        ProfileReport
	Profiles        []ProfileReport
	OverallScore    int
	OverallVerdict  string
	CloakingProfile *ProfileReport // en yüksek skorlu sapma; nil olabilir
	Diagnostics     []string       // Operatöre gösterilecek operasyonel ipuçları
	UniqueHashes    int            // Başarılı yanıtlar arasındaki tekil body hash sayısı
}

// Brands, beyaz sayfa arkasında saklanma ihtimali yüksek hedef markalar.
// Liste kullanıcı tarafından genişletilebilir; analyzer.Analyze'a parametre
// olarak verilebilir, verilmezse bu varsayılan kullanılır.
var DefaultBrands = []string{
	"a101", "bim", "şok", "sok", "migros", "carrefoursa",
	"trendyol", "hepsiburada", "n11", "gittigidiyor", "amazon",
	"garanti", "akbank", "ziraat", "yapi kredi", "yapikredi", "isbank", "iş bankası",
	"halkbank", "vakıfbank", "vakifbank", "denizbank", "qnb", "finansbank",
	"papara", "ininal", "paycell", "paratika",
	"ptt", "turkiye.gov.tr", "e-devlet", "edevlet", "sgk", "gib",
	"turkcell", "vodafone", "türk telekom", "turk telekom",
	"netflix", "spotify", "instagram", "facebook", "whatsapp",
	"microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
	"binance", "btcturk", "paribu", "coinbase",
	"trendyol go", "yemeksepeti", "getir",
}

// SuspiciousJSPatterns, kart formu/oturum çalma kalıpları.
var SuspiciousJSPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)card[_-]?number`),
	regexp.MustCompile(`(?i)cvv|cvc|cvv2`),
	regexp.MustCompile(`(?i)otp|one[_-]?time[_-]?password|sms[_-]?kod`),
	regexp.MustCompile(`(?i)tckn|t\.c\.\s*kimlik`),
	regexp.MustCompile(`(?i)expire(date)?|son\s*kullanma`),
	regexp.MustCompile(`(?i)telegram\.org/bot|api\.telegram\.org`),
}

// Analyze, fetcher sonuçlarını alır ve tam raporu döndürür.
func Analyze(target string, results []fetcher.Result, brands []string) Report {
	if len(brands) == 0 {
		brands = DefaultBrands
	}

	// Tüm sonuçları fingerprint'e dönüştür
	prs := make([]ProfileReport, 0, len(results))
	for _, r := range results {
		fp := buildFingerprint(r.Body, brands)
		prs = append(prs, ProfileReport{Result: r, Fingerprint: fp})
	}

	// Baseline seçimi: en büyük gövdeli, başarılı (2xx) insan profili.
	// Cloaker bazen ilk isteği drop edebileceği için sabit "ilk profil"
	// yerine en dolu yanıtı baseline kabul ediyoruz. Hiç insan 2xx yoksa
	// herhangi bir başarılı yanıta düşeriz.
	baselineIdx := -1
	bestLen := -1
	for i, r := range results {
		if r.Err != nil || len(r.Body) == 0 {
			continue
		}
		if r.Profile.Kind != "human" {
			continue
		}
		if r.StatusCode >= 200 && r.StatusCode < 300 && r.BodyLen > bestLen {
			baselineIdx = i
			bestLen = r.BodyLen
		}
	}
	if baselineIdx == -1 {
		for i, r := range results {
			if r.Err == nil && len(r.Body) > 0 {
				baselineIdx = i
				break
			}
		}
	}
	if baselineIdx >= 0 {
		prs[baselineIdx].IsBaseline = true
	}

	rep := Report{Target: target}
	if baselineIdx == -1 {
		// Hiç başarılı çekim yoksa diagnostic'i yine de göster — kullanıcı
		// "neden hiç sonuç yok" sorusuna kantitatif cevap görmeli.
		rep.Profiles = prs
		rep.OverallVerdict = "tarama başarısız"
		errCount := 0
		var sampleErr string
		for _, r := range results {
			if r.Err != nil {
				errCount++
				if sampleErr == "" {
					sampleErr = r.Err.Error()
				}
			}
		}
		rep.Diagnostics = []string{
			"Hiçbir profil başarılı yanıt almadı (" + intToStr(errCount) + "/" + intToStr(len(results)) + " hata).",
			"Olası nedenler:",
			"  • IP'niz cloaker tarafından geçici olarak banlanmış (5-15 dk bekleyin veya VPN/farklı IP).",
			"  • Hedef site şu an erişilemez veya tüm istekleri reset ediyor.",
			"  • Cloudflare/edge proxy bizim TLS/JA3 imzamızı bot olarak işaretlemiş.",
			"  Örnek hata: " + truncErr(sampleErr),
			"  Öneri: -concurrency 1 -timeout 30s ile yavaş tarama deneyin.",
		}
		return rep
	}

	rep.Baseline = prs[baselineIdx]
	baseFP := rep.Baseline.Fingerprint

	// Her profil için sinyalleri çıkar
	for i := range prs {
		pr := &prs[i]
		if pr.Result.Err != nil {
			pr.Verdict = "hata"
			continue
		}
		if i == baselineIdx {
			pr.Verdict = "baseline"
			continue
		}
		pr.Signals = diff(baseFP, pr.Fingerprint, rep.Baseline.Result, pr.Result)
		pr.Score = scoreOf(pr.Signals)
		pr.Verdict = verdict(pr.Score)
	}

	rep.Profiles = prs

	// En yüksek skorlu sapan profil + genel sonuç
	var maxScore int
	var maxIdx = -1
	for i, pr := range prs {
		if pr.IsBaseline || pr.Result.Err != nil {
			continue
		}
		if pr.Score > maxScore {
			maxScore = pr.Score
			maxIdx = i
		}
	}
	rep.OverallScore = maxScore
	rep.OverallVerdict = verdict(maxScore)
	if maxIdx >= 0 {
		rep.CloakingProfile = &prs[maxIdx]
	}
	rep.UniqueHashes, rep.Diagnostics = diagnose(prs)
	return rep
}

// diagnose, "neden cloaking görmedik" sorusuna kantitatif cevap üretir.
// Cloaker pasifse bile operatör nedeni bilmek ister.
func diagnose(prs []ProfileReport) (int, []string) {
	hashes := map[string]int{}
	successful := 0
	humanLoginSeen := false
	botLoginSeen := false

	// Baseline'ın kendisi black page olabilir mi? Eğer baseline'da çok yoğun
	// marka sızıntısı + password input + diğer profillerin çoğu 4xx ise
	// büyük ihtimalle baseline cloaker tarafından zaten black açılmıştır.
	var baseline *ProfileReport
	bot4xx, bot2xx := 0, 0
	for i := range prs {
		if prs[i].IsBaseline {
			baseline = &prs[i]
		}
		if prs[i].Result.Profile.Kind == "bot" && prs[i].Result.Err == nil {
			if prs[i].Result.StatusCode >= 400 {
				bot4xx++
			}
			if prs[i].Result.StatusCode == 200 {
				bot2xx++
			}
		}
	}

	for _, p := range prs {
		if p.Result.Err != nil || p.Result.BodyLen == 0 {
			continue
		}
		successful++
		hashes[p.Result.BodySHA256]++
		if p.Result.Profile.Kind == "human" && p.Fingerprint.HasPassword {
			humanLoginSeen = true
		}
		if p.Result.Profile.Kind == "bot" && p.Fingerprint.HasPassword {
			botLoginSeen = true
		}
	}

	var diag []string
	switch {
	case successful == 0:
		diag = append(diag, "Hiçbir profil yanıt almadı; hedef ulaşılmaz veya bizi tamamen bloklamış olabilir.")
	case len(hashes) == 1:
		diag = append(diag, "Tüm profiller birebir aynı içeriği aldı. Olası nedenler:")
		diag = append(diag, "  • Cloaker şu an pasif (operatör henüz black page'i açmamış olabilir).")
		diag = append(diag, "  • Cloaker IP-tabanlı çalışıyor; whitelist'imizdeki üst başlıklar (X-Forwarded-For) edge proxy tarafından yok sayılıyor olabilir.")
		diag = append(diag, "  • Cloaker JS challenge / fingerprint istiyor; saf HTTP fetcher ile tetiklenemeyebilir.")
		diag = append(diag, "  • Tek seferlik token (gclid/fbclid) doğrulaması yapıyor; gerçek reklam URL'sini kullanmak gerekebilir.")
		diag = append(diag, "  Öneri: -url'i gerçek reklam tıklama linki ile (gclid=... dahil) çağırın veya TR çıkışlı bir VPN ile tekrar deneyin.")
	case len(hashes) == 2:
		diag = append(diag, "İçerik 2 farklı hash'e ayrışıyor → klasik cloaking deseni mevcut.")
	default:
		diag = append(diag, "İçerik "+intToStr(len(hashes))+" farklı varyanta ayrışıyor → çoklu hedefli cloaking veya dinamik içerik.")
	}

	if humanLoginSeen && !botLoginSeen {
		diag = append(diag, "Login formu yalnızca insan profillerinde görünüyor → klasik phishing white-page/black-page şeması.")
	}
	if botLoginSeen && !humanLoginSeen {
		diag = append(diag, "Login formu yalnızca bot profillerinde görünüyor (alışılmadık) → SEO hile veya araştırmacı tuzağı olabilir.")
	}

	// Baseline'ın kendisi black olabilir mi?
	// Şart: baseline'da yoğun phishing markası VE en az bir önemli bot 4xx aldı
	// (cloaker araştırmacıları engelliyor demektir).
	if baseline != nil {
		brandTotal := 0
		topBrand := ""
		topHits := 0
		for b, c := range baseline.Fingerprint.BrandHits {
			brandTotal += c
			if c > topHits {
				topHits = c
				topBrand = b
			}
		}
		looksLikeBlack := brandTotal >= 15 || baseline.Fingerprint.HasPassword
		if looksLikeBlack && bot4xx >= 1 {
			diag = append(diag, "DİKKAT: Baseline (insan profili) muhtemelen ZATEN BLACK PAGE alıyor — uyarılar TERSE OKUNMALI.")
			diag = append(diag, "  • Baseline'da toplam "+intToStr(brandTotal)+" marka sızıntısı (en yoğun: "+topBrand+" × "+intToStr(topHits)+").")
			diag = append(diag, "  • "+intToStr(bot4xx)+" bot/araştırmacı profili 4xx ile bloklanmış.")
			diag = append(diag, "  • Bu durumda 'BRAND_HIDDEN' sinyalleri aslında 'cloaker bot'tan saklıyor' anlamına gelir.")
			diag = append(diag, "  • Olası operasyon: Cloaker bilinen bot/CERT IP-UA'larını siyah listeye almış; mağduru direkt black page'e yönlendiriyor.")
			diag = append(diag, "  • White page kanıtı için: clean tarayıcıda incognito + farklı IP ile manuel ziyaret, veya kök URL ('/' veya '/index') ile yeniden tarama yapın.")
		}
	}

	return len(hashes), diag
}

func verdict(score int) string {
	switch {
	case score >= 70:
		return "CLOAKING TESPİT EDİLDİ"
	case score >= 40:
		return "ŞÜPHELİ"
	case score >= 15:
		return "ZAYIF FARK"
	default:
		return "TEMİZ"
	}
}

func scoreOf(sigs []Signal) int {
	total := 0
	for _, s := range sigs {
		total += s.Weight
	}
	if total > 100 {
		total = 100
	}
	return total
}

// diff, baseline ile karşılaştırma yapar ve sinyalleri döndürür.
func diff(base, other Fingerprint, baseRes, otherRes fetcher.Result) []Signal {
	var sigs []Signal

	if base.Title != other.Title && base.Title != "" && other.Title != "" {
		sigs = append(sigs, Signal{
			Code:   "TITLE_DIFF",
			Weight: 25,
			Detail: trunc("Baseline: \""+base.Title+"\"  |  Bu profil: \""+other.Title+"\"", 200),
		})
	}

	if baseRes.FinalURL != otherRes.FinalURL {
		sigs = append(sigs, Signal{
			Code:   "FINAL_URL_DIFF",
			Weight: 30,
			Detail: "Baseline → " + baseRes.FinalURL + "  |  Bu profil → " + otherRes.FinalURL,
		})
	}

	// İçerik uzunluğu büyük farkı (hash farkı zaten cloaking'in kalbi)
	if baseRes.BodySHA256 != otherRes.BodySHA256 && baseRes.BodySHA256 != "" && otherRes.BodySHA256 != "" {
		lenDelta := abs(baseRes.BodyLen - otherRes.BodyLen)
		ratio := 0.0
		if baseRes.BodyLen > 0 {
			ratio = float64(lenDelta) / float64(baseRes.BodyLen)
		}
		w := 15
		if ratio > 0.4 {
			w = 30
		} else if ratio > 0.15 {
			w = 22
		}
		sigs = append(sigs, Signal{
			Code:   "BODY_DIFF",
			Weight: w,
			Detail: "Gövde hash farklı (Δlen=" + itoa(lenDelta) + " byte).",
		})
	}

	// Marka sızıntıları (white page'de yok, bot/diğer profilde var)
	for brand, hits := range other.BrandHits {
		baseHits := base.BrandHits[brand]
		if hits >= 2 && baseHits == 0 {
			sigs = append(sigs, Signal{
				Code:   "BRAND_HIT",
				Weight: 25,
				Detail: "Baseline'da geçmeyen marka bu profilde " + itoa(hits) + " kez geçiyor: " + brand,
			})
		}
	}
	// Tersi de önemli: white page bir markayı gösteriyor, bot sayfası saklıyorsa
	for brand, hits := range base.BrandHits {
		otherHits := other.BrandHits[brand]
		if hits >= 2 && otherHits == 0 {
			sigs = append(sigs, Signal{
				Code:   "BRAND_HIDDEN",
				Weight: 10,
				Detail: "Baseline'da " + itoa(hits) + " kez geçen marka bu profilde gizli: " + brand,
			})
		}
	}

	// Form action farkı
	if !slicesEqual(base.FormsAction, other.FormsAction) {
		sigs = append(sigs, Signal{
			Code:   "FORM_DIFF",
			Weight: 20,
			Detail: "Form action listeleri farklı.",
		})
	}

	// Login/password sinyali sadece bir tarafta varsa
	if other.HasPassword && !base.HasPassword {
		sigs = append(sigs, Signal{
			Code:   "PASSWORD_INPUT_ONLY_HERE",
			Weight: 25,
			Detail: "Bu profilde <input type=password> var, baseline'da yok.",
		})
	}
	if base.HasPassword && !other.HasPassword {
		sigs = append(sigs, Signal{
			Code:   "PASSWORD_INPUT_HIDDEN",
			Weight: 20,
			Detail: "Baseline'da bulunan password input bu profilde gizli.",
		})
	}

	// Şüpheli JS yalnızca bir tarafta görünüyorsa
	for _, p := range other.SuspiciousJS {
		if !contains(base.SuspiciousJS, p) {
			sigs = append(sigs, Signal{
				Code:   "SUSPICIOUS_JS",
				Weight: 15,
				Detail: "Bu profile özel kart/OTP/Telegram kalıbı: " + p,
			})
		}
	}

	// Soft redirect (meta refresh) farkı
	if other.IsSoftRedir && !base.IsSoftRedir {
		sigs = append(sigs, Signal{
			Code:   "META_REFRESH_ONLY_HERE",
			Weight: 20,
			Detail: "Bu profil meta-refresh ile yönlendiriliyor → " + other.SoftRedirTo,
		})
	}
	if base.IsSoftRedir && !other.IsSoftRedir {
		sigs = append(sigs, Signal{
			Code:   "META_REFRESH_HIDDEN",
			Weight: 15,
			Detail: "Baseline'daki meta-refresh bu profile gösterilmiyor.",
		})
	}

	// Iframe farkı
	if !slicesEqual(base.IframesSrc, other.IframesSrc) && (len(base.IframesSrc) > 0 || len(other.IframesSrc) > 0) {
		sigs = append(sigs, Signal{
			Code:   "IFRAME_DIFF",
			Weight: 12,
			Detail: "Iframe kaynakları farklı.",
		})
	}

	// Status farkı — cloaker'ın en sık imzası (200 vs 403/451/302).
	// 200→4xx özellikle güçlü çünkü sadece "şüpheli" ziyaretçiler bloklanıyor.
	if baseRes.StatusCode != otherRes.StatusCode {
		w := 20
		if baseRes.StatusCode == 200 && otherRes.StatusCode >= 400 {
			w = 35
		}
		if baseRes.StatusCode >= 400 && otherRes.StatusCode == 200 {
			w = 35
		}
		sigs = append(sigs, Signal{
			Code:   "STATUS_DIFF",
			Weight: w,
			Detail: "HTTP " + itoa(baseRes.StatusCode) + " → " + itoa(otherRes.StatusCode) +
				"  (cloaker " + classifyBlock(baseRes.StatusCode, otherRes.StatusCode) + ")",
		})
	}

	return sigs
}

// classifyBlock, status farkının insan-dilinde anlamını verir.
func classifyBlock(base, other int) string {
	switch {
	case base == 200 && other >= 400:
		return "bu profili bloklamış"
	case base >= 400 && other == 200:
		return "bu profile özel sayfa açmış"
	case base == 200 && other >= 300 && other < 400:
		return "bu profili yönlendirmiş"
	default:
		return "kategorize edilemedi"
	}
}

// buildFingerprint, ham HTML gövdesinden parmak izi çıkarır.
func buildFingerprint(body []byte, brands []string) Fingerprint {
	fp := Fingerprint{
		LinksHost:   map[string]int{},
		ScriptsHost: map[string]int{},
		BrandHits:   map[string]int{},
	}
	if len(body) == 0 {
		return fp
	}

	// Marka sayımı: tüm gövdede case-insensitive substring
	lower := bytes.ToLower(body)
	for _, b := range brands {
		c := bytes.Count(lower, []byte(strings.ToLower(b)))
		if c > 0 {
			fp.BrandHits[b] = c
		}
	}

	// Şüpheli JS desenleri
	for _, re := range SuspiciousJSPatterns {
		if re.Match(body) {
			fp.SuspiciousJS = append(fp.SuspiciousJS, re.String())
		}
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return fp
	}

	var inHead, inTitle bool
	var titleBuf bytes.Buffer
	var textBuf bytes.Buffer

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.ElementNode:
			switch strings.ToLower(n.Data) {
			case "head":
				inHead = true
				defer func() { inHead = false }()
			case "title":
				inTitle = true
				defer func() { inTitle = false }()
			case "meta":
				name := strings.ToLower(attr(n, "name"))
				if name == "description" {
					fp.MetaDesc = attr(n, "content")
				}
				if strings.EqualFold(attr(n, "http-equiv"), "refresh") {
					fp.IsSoftRedir = true
					fp.SoftRedirTo = extractRefreshTarget(attr(n, "content"))
				}
			case "h1":
				h := strings.TrimSpace(textOf(n))
				if h != "" {
					fp.H1 = append(fp.H1, h)
				}
			case "a":
				if h := hostOf(attr(n, "href")); h != "" {
					fp.LinksHost[h]++
				}
			case "script":
				if h := hostOf(attr(n, "src")); h != "" {
					fp.ScriptsHost[h]++
				}
			case "iframe":
				if s := attr(n, "src"); s != "" {
					fp.IframesSrc = append(fp.IframesSrc, s)
				}
			case "form":
				fp.FormsAction = append(fp.FormsAction, attr(n, "action"))
			case "input":
				t := strings.ToLower(attr(n, "type"))
				name := strings.ToLower(attr(n, "name"))
				if t == "password" {
					fp.HasPassword = true
				}
				if t == "email" || t == "text" {
					if strings.Contains(name, "user") || strings.Contains(name, "login") || strings.Contains(name, "email") {
						fp.HasLogin = true
					}
				}
			}
		case html.TextNode:
			if inTitle {
				titleBuf.WriteString(n.Data)
			}
			if !inHead {
				textBuf.WriteString(n.Data)
				textBuf.WriteByte(' ')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	fp.Title = strings.TrimSpace(strings.Join(strings.Fields(titleBuf.String()), " "))
	fp.WordCount = len(strings.Fields(textBuf.String()))
	sort.Strings(fp.IframesSrc)
	sort.Strings(fp.FormsAction)
	return fp
}

// ----- yardımcılar -----

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

func textOf(n *html.Node) string {
	var b bytes.Buffer
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func hostOf(raw string) string {
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "javascript:") {
		return ""
	}
	if strings.HasPrefix(raw, "//") {
		raw = "https:" + raw
	}
	if !strings.Contains(raw, "://") {
		return "" // göreli linkleri saymıyoruz
	}
	idx := strings.Index(raw, "://")
	rest := raw[idx+3:]
	end := strings.IndexAny(rest, "/?#")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

var refreshURLRe = regexp.MustCompile(`(?i)url\s*=\s*['"]?([^'">\s]+)`)

func extractRefreshTarget(s string) string {
	m := refreshURLRe.FindStringSubmatch(s)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func itoa(i int) string {
	// Küçük performans: strconv yerine inline; yine de strconv kullanmak güvenli.
	return intToStr(i)
}

func intToStr(i int) string {
	// strconv.Itoa kullanmamak için saf çözüm (CGO bağımsız sade build).
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func truncErr(s string) string {
	if len(s) <= 200 {
		return s
	}
	return s[:200] + "…"
}
