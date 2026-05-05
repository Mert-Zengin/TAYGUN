// Taygun — cloaker tespit aracı
//
// Kullanım örnekleri:
//
//	taygun -url https://aldinburadancaylariniz.store/
//	taygun -url https://x.com -json rapor.json
//	taygun -file hedefler.txt -timeout 20s -dump ./dump
//	echo https://x.com | taygun -stdin
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Mert-Zengin/taygun/internal/analyzer"
	"github.com/Mert-Zengin/taygun/internal/fetcher"
	"github.com/Mert-Zengin/taygun/internal/profiles"
	"github.com/Mert-Zengin/taygun/internal/report"
	"github.com/Mert-Zengin/taygun/internal/screenshot"
)

const version = "0.1.0"

func main() {
	var (
		urlFlag     = flag.String("url", "", "Tek hedef URL")
		fileFlag    = flag.String("file", "", "Her satırda bir URL içeren dosya")
		stdinFlag   = flag.Bool("stdin", false, "URL'leri stdin'den oku (her satır bir URL)")
		jsonOut     = flag.String("json", "", "Sonuçları JSON olarak yazılacak dosya (boşsa stdout'a sadece tablo)")
		dumpDir     = flag.String("dump", "", "Her profilin gövdesini bu klasöre dök (debug)")
		timeoutFlag = flag.Duration("timeout", 15*time.Second, "Tek istek zaman aşımı")
		concurrency = flag.Int("concurrency", 8, "Eş zamanlı istek sınırı (profil başına)")
		insecureTLS = flag.Bool("insecure", true, "TLS doğrulamasını yoksay (cloaker'lar genelde geçersiz cert kullanır)")
		brandsFlag  = flag.String("brands", "", "Virgülle ayrılmış ek markalar (ör: trendyol,a101)")
		quiet       = flag.Bool("quiet", false, "Sadece sonuç satırını yazdır")
		showVer     = flag.Bool("version", false, "Versiyon")
		screenshotF = flag.Bool("screenshot", false, "Her profil için headless Chrome ile PNG ekran görüntüsü al (Chrome/Chromium gerekir)")
		screenshotT = flag.Duration("screenshot-timeout", 30*time.Second, "Screenshot başına zaman aşımı")
		screenshotP = flag.Int("screenshot-parallel", 2, "Eş zamanlı screenshot sayısı (RAM tüketimine dikkat)")
		chromePath  = flag.String("chrome-path", "", "Chrome/Chromium binary yolu (boşsa PATH'ten otomatik)")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println("taygun", version)
		return
	}

	targets := collectTargets(*urlFlag, *fileFlag, *stdinFlag)
	if len(targets) == 0 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel)

	opts := fetcher.DefaultOptions()
	opts.Timeout = *timeoutFlag
	opts.ConcurrencyLimit = *concurrency
	opts.InsecureTLS = *insecureTLS

	brands := analyzer.DefaultBrands
	if *brandsFlag != "" {
		extra := splitCSV(*brandsFlag)
		brands = append(brands, extra...)
	}

	profs := profiles.All()

	var allReports []analyzer.Report
	exitCode := 0
	for _, raw := range targets {
		target, err := fetcher.NormalizeURL(raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[hata] %s: %v\n", raw, err)
			exitCode = 1
			continue
		}

		results := fetcher.FetchAll(ctx, target, profs, opts)

		// Screenshot istendiyse dump dizini yoksa otomatik oluştur
		effectiveDump := *dumpDir
		if *screenshotF && effectiveDump == "" {
			effectiveDump = "./taygun_dump"
		}

		if effectiveDump != "" {
			if err := dumpBodies(effectiveDump, target, results); err != nil {
				fmt.Fprintf(os.Stderr, "[uyarı] dump yazılamadı: %v\n", err)
			}
		}

		if *screenshotF {
			shotOpts := screenshot.DefaultOptions()
			shotOpts.Timeout = *screenshotT
			shotOpts.ChromePath = *chromePath
			captureScreenshots(ctx, effectiveDump, target, profs, shotOpts, *screenshotP)
		}

		rep := analyzer.Analyze(target, results, brands)
		allReports = append(allReports, rep)

		if !*quiet {
			report.PrintTable(os.Stdout, rep)
		} else {
			fmt.Printf("%-60s  skor=%-3d  %s\n", target, rep.OverallScore, rep.OverallVerdict)
		}

		if rep.OverallScore >= 70 {
			exitCode = 1 // CI için: cloaking bulundu → fail
		}
	}

	if *jsonOut != "" {
		if err := writeJSONFile(*jsonOut, allReports); err != nil {
			fmt.Fprintf(os.Stderr, "[hata] JSON yazılamadı: %v\n", err)
			exitCode = 2
		}
	}

	os.Exit(exitCode)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Taygun v%s — cloaker tespit aracı

Kullanım:
  taygun -url <hedef>
  taygun -file hedefler.txt -json rapor.json
  cat liste.txt | taygun -stdin -quiet

Bayraklar:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
Örnekler:
  taygun -url https://example.com -timeout 20s -dump ./dump
  taygun -url https://example.com/login.php -screenshot
  taygun -file liste.txt -json rapor.json -quiet

UYARI - Path doğruluğu:
  Cloaker'ın aktif olduğu URL genellikle "/", "/index.php",
  "/Indirim/index.php" gibi spesifik bir path olabilir. Yanlış path'te
  404 dönmesi cloaking yokluğu anlamına GELMEZ; o endpoint pasiftir.
  Aday path'leri (ana sayfa + reklamdaki tam URL + yaygın phishing
  landing'leri) ayrı ayrı taramanız önerilir. Tek path taraması
  %100 güvenilirlik vermez.

UYARI - USOM/TR-CERT/BTK profilleri:
  Bu üç profil sentetiktir; USOM veya BTK'nın resmî tarayıcı imzaları
  DEĞİLDİR. Yalnızca "USOM" / "TR-CERT" / ".gov.tr" anahtar kelimelerine
  reaktif paranoid cloaker'ları tetiklemek için tasarlanmıştır.
`)
}

func collectTargets(urlFlag, fileFlag string, stdinFlag bool) []string {
	var out []string
	if urlFlag != "" {
		out = append(out, urlFlag)
	}
	if fileFlag != "" {
		f, err := os.Open(fileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[hata] dosya açılamadı: %v\n", err)
		} else {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				out = append(out, line)
			}
		}
	}
	if stdinFlag {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			out = append(out, line)
		}
	}
	return out
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func handleSignals(cancel context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Fprintln(os.Stderr, "\n[!] iptal sinyali alındı, kapatılıyor...")
	cancel()
}

// dumpRoot, hedef + zaman damgalı tek bir kök klasör hesaplar.
// Hem HTML hem PNG aynı klasöre yazılsın diye paylaşılır.
var dumpRootCache = map[string]string{}
var dumpRootMu sync.Mutex

func currentDumpRoot(parent, target string) string {
	dumpRootMu.Lock()
	defer dumpRootMu.Unlock()
	key := parent + "|" + target
	if r, ok := dumpRootCache[key]; ok {
		return r
	}
	root := filepath.Join(parent, safeHost(target)+"_"+time.Now().Format("20060102_150405"))
	dumpRootCache[key] = root
	return root
}

func dumpBodies(dir, target string, results []fetcher.Result) error {
	root := currentDumpRoot(dir, target)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	for _, r := range results {
		name := safeName(r.Profile.Name) + ".html"
		if err := os.WriteFile(filepath.Join(root, name), r.Body, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func captureScreenshots(ctx context.Context, dir, target string, profs []profiles.Profile, opts screenshot.Options, parallel int) {
	if parallel < 1 {
		parallel = 1
	}
	root := currentDumpRoot(dir, target)
	if err := os.MkdirAll(root, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "[uyarı] screenshot klasörü oluşturulamadı: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "[i] %d profil için screenshot alınıyor (paralel=%d)...\n", len(profs), parallel)

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var failed int
	var failedMu sync.Mutex

	for _, p := range profs {
		wg.Add(1)
		sem <- struct{}{}
		go func(prof profiles.Profile) {
			defer wg.Done()
			defer func() { <-sem }()
			png, err := screenshot.Capture(ctx, target, prof, opts)
			if err != nil {
				failedMu.Lock()
				failed++
				failedMu.Unlock()
				fmt.Fprintf(os.Stderr, "    [x] %s — %v\n", prof.Name, err)
				return
			}
			path := filepath.Join(root, safeName(prof.Name)+".png")
			if err := os.WriteFile(path, png, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "    [x] %s — yazılamadı: %v\n", prof.Name, err)
				return
			}
			fmt.Fprintf(os.Stderr, "    [+] %s\n", prof.Name)
		}(p)
	}
	wg.Wait()
	fmt.Fprintf(os.Stderr, "[i] screenshot tamam. %d başarılı, %d başarısız. Klasör: %s\n",
		len(profs)-failed, failed, root)
}

func safeHost(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	return safeName(u)
}

func safeName(s string) string {
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return repl.Replace(s)
}

func writeJSONFile(path string, reports []analyzer.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if len(reports) == 1 {
		return report.WriteJSON(f, reports[0])
	}
	// Çoklu rapor: bir array içine sar
	if _, err := f.WriteString("[\n"); err != nil {
		return err
	}
	for i, r := range reports {
		if i > 0 {
			if _, err := f.WriteString(",\n"); err != nil {
				return err
			}
		}
		if err := report.WriteJSON(f, r); err != nil {
			return err
		}
	}
	_, err = f.WriteString("]\n")
	return err
}
