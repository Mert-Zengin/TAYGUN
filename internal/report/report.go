// Package report, analyzer çıktısını terminal (renkli tablo) ve JSON
// formatlarında insan + makine okunabilir biçimde sunar.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/Mert-Zengin/taygun/internal/analyzer"
)

// PrintTable, raporu terminale yazdırır.
func PrintTable(w io.Writer, rep analyzer.Report) {
	bold := color.New(color.Bold).SprintFunc()
	red := color.New(color.FgRed, color.Bold).SprintFunc()
	yellow := color.New(color.FgYellow, color.Bold).SprintFunc()
	green := color.New(color.FgGreen, color.Bold).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()
	gray := color.New(color.FgHiBlack).SprintFunc()

	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("╔══════════════════════════════════════════════════════════════════════╗"))
	fmt.Fprintln(w, bold("║                            TAYGUN RAPORU                             ║"))
	fmt.Fprintln(w, bold("╚══════════════════════════════════════════════════════════════════════╝"))
	fmt.Fprintf(w, "  Hedef         : %s\n", cyan(rep.Target))
	fmt.Fprintf(w, "  Baseline      : %s  (%s)\n", rep.Baseline.Result.Profile.Name, gray(rep.Baseline.Result.FinalURL))
	fmt.Fprintf(w, "  Tarih         : %s\n", time.Now().Format("2006-01-02 15:04:05"))

	verdictColor := green
	switch {
	case rep.OverallScore >= 70:
		verdictColor = red
	case rep.OverallScore >= 40:
		verdictColor = yellow
	case rep.OverallScore >= 15:
		verdictColor = yellow
	}
	fmt.Fprintf(w, "  Sonuç         : %s   (skor: %d/100)\n\n", verdictColor(rep.OverallVerdict), rep.OverallScore)

	// Profil özet tablosu
	fmt.Fprintln(w, bold("┌─ PROFİL ÖZETİ ──────────────────────────────────────────────────────"))
	fmt.Fprintf(w, "  %-28s %-6s %-12s %-9s %s\n",
		bold("Profil"), bold("HTTP"), bold("Boyut"), bold("Skor"), bold("Verdict"))
	fmt.Fprintln(w, gray("  ──────────────────────────────────────────────────────────────────"))

	for _, p := range rep.Profiles {
		status := fmt.Sprintf("%d", p.Result.StatusCode)
		if p.Result.Err != nil {
			status = "ERR"
		}
		size := formatBytes(p.Result.BodyLen)
		v := p.Verdict
		switch p.Verdict {
		case "CLOAKING TESPİT EDİLDİ":
			v = red(v)
		case "ŞÜPHELİ":
			v = yellow(v)
		case "ZAYIF FARK":
			v = yellow(v)
		case "TEMİZ":
			v = green(v)
		case "baseline":
			v = cyan(v)
		case "hata":
			v = red(v + ": " + truncErr(p.Result.Err))
		}
		fmt.Fprintf(w, "  %-28s %-6s %-12s %-9s %s\n",
			truncS(p.Result.Profile.Name, 28), status, size, fmt.Sprintf("%d", p.Score), v)
	}

	// Cloaking sinyalleri
	if rep.CloakingProfile != nil && len(rep.CloakingProfile.Signals) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("┌─ EN BÜYÜK SAPMA: ")+cyan(rep.CloakingProfile.Result.Profile.Name)+bold(" ─────────────"))
		fmt.Fprintf(w, "  Final URL : %s\n", rep.CloakingProfile.Result.FinalURL)
		fmt.Fprintf(w, "  Skor      : %d/100\n", rep.CloakingProfile.Score)
		fmt.Fprintln(w, gray("  ──────────────────────────────────────────────────────────────────"))
		for _, s := range rep.CloakingProfile.Signals {
			fmt.Fprintf(w, "  • [%s +%d] %s\n", red(s.Code), s.Weight, s.Detail)
		}
	}

	// Tüm sapan profillerin sinyallerini de aç
	fmt.Fprintln(w)
	fmt.Fprintln(w, bold("┌─ TÜM SAPMA SİNYALLERİ ──────────────────────────────────────────────"))
	any := false
	for _, p := range rep.Profiles {
		if p.IsBaseline || len(p.Signals) == 0 {
			continue
		}
		any = true
		fmt.Fprintf(w, "  %s  (skor %d)\n", bold(p.Result.Profile.Name), p.Score)
		for _, s := range p.Signals {
			fmt.Fprintf(w, "      - %s [+%d]  %s\n", yellow(s.Code), s.Weight, s.Detail)
		}
	}
	if !any {
		fmt.Fprintln(w, gray("  Hiçbir profilde anlamlı sapma yok."))
	}

	if len(rep.Diagnostics) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, bold("┌─ DİAGNOSTİK ────────────────────────────────────────────────────────"))
		fmt.Fprintf(w, "  Tekil yanıt sayısı: %s\n", cyan(fmt.Sprintf("%d", rep.UniqueHashes)))
		for _, d := range rep.Diagnostics {
			fmt.Fprintf(w, "  %s\n", d)
		}
	}
	fmt.Fprintln(w)
}

// WriteJSON, raporu JSON olarak yazar (CI / pipeline için).
func WriteJSON(w io.Writer, rep analyzer.Report) error {
	out := toJSON(rep)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// jsonReport, dış API yüzeyini sabitlemek için intermediate yapı.
type jsonReport struct {
	Target          string        `json:"target"`
	GeneratedAt     time.Time     `json:"generated_at"`
	BaselineProfile string        `json:"baseline_profile"`
	OverallScore    int           `json:"overall_score"`
	OverallVerdict  string        `json:"overall_verdict"`
	UniqueHashes    int           `json:"unique_response_hashes"`
	Diagnostics     []string      `json:"diagnostics,omitempty"`
	Profiles        []jsonProfile `json:"profiles"`
}

type jsonProfile struct {
	Name        string                 `json:"name"`
	Kind        string                 `json:"kind"`
	UserAgent   string                 `json:"user_agent"`
	IsBaseline  bool                   `json:"is_baseline"`
	StatusCode  int                    `json:"status_code"`
	FinalURL    string                 `json:"final_url"`
	BodyBytes   int                    `json:"body_bytes"`
	BodySHA256  string                 `json:"body_sha256"`
	DurationMs  int64                  `json:"duration_ms"`
	Error       string                 `json:"error,omitempty"`
	Title       string                 `json:"title"`
	HasPassword bool                   `json:"has_password_input"`
	BrandHits   map[string]int         `json:"brand_hits"`
	Score       int                    `json:"score"`
	Verdict     string                 `json:"verdict"`
	Signals     []jsonSignal           `json:"signals"`
}

type jsonSignal struct {
	Code   string `json:"code"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

func toJSON(rep analyzer.Report) jsonReport {
	jr := jsonReport{
		Target:          rep.Target,
		GeneratedAt:     time.Now().UTC(),
		BaselineProfile: rep.Baseline.Result.Profile.Name,
		OverallScore:    rep.OverallScore,
		OverallVerdict:  rep.OverallVerdict,
		UniqueHashes:    rep.UniqueHashes,
		Diagnostics:     rep.Diagnostics,
	}
	for _, p := range rep.Profiles {
		jp := jsonProfile{
			Name:        p.Result.Profile.Name,
			Kind:        p.Result.Profile.Kind,
			UserAgent:   p.Result.Profile.UserAgent,
			IsBaseline:  p.IsBaseline,
			StatusCode:  p.Result.StatusCode,
			FinalURL:    p.Result.FinalURL,
			BodyBytes:   p.Result.BodyLen,
			BodySHA256:  p.Result.BodySHA256,
			DurationMs:  p.Result.Duration.Milliseconds(),
			Title:       p.Fingerprint.Title,
			HasPassword: p.Fingerprint.HasPassword,
			BrandHits:   p.Fingerprint.BrandHits,
			Score:       p.Score,
			Verdict:     p.Verdict,
		}
		if p.Result.Err != nil {
			jp.Error = p.Result.Err.Error()
		}
		for _, s := range p.Signals {
			jp.Signals = append(jp.Signals, jsonSignal{Code: s.Code, Weight: s.Weight, Detail: s.Detail})
		}
		jr.Profiles = append(jr.Profiles, jp)
	}
	return jr
}

func formatBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func truncS(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func truncErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 60 {
		return s[:57] + "…"
	}
	return s
}
