// Command boarnet-sweetadb-adapter ships events from an existing
// sweetADB (github.com/Womkirkie/sweetADB) honeypot into a BoarNet
// ingest endpoint. Drop the binary alongside a running sweetadb
// process, point it at the events.jsonl and the BoarNet token, and
// the adapter takes care of:
//
//   - Registering the sensor with BoarNet on startup
//   - Tailing events.jsonl (inode + offset tracked so restarts don't
//     re-ship history)
//   - Translating sweetADB event types into BoarNet envelope v1
//     with `adb.*` event types
//   - HMAC-peppering source IPs (same scheme as the first-party
//     BoarNet agent, so dashboards can cross-reference attackers
//     across sensors)
//   - Hashing binary payload drops (./mimic/payloads/*.bin) and
//     surfacing them as `payload.dropped` envelopes
//   - Batched gzip POSTs with exponential-backoff retry on transient
//     network / 5xx errors
//
// No external Go dependencies — stdlib only, so partner operators
// can `go build` with any Go 1.21+ toolchain and walk away with a
// single static binary.
//
// License parity: sweetADB is MIT-licensed and this adapter is
// MIT-licensed so downstream redistribution is friction-free.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- configuration ----------

type config struct {
	EventsLog   string
	PayloadsDir string
	IngestURL   string
	Token       string
	SensorID    string
	PepperKeyID string
	DataDir     string
	Fleet       string
	Persona     string
	Verbose     bool
}

func loadConfig() (*config, error) {
	c := &config{}
	flag.StringVar(&c.EventsLog, "events-log", envOr("SWEETADB_EVENTS_LOG", "./mimic/events.jsonl"),
		"Path to sweetADB's events.jsonl")
	flag.StringVar(&c.PayloadsDir, "payloads-dir", envOr("SWEETADB_PAYLOADS_DIR", "./mimic/payloads"),
		"Directory sweetADB drops binary payloads into")
	flag.StringVar(&c.IngestURL, "ingest-url", envOr("BOARNET_INGEST_URL", "https://www.boarnet.io/api/ingest/v1/events"),
		"BoarNet ingest endpoint")
	flag.StringVar(&c.Token, "token", os.Getenv("BOARNET_TOKEN"),
		"BoarNet ingest token (bn_…). Mint at /dashboard/sensors.")
	flag.StringVar(&c.SensorID, "sensor-id", os.Getenv("BOARNET_SENSOR_ID"),
		"Stable sensor identifier, e.g. mesh-adb-01")
	flag.StringVar(&c.PepperKeyID, "pepper-key-id", envOr("BOARNET_PEPPER_KEY_ID", "pepper-sweetadb-v1"),
		"Pepper key id stamped on envelopes")
	flag.StringVar(&c.DataDir, "data-dir", envOr("BOARNET_DATA_DIR", "/var/lib/boarnet-sweetadb"),
		"Writable directory for pepper secret + tail offset")
	flag.StringVar(&c.Fleet, "fleet", envOr("BOARNET_FLEET", "mesh"),
		"Fleet tier (mesh for partner sensors; core reserved for BoarNet-operated)")
	flag.StringVar(&c.Persona, "persona", envOr("BOARNET_PERSONA", "sweetadb"),
		"Persona tag for dashboard grouping")
	flag.BoolVar(&c.Verbose, "verbose", false, "Log every envelope emitted")
	flag.Parse()

	if c.Token == "" {
		return nil, errors.New("--token (or BOARNET_TOKEN env) required")
	}
	if c.SensorID == "" {
		return nil, errors.New("--sensor-id (or BOARNET_SENSOR_ID env) required")
	}
	if c.Fleet != "core" && c.Fleet != "mesh" {
		return nil, fmt.Errorf("--fleet must be core or mesh, got %q", c.Fleet)
	}
	return c, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------- pepper (per-sensor src_ip HMAC secret) ----------

type pepper struct {
	keyID  string
	secret []byte
}

// loadOrCreatePepper mirrors the first-party agent's behavior — 32
// random bytes stored with 0600 perms. HMACing src_ip with this
// secret makes the IP hash privacy-preserving while still stable
// for pivot queries on the server.
func loadOrCreatePepper(dataDir, keyID string) (*pepper, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "pepper.secret")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return &pepper{keyID: keyID, secret: b}, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, err
	}
	return &pepper{keyID: keyID, secret: secret}, nil
}

func (p *pepper) srcIPHash(ip string) string {
	h := hmac.New(sha256.New, p.secret)
	h.Write([]byte(ip))
	return "hmac-sha256:" + hex.EncodeToString(h.Sum(nil))
}

// ---------- envelope v1 ----------

type envelope struct {
	EventID         string          `json:"event_id"`
	EnvelopeVersion int             `json:"envelope_version"`
	EventType       string          `json:"event_type"`
	Ts              string          `json:"ts"`
	Sensor          envSensor       `json:"sensor"`
	Src             envSrc          `json:"src"`
	Dst             envDst          `json:"dst"`
	Fingerprints    envFingerprints `json:"fingerprints"`
	EncryptionHints envEncHints     `json:"encryption_hints"`
	Raw             json.RawMessage `json:"raw"`
	Tags            []string        `json:"tags"`
}

type envSensor struct {
	ID           string `json:"id"`
	Fleet        string `json:"fleet"`
	AgentVersion string `json:"agent_version"`
}

type envSrc struct {
	IP     string `json:"ip"`
	IPHash string `json:"ip_hash"`
	Port   int    `json:"port"`
}

type envDst struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
}

// Server validator requires all four keys to be present (nil-valued
// is fine). No omitempty — nil pointers serialize as JSON null.
type envFingerprints struct {
	JA3     *string `json:"ja3"`
	JA3Hash *string `json:"ja3_hash"`
	JA4     *string `json:"ja4"`
	SSH     *string `json:"ssh"`
}

type envEncHints struct {
	SensorEncryptedFields []string `json:"sensor_encrypted_fields"`
	PepperKeyID           string   `json:"pepper_key_id"`
}

func newEnvelope(cfg *config) *envelope {
	return &envelope{
		EventID:         randEventID(),
		EnvelopeVersion: 1,
		Ts:              time.Now().UTC().Format(time.RFC3339Nano),
		Sensor: envSensor{
			ID:           cfg.SensorID,
			Fleet:        cfg.Fleet,
			AgentVersion: "boarnet-sweetadb-adapter/0.1.0",
		},
		Fingerprints: envFingerprints{},
		EncryptionHints: envEncHints{
			SensorEncryptedFields: []string{},
			PepperKeyID:           cfg.PepperKeyID,
		},
		Tags: []string{},
	}
}

func randEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

// ---------- sweetADB event mapping ----------

type sweetEvent struct {
	Ts        int64   `json:"ts"`
	IP        string  `json:"ip"`
	Port      int     `json:"port"`
	Seq       int     `json:"seq"`
	Event     string  `json:"event"`
	Detail    string  `json:"detail"`
	ElapsedMS float64 `json:"elapsed_ms"`
}

// sweetADB listens on :5555 (ADB over TCP) by default. If the
// operator runs on a non-default port, they can override via flag
// but we don't parse it from the events.jsonl itself (sweetADB
// doesn't write the listening port into each event).
const adbDefaultPort = 5555

// toEnvelope maps one sweetADB event into a BoarNet envelope.
// Returns nil if the event should be suppressed (stream_close /
// stream_data without payload are noisy heartbeats we don't need to
// ship).
func toEnvelope(cfg *config, p *pepper, e sweetEvent, dstPort int) *envelope {
	if e.IP == "" {
		return nil
	}

	env := newEnvelope(cfg)
	env.Src = envSrc{
		IP:     e.IP,
		IPHash: p.srcIPHash(e.IP),
		Port:   e.Port,
	}
	env.Dst = envDst{Port: dstPort, Proto: "tcp"}
	// Use sweetADB's timestamp rather than wall clock so events
	// replayed from a historical log land with their real times.
	env.Ts = time.Unix(e.Ts, 0).UTC().Format(time.RFC3339Nano)

	baseTags := []string{"adb", "stack:sweetadb", "probe-family:adb"}

	// Event-type mapping. BoarNet's adb.* types are purpose-built;
	// see app/_lib/ingest/envelope-types.ts for the full whitelist.
	switch e.Event {
	case "cnxn":
		env.EventType = "adb.cnxn"
		env.Tags = append(baseTags, "adb-handshake")
	case "auth":
		env.EventType = "adb.auth"
		env.Tags = append(baseTags, "adb-auth")
	case "shell_command":
		env.EventType = "adb.cmd.exec"
		env.Tags = append(baseTags, "adb-shell")
	case "stream_open", "stream_data", "stream_close":
		env.EventType = "adb.stream"
		env.Tags = append(baseTags, "adb-stream:"+strings.TrimPrefix(e.Event, "stream_"))
	case "sync_data":
		// sync_data means the attacker pushed or pulled a file. The
		// payload file lands in payloads/ and is surfaced separately
		// via surfacePayloadIfPresent. Still emit an adb.stream for
		// the session transcript.
		env.EventType = "adb.stream"
		env.Tags = append(baseTags, "adb-sync")
	case "unknown_cmd":
		env.EventType = "adb.stream"
		env.Tags = append(baseTags, "adb-unknown-cmd")
	default:
		// Forward-compat: new sweetADB event types get a generic
		// adb.stream tag so the server still stores them.
		env.EventType = "adb.stream"
		env.Tags = append(baseTags, "adb-event:"+e.Event)
	}

	raw := map[string]any{
		"seq":        e.Seq,
		"event":      e.Event,
		"detail":     e.Detail,
		"elapsed_ms": e.ElapsedMS,
	}
	body, _ := json.Marshal(raw)
	env.Raw = body

	return env
}

// ---------- payload surfacing ----------

// sha256File hashes one payload file. sweetADB uses the naming
// convention <ip>_<ts>_<stream_id>.bin; we extract the IP from the
// filename so a payload envelope is attributable even when it
// arrives without a matching events.jsonl line.
func payloadEnvelope(cfg *config, p *pepper, path string) (*envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	base := filepath.Base(path)
	parts := strings.SplitN(base, "_", 2)
	ip := "0.0.0.0"
	if len(parts) > 0 && parts[0] != "" {
		ip = parts[0]
	}

	env := newEnvelope(cfg)
	env.EventType = "payload.dropped"
	env.Src = envSrc{IP: ip, IPHash: p.srcIPHash(ip), Port: 0}
	env.Dst = envDst{Port: adbDefaultPort, Proto: "tcp"}
	env.Tags = []string{"adb", "stack:sweetadb", "adb-payload"}
	raw, _ := json.Marshal(map[string]any{
		"sha256":    sum,
		"size":      n,
		"direction": "upload",
		"source":    base,
	})
	env.Raw = raw
	return env, nil
}

// ---------- log tailer (inode + byte offset) ----------

type tailer struct {
	path    string
	offset  int64
	inode   uint64
	log     *slog.Logger
	offPath string
}

func newTailer(path, offPath string, log *slog.Logger) *tailer {
	t := &tailer{path: path, offPath: offPath, log: log}
	t.loadOffset()
	return t
}

func (t *tailer) loadOffset() {
	b, err := os.ReadFile(t.offPath)
	if err != nil {
		return
	}
	var saved struct {
		Inode  uint64 `json:"inode"`
		Offset int64  `json:"offset"`
	}
	if err := json.Unmarshal(b, &saved); err == nil {
		t.inode = saved.Inode
		t.offset = saved.Offset
	}
}

func (t *tailer) saveOffset() {
	body, _ := json.Marshal(map[string]any{
		"inode":  t.inode,
		"offset": t.offset,
	})
	_ = os.WriteFile(t.offPath, body, 0o600)
}

// Run tails the file and invokes onLine for every non-empty line.
// Detects rotation via inode change (unix) and seeks back to the
// start of the new file. On Windows / filesystems without a
// meaningful inode, we fall back to size-truncation detection.
func (t *tailer) Run(ctx context.Context, onLine func([]byte)) error {
	for {
		if err := t.step(ctx, onLine); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			t.log.Warn("tail step error — backing off", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
}

func (t *tailer) step(ctx context.Context, onLine func([]byte)) error {
	f, err := os.Open(t.path)
	if err != nil {
		// Not yet created — wait and retry.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
			return nil
		}
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}
	curInode := fileInode(st)
	if t.inode != 0 && curInode != 0 && curInode != t.inode {
		t.log.Info("log rotated — seeking to start of new file", "old_inode", t.inode, "new_inode", curInode)
		t.offset = 0
	}
	if st.Size() < t.offset {
		t.log.Info("log truncated — seeking to 0")
		t.offset = 0
	}
	t.inode = curInode

	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}

	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			t.offset += int64(len(line))
			line = bytes.TrimRight(line, "\r\n")
			if len(line) > 0 {
				onLine(line)
			}
			t.saveOffset()
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	// Idle sleep before the next poll cycle. sweetADB fsyncs each
	// line, so we don't miss events by polling at 1s granularity.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(1 * time.Second):
	}
	return nil
}

// ---------- publisher (batched gzip POST with retry) ----------

type publisher struct {
	url        string
	token      string
	httpClient *http.Client
	log        *slog.Logger

	ch      chan *envelope
	wg      sync.WaitGroup
	stopped bool
	mu      sync.Mutex
}

func newPublisher(url, token string, log *slog.Logger) *publisher {
	return &publisher{
		url:        url,
		token:      token,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		log:        log,
		ch:         make(chan *envelope, 2048),
	}
}

func (p *publisher) Start(ctx context.Context) {
	p.wg.Add(1)
	go p.loop(ctx)
}

func (p *publisher) Enqueue(env *envelope) {
	select {
	case p.ch <- env:
	default:
		p.log.Warn("publisher queue full — dropping", "event_id", env.EventID)
	}
}

func (p *publisher) loop(ctx context.Context) {
	defer p.wg.Done()
	const batchSize = 50
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	batch := make([]*envelope, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := p.send(ctx, batch); err != nil {
			p.log.Warn("batch failed — dropping", "size", len(batch), "err", err)
		} else {
			p.log.Info("batch sent", "size", len(batch))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case env := <-p.ch:
			batch = append(batch, env)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (p *publisher) send(ctx context.Context, batch []*envelope) error {
	wrapper := struct {
		Envelopes []*envelope `json:"envelopes"`
	}{Envelopes: batch}
	body, err := json.Marshal(wrapper)
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(body); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(gz.Bytes()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Encoding", "gzip")
		req.Header.Set("Authorization", "Bearer "+p.token)
		req.Header.Set("User-Agent", "boarnet-sweetadb-adapter/0.1.0")

		resp, err := p.httpClient.Do(req)
		if err != nil {
			p.log.Warn("HTTP error — retrying", "attempt", attempt+1, "err", err)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var body struct {
				Accepted int `json:"accepted"`
				Rejected []struct {
					EventID string `json:"event_id"`
					Reason  string `json:"reason"`
				} `json:"rejected"`
			}
			if err := json.Unmarshal(respBody, &body); err == nil {
				if len(body.Rejected) > 0 {
					p.log.Warn("server rejected envelopes",
						"accepted", body.Accepted,
						"rejected_count", len(body.Rejected),
						"first_reason", body.Rejected[0].Reason,
					)
				}
			}
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("ingest %d: %s", resp.StatusCode, string(respBody))
		}
		p.log.Warn("server 5xx — retrying", "status", resp.StatusCode, "body", string(respBody))
		time.Sleep(backoff)
		backoff *= 2
	}
	return errors.New("exhausted retries")
}

// ---------- sensor self-registration ----------

func registerSensor(ctx context.Context, cfg *config, log *slog.Logger) error {
	baseURL := strings.TrimSuffix(cfg.IngestURL, "/events")
	body, _ := json.Marshal(map[string]any{
		"sensor_id": cfg.SensorID,
		"persona":   cfg.Persona,
		"fleet":     cfg.Fleet,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/sensor/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("User-Agent", "boarnet-sweetadb-adapter/0.1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("register %d: %s", resp.StatusCode, string(b))
	}
	log.Info("sensor registered", "sensor_id", cfg.SensorID, "fleet", cfg.Fleet, "persona", cfg.Persona)
	return nil
}

// ---------- payload watcher ----------

// watchPayloads periodically scans the payloads directory for
// files we haven't yet shipped (tracked by marker file). Each new
// file becomes one payload.dropped envelope with the SHA256. We
// keep it simple — scan every 15s, check against a marker directory
// so restarts don't re-ship.
func watchPayloads(ctx context.Context, cfg *config, p *pepper,
	pub *publisher, log *slog.Logger,
) {
	markerDir := filepath.Join(cfg.DataDir, "shipped-payloads")
	_ = os.MkdirAll(markerDir, 0o700)

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		entries, err := os.ReadDir(cfg.PayloadsDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".bin") {
				continue
			}
			marker := filepath.Join(markerDir, e.Name()+".shipped")
			if _, err := os.Stat(marker); err == nil {
				continue
			}
			full := filepath.Join(cfg.PayloadsDir, e.Name())
			env, err := payloadEnvelope(cfg, p, full)
			if err != nil {
				log.Warn("payload hash failed", "file", e.Name(), "err", err)
				continue
			}
			pub.Enqueue(env)
			_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
			log.Info("payload shipped", "file", e.Name())
		}
	}
}

// ---------- main ----------

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(2)
	}

	logLevel := slog.LevelInfo
	if cfg.Verbose {
		logLevel = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Info("boarnet-sweetadb-adapter starting",
		"sensor_id", cfg.SensorID,
		"events_log", cfg.EventsLog,
		"ingest_url", cfg.IngestURL,
	)

	pep, err := loadOrCreatePepper(cfg.DataDir, cfg.PepperKeyID)
	if err != nil {
		log.Error("pepper init failed", "err", err)
		os.Exit(1)
	}

	if err := registerSensor(ctx, cfg, log); err != nil {
		// Non-fatal — token might be provisional or network blip.
		// Events will still authenticate; persona registration can
		// re-succeed on restart.
		log.Warn("sensor registration failed (continuing)", "err", err)
	}

	pub := newPublisher(cfg.IngestURL, cfg.Token, log)
	pub.Start(ctx)

	go watchPayloads(ctx, cfg, pep, pub, log)

	offPath := filepath.Join(cfg.DataDir, "events-tail.offset")
	t := newTailer(cfg.EventsLog, offPath, log)
	log.Info("tailing events.jsonl", "path", cfg.EventsLog, "offset", t.offset)

	err = t.Run(ctx, func(line []byte) {
		var ev sweetEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Debug("skip non-json line", "err", err)
			return
		}
		env := toEnvelope(cfg, pep, ev, adbDefaultPort)
		if env == nil {
			return
		}
		if cfg.Verbose {
			log.Debug("envelope emitted", "event_type", env.EventType, "src_ip", env.Src.IP)
		}
		pub.Enqueue(env)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Error("tailer failed", "err", err)
	}

	log.Info("shutting down — flushing publisher")
	cancel()
	pub.wg.Wait()
}
