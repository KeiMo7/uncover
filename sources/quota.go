package sources

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

// ErrQuotaExhausted is returned when an engine has no budget left for the
// current window. Callers should skip that engine and keep the others.
var ErrQuotaExhausted = errors.New("engine quota exhausted")

// ErrRateLimitedExhausted is returned when an engine kept answering with
// HTTP 429 after all configured backoff retries. The local budget may still
// have room; the upstream asked us to stop.
var ErrRateLimitedExhausted = errors.New("engine rate limited")

// Skip / engine report reasons. These strings are part of the JSON report
// contract and must stay stable.
const (
	ReasonQuotaExhausted = "quota_exhausted"
	ReasonRateLimited    = "rate_limited"
	ReasonMissingKeys    = "missing_keys"
	ReasonQueryError     = "query_error"
)

// Engine report statuses.
const (
	StatusParticipated = "participated"
	StatusPartial      = "partial"
	StatusSkipped      = "skipped"
	StatusError        = "error"
)

// WindowType controls how budget is replenished.
type WindowType string

const (
	// WindowFixed resets the whole counter at one instant per window.
	WindowFixed WindowType = "fixed"
	// WindowRolling releases each call exactly one window after it was made.
	WindowRolling WindowType = "rolling"
)

const (
	defaultQuotaWindow       = 24 * time.Hour
	defaultQuotaRetries      = 2
	defaultQuotaBackoff      = 500 * time.Millisecond
	defaultQuotaBackoffLimit = 30 * time.Second
)

// SupportedEngines is the canonical list of engine names accepted by the
// quota configuration. It mirrors Service.AllAgents.
var SupportedEngines = []string{
	"shodan", "censys", "fofa", "shodan-idb", "quake", "hunter", "zoomeye",
	"netlas", "criminalip", "publicwww", "hunterhow", "google", "odin",
	"binaryedge", "onyphe", "driftnet", "greynoise", "daydaymap", "nerdydata",
	"scanmalware", "subdomaincenter",
}

var engineAliases = map[string]string{
	"subdomain-center": "subdomaincenter",
	"shodan_idb":       "shodan-idb",
	"zoom-eye":         "zoomeye",
}

func normalizeEngine(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if canonical, ok := engineAliases[name]; ok {
		return canonical
	}
	return name
}

func isSupportedEngine(name string) bool {
	for _, engine := range SupportedEngines {
		if engine == name {
			return true
		}
	}
	return false
}

// Duration is a YAML-friendly time.Duration. Strings such as "24h" and
// "500ms" are accepted, as are plain integers interpreted as seconds.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var asString string
	if err := value.Decode(&asString); err == nil {
		parsed, err := time.ParseDuration(asString)
		if err != nil {
			return fmt.Errorf("invalid duration %q", asString)
		}
		*d = Duration(parsed)
		return nil
	}
	var asInt int64
	if err := value.Decode(&asInt); err == nil {
		*d = Duration(time.Duration(asInt) * time.Second)
		return nil
	}
	return fmt.Errorf("invalid duration value")
}

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// WindowConfig describes the replenishment policy of a budget.
type WindowConfig struct {
	Type string   `yaml:"type"`
	Size Duration `yaml:"size"`
}

// RateConfig configures the per-engine request rate. It maps onto the
// existing ratelimit package; it is independent from the quota budget.
type RateConfig struct {
	Max       uint     `yaml:"max"`
	Per       Duration `yaml:"per"`
	Unlimited bool     `yaml:"unlimited"`
}

// EngineQuota is a per-engine quota override. A nil Limit means unlimited.
// An explicit `limit: 0` means the engine may not be called at all: it is
// reported as quota_exhausted and skipped.
type EngineQuota struct {
	Limit      *int          `yaml:"limit"`
	Unlimited  bool          `yaml:"unlimited"`
	Window     *WindowConfig `yaml:"window"`
	Rate       *RateConfig   `yaml:"rate"`
	MaxRetries *int          `yaml:"max_retries"`
}

// BackoffConfig controls retries after HTTP 429.
type BackoffConfig struct {
	Initial Duration `yaml:"initial"`
	Max     Duration `yaml:"max"`
}

// QuotaConfig is the on-disk quota configuration.
//
// Global fields (Window, Rate, MaxRetries, Backoff) apply to every engine.
// Defaults applies to every engine and is overridden by Engines.
type QuotaConfig struct {
	Window     *WindowConfig           `yaml:"window"`
	Rate       *RateConfig             `yaml:"rate"`
	MaxRetries *int                    `yaml:"max_retries"`
	Backoff    *BackoffConfig          `yaml:"backoff"`
	Defaults   *EngineQuota            `yaml:"defaults"`
	Engines    map[string]*EngineQuota `yaml:"engines"`
}

// LoadQuotaConfigFile reads and validates a quota YAML file.
func LoadQuotaConfigFile(path string) (*QuotaConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("quota configuration %s: %w", path, err)
	}
	cfg, err := ParseQuotaConfig(data)
	if err != nil {
		return nil, fmt.Errorf("quota configuration %s: %w", path, err)
	}
	return cfg, nil
}

// ParseQuotaConfig decodes a quota configuration and rejects unknown fields.
func ParseQuotaConfig(data []byte) (*QuotaConfig, error) {
	cfg := &QuotaConfig{}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("quota configuration is empty")
		}
		return nil, err
	}
	return cfg, nil
}

// Validate checks the configuration and returns an error naming the exact
// offending key. It is safe to call before a manager is built.
func (c *QuotaConfig) Validate(agents []string) error {
	if c == nil {
		return nil
	}
	if err := validateWindow("window", c.Window); err != nil {
		return err
	}
	if err := validateRate("rate", c.Rate); err != nil {
		return err
	}
	if c.MaxRetries != nil && *c.MaxRetries < 0 {
		return fmt.Errorf("max_retries: must be >= 0")
	}
	if err := validateBackoff("backoff", c.Backoff); err != nil {
		return err
	}
	if err := validateEngineQuota("defaults", c.Defaults); err != nil {
		return err
	}

	seen := make(map[string]string, len(c.Engines))
	names := make([]string, 0, len(c.Engines))
	for name := range c.Engines {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		canonical := normalizeEngine(name)
		if !isSupportedEngine(canonical) {
			return fmt.Errorf("engines.%s: unknown engine %q", name, name)
		}
		if previous, ok := seen[canonical]; ok {
			return fmt.Errorf("engines.%s: duplicate engine (already configured as %q)", name, previous)
		}
		seen[canonical] = name
		if err := validateEngineQuota("engines."+name, c.Engines[name]); err != nil {
			return err
		}
	}
	return nil
}

func validateWindow(path string, w *WindowConfig) error {
	if w == nil {
		return nil
	}
	switch WindowType(strings.ToLower(w.Type)) {
	case "", WindowFixed, WindowRolling:
	default:
		return fmt.Errorf("%s.type: must be %q or %q, got %q", path, WindowFixed, WindowRolling, w.Type)
	}
	if w.Size < 0 {
		return fmt.Errorf("%s.size: must be > 0", path)
	}
	return nil
}

func validateRate(path string, r *RateConfig) error {
	if r == nil {
		return nil
	}
	if r.Unlimited {
		return nil
	}
	if r.Max == 0 {
		return fmt.Errorf("%s.max: must be > 0 (use unlimited: true to disable)", path)
	}
	if r.Per <= 0 {
		return fmt.Errorf("%s.per: must be > 0", path)
	}
	return nil
}

func validateBackoff(path string, b *BackoffConfig) error {
	if b == nil {
		return nil
	}
	if b.Initial < 0 {
		return fmt.Errorf("%s.initial: must be >= 0", path)
	}
	if b.Max < 0 {
		return fmt.Errorf("%s.max: must be >= 0", path)
	}
	if b.Initial > 0 && b.Max > 0 && b.Initial > b.Max {
		return fmt.Errorf("%s.initial: must be <= %s.max", path, path)
	}
	return nil
}

func validateEngineQuota(path string, q *EngineQuota) error {
	if q == nil {
		return nil
	}
	if q.Unlimited && q.Limit != nil {
		return fmt.Errorf("%s: limit and unlimited are mutually exclusive", path)
	}
	if q.Limit != nil && *q.Limit < 0 {
		return fmt.Errorf("%s.limit: must be >= 0", path)
	}
	if err := validateWindow(path+".window", q.Window); err != nil {
		return err
	}
	if err := validateRate(path+".rate", q.Rate); err != nil {
		return err
	}
	if q.MaxRetries != nil && *q.MaxRetries < 0 {
		return fmt.Errorf("%s.max_retries: must be >= 0", path)
	}
	return nil
}

// ValidateForAgents additionally cross-checks engine names in the config
// against the agents actually requested. It deliberately does not error for
// config entries about engines not in use: config files are shared between
// runs. It does catch engines that are requested but unknown to uncover.
func (c *QuotaConfig) ValidateForAgents(agents []string) error {
	if c == nil {
		return nil
	}
	if err := c.Validate(agents); err != nil {
		return err
	}
	for _, agent := range agents {
		if !isSupportedEngine(normalizeEngine(agent)) {
			return fmt.Errorf("unknown engine %q", agent)
		}
	}
	return nil
}

// RateLimit is the effective per-engine rate used to build the session
// limiter. A nil value means "keep the built-in default".
type RateLimit struct {
	Max       uint
	Per       time.Duration
	Unlimited bool
}

type effectiveQuota struct {
	limit          *int
	windowType     WindowType
	windowSize     time.Duration
	rate           *RateLimit
	maxRetries     int
	backoffInitial time.Duration
	backoffMax     time.Duration
}

func cloneInt(v *int) *int {
	if v == nil {
		return nil
	}
	out := *v
	return &out
}

func (c *QuotaConfig) effective(engine string) effectiveQuota {
	eff := effectiveQuota{
		windowType:     WindowFixed,
		windowSize:     defaultQuotaWindow,
		maxRetries:     defaultQuotaRetries,
		backoffInitial: defaultQuotaBackoff,
		backoffMax:     defaultQuotaBackoffLimit,
	}
	if c == nil {
		return eff
	}
	// Global values.
	if c.Window != nil {
		if t := strings.ToLower(c.Window.Type); t != "" {
			eff.windowType = WindowType(t)
		}
		if c.Window.Size > 0 {
			eff.windowSize = time.Duration(c.Window.Size)
		}
	}
	if c.Rate != nil {
		eff.rate = &RateLimit{Max: c.Rate.Max, Per: time.Duration(c.Rate.Per), Unlimited: c.Rate.Unlimited}
	}
	if c.MaxRetries != nil {
		eff.maxRetries = *c.MaxRetries
	}
	if c.Backoff != nil {
		if c.Backoff.Initial > 0 {
			eff.backoffInitial = time.Duration(c.Backoff.Initial)
		}
		if c.Backoff.Max > 0 {
			eff.backoffMax = time.Duration(c.Backoff.Max)
		}
	}
	apply := func(q *EngineQuota) {
		if q == nil {
			return
		}
		if q.Unlimited {
			eff.limit = nil
		} else if q.Limit != nil {
			eff.limit = cloneInt(q.Limit)
		}
		if q.Window != nil {
			if t := strings.ToLower(q.Window.Type); t != "" {
				eff.windowType = WindowType(t)
			}
			if q.Window.Size > 0 {
				eff.windowSize = time.Duration(q.Window.Size)
			}
		}
		if q.Rate != nil {
			eff.rate = &RateLimit{Max: q.Rate.Max, Per: time.Duration(q.Rate.Per), Unlimited: q.Rate.Unlimited}
		}
		if q.MaxRetries != nil {
			eff.maxRetries = *q.MaxRetries
		}
	}
	apply(c.Defaults)
	if c.Engines != nil {
		if q, ok := c.Engines[engine]; ok {
			apply(q)
		} else {
			// The config may use an alias (for example "subdomain-center").
			for name, q := range c.Engines {
				if normalizeEngine(name) == engine {
					apply(q)
					break
				}
			}
		}
	}
	return eff
}

// RateLimitOverrides returns the effective rate overrides for the requested
// agents. Engines without a configured rate are omitted so the session keeps
// using the built-in DefaultRateLimits. A nil manager yields no overrides.
func (m *QuotaManager) RateLimitOverrides(agents []string) map[string]*RateLimit {
	if m == nil {
		return nil
	}
	out := make(map[string]*RateLimit)
	for _, agent := range agents {
		engine := normalizeEngine(agent)
		if st := m.state(engine); st != nil && st.rate != nil {
			out[engine] = st.rate
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// QuotaToken represents one reserved call. Commit marks the call as used;
// Release gives the budget back. Both are idempotent.
type QuotaToken struct {
	state     *engineQuota
	id        uint64
	epoch     int
	void      bool
	counted   bool // reservation occupies a slot in the budget
	committed bool
	released  bool
}

type quotaToken struct {
	id uint64
	at time.Time
}

type engineQuota struct {
	name        string
	limit       *int
	windowType  WindowType
	windowSize  time.Duration
	rate        *RateLimit
	maxRetries  int
	backoffInit time.Duration
	backoffMax  time.Duration
	unlimited   bool

	mu          sync.Mutex
	epoch       int
	windowStart time.Time
	used        int // fixed window: reserved + committed
	rolling     *list.List
	index       map[uint64]*list.Element
	nextID      uint64

	attempted      int
	committed      int
	released       int
	quotaBlocked   bool
	rateLimited    bool
	rateExhausted  bool
	failOpen       bool
	failOpenReason string
}

func newEngineQuota(name string, cfg effectiveQuota) *engineQuota {
	q := &engineQuota{
		name:        name,
		limit:       cfg.limit,
		windowType:  cfg.windowType,
		windowSize:  cfg.windowSize,
		rate:        cfg.rate,
		maxRetries:  cfg.maxRetries,
		backoffInit: cfg.backoffInitial,
		backoffMax:  cfg.backoffMax,
		unlimited:   cfg.limit == nil,
	}
	if q.windowType == "" {
		q.windowType = WindowFixed
	}
	if q.windowSize <= 0 {
		q.windowSize = defaultQuotaWindow
	}
	if q.windowType == WindowRolling {
		q.rolling = list.New()
		q.index = make(map[uint64]*list.Element)
	}
	return q
}

// QuotaManager enforces per-engine call budgets. The zero value is not
// usable; construct it with NewQuotaManager.
type QuotaManager struct {
	engines   map[string]*engineQuota
	requested map[string]struct{}
	now       func() time.Time
	warn      func(format string, args ...any)

	// onAcquire is used by tests to simulate an accounting failure.
	onAcquire func(engine string)
}

// NewQuotaManager builds a manager for the requested agents. A nil config
// returns (nil, nil), which means quota management is disabled.
func NewQuotaManager(cfg *QuotaConfig, agents []string) (*QuotaManager, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.ValidateForAgents(agents); err != nil {
		return nil, err
	}
	m := &QuotaManager{
		engines:   make(map[string]*engineQuota),
		requested: make(map[string]struct{}, len(agents)),
		now:       time.Now,
		warn: func(format string, args ...any) {
			gologger.Warning().Msgf(format, args...)
		},
	}
	add := func(name string) {
		engine := normalizeEngine(name)
		if _, ok := m.engines[engine]; ok {
			return
		}
		m.engines[engine] = newEngineQuota(engine, cfg.effective(engine))
	}
	for _, agent := range agents {
		engine := normalizeEngine(agent)
		m.requested[engine] = struct{}{}
		add(engine)
	}
	for name := range cfg.Engines {
		add(name)
	}
	return m, nil
}

func (m *QuotaManager) state(engine string) *engineQuota {
	if m == nil {
		return nil
	}
	return m.engines[normalizeEngine(engine)]
}

// Has reports whether the engine has a quota state (even unlimited).
func (m *QuotaManager) Has(engine string) bool {
	return m.state(engine) != nil
}

// Requested reports whether the engine was part of the agents passed to
// NewQuotaManager. It is used to keep shared config files from inflating a
// run report with engines the run never touches.
func (m *QuotaManager) Requested(engine string) bool {
	if m == nil {
		return false
	}
	_, ok := m.requested[normalizeEngine(engine)]
	return ok
}

// CanonicalEngineName normalises an engine name to its report/state key.
func CanonicalEngineName(engine string) string {
	return normalizeEngine(engine)
}

// SkipReason explains why an engine is currently unavailable. It is used for
// pre-flight skips and for the all-skipped error message.
func (m *QuotaManager) SkipReason(engine string) (reason, message string) {
	st := m.state(engine)
	if st == nil {
		return "", ""
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rateExhausted {
		return ReasonRateLimited, fmt.Sprintf("%s kept answering HTTP 429 after all retries", engine)
	}
	if st.failOpen || st.unlimited {
		return "", ""
	}
	now := m.now()
	if st.windowType == WindowRolling {
		st.pruneLocked(now)
		if st.rolling.Len() >= *st.limit {
			return ReasonQuotaExhausted, fmt.Sprintf("%s has used %d/%d calls in the rolling window", engine, st.rolling.Len(), *st.limit)
		}
		return "", ""
	}
	st.resetLocked(now)
	if st.used >= *st.limit {
		return ReasonQuotaExhausted, fmt.Sprintf("%s has used %d/%d calls in the current window", engine, st.used, *st.limit)
	}
	return "", ""
}

// Available is a cheap pre-check used to skip an engine before it is
// started. The authoritative check is Acquire, which is atomic.
func (m *QuotaManager) Available(engine string) bool {
	st := m.state(engine)
	if st == nil {
		return true
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.availableLocked(m.now())
}

func (st *engineQuota) availableLocked(now time.Time) bool {
	if st.rateExhausted {
		return false
	}
	if st.failOpen || st.unlimited {
		return true
	}
	if st.windowType == WindowRolling {
		st.pruneLocked(now)
		return st.rolling.Len() < *st.limit
	}
	st.resetLocked(now)
	return st.used < *st.limit
}

func (st *engineQuota) resetLocked(now time.Time) {
	if st.windowStart.IsZero() {
		st.windowStart = now
		return
	}
	if !now.Before(st.windowStart.Add(st.windowSize)) {
		st.epoch++
		st.windowStart = now
		st.used = 0
	}
}

func (st *engineQuota) pruneLocked(now time.Time) {
	cutoff := now.Add(-st.windowSize)
	for front := st.rolling.Front(); front != nil; front = st.rolling.Front() {
		token := front.Value.(*quotaToken)
		if token.at.After(cutoff) {
			break
		}
		st.rolling.Remove(front)
		delete(st.index, token.id)
	}
}

// Acquire reserves one call for the engine. It returns ErrQuotaExhausted if
// no budget is left. The reservation is atomic across goroutines.
//
// If quota accounting fails unexpectedly, the engine is switched to
// fail-open (unlimited) for the rest of the run and a warning is emitted.
func (m *QuotaManager) Acquire(engine string) (token *QuotaToken, err error) {
	st := m.state(engine)
	if st == nil {
		return &QuotaToken{void: true}, nil
	}

	st.mu.Lock()
	defer func() {
		if r := recover(); r != nil {
			// The lock is still held here, so mutating state is safe.
			st.failOpen = true
			st.failOpenReason = fmt.Sprint(r)
			m.warn("quota accounting failed for engine %s: %v; falling back to unlimited", engine, r)
			token = &QuotaToken{void: true}
			err = nil
		}
		st.mu.Unlock()
	}()

	if m.onAcquire != nil {
		m.onAcquire(engine)
	}

	now := m.now()
	st.attempted++
	if st.rateExhausted {
		return nil, fmt.Errorf("%w: %s exhausted its 429 retries", ErrRateLimitedExhausted, st.name)
	}
	if st.failOpen || st.unlimited {
		st.nextID++
		return &QuotaToken{state: st, id: st.nextID}, nil
	}

	if st.windowType == WindowRolling {
		st.pruneLocked(now)
		if st.rolling.Len() >= *st.limit {
			st.quotaBlocked = true
			return nil, fmt.Errorf("%w: %s has used %d/%d calls in the rolling window", ErrQuotaExhausted, st.name, st.rolling.Len(), *st.limit)
		}
		st.nextID++
		entry := &quotaToken{id: st.nextID, at: now}
		element := st.rolling.PushBack(entry)
		st.index[entry.id] = element
		return &QuotaToken{state: st, id: entry.id, epoch: st.epoch, counted: true}, nil
	}

	st.resetLocked(now)
	if st.used >= *st.limit {
		st.quotaBlocked = true
		return nil, fmt.Errorf("%w: %s has used %d/%d calls in the current window", ErrQuotaExhausted, st.name, st.used, *st.limit)
	}
	st.used++
	st.nextID++
	return &QuotaToken{state: st, id: st.nextID, epoch: st.epoch, counted: true}, nil
}

// Commit marks a reserved call as used. It is safe to call after Release.
func (m *QuotaManager) Commit(token *QuotaToken) {
	if token == nil || token.void || token.state == nil {
		return
	}
	st := token.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if token.released || token.committed {
		return
	}
	token.committed = true
	st.committed++
}

// Release gives a reserved call back. Calling Release after Commit, or more
// than once, is a no-op.
func (m *QuotaManager) Release(token *QuotaToken) {
	if token == nil || token.void || token.state == nil {
		return
	}
	st := token.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if token.released || token.committed {
		return
	}
	token.released = true
	st.released++
	if !token.counted {
		return
	}
	if st.windowType == WindowRolling {
		if element, ok := st.index[token.id]; ok {
			st.rolling.Remove(element)
			delete(st.index, token.id)
		}
		return
	}
	// Only give the token back to the window it was taken from. If the window
	// rolled while the call was in flight, the new window already has a full
	// budget and must not be incremented.
	if token.epoch == st.epoch && st.used > 0 {
		st.used--
	}
}

// RateLimitRetries returns the number of 429 backoff retries for an engine.
func (m *QuotaManager) RateLimitRetries(engine string) int {
	st := m.state(engine)
	if st == nil {
		return 0
	}
	return st.maxRetries
}

// Backoff returns the wait before retry number attempt (0-based).
func (m *QuotaManager) Backoff(engine string, attempt int) time.Duration {
	st := m.state(engine)
	if st == nil {
		return defaultQuotaBackoff
	}
	initial := st.backoffInit
	if initial <= 0 {
		initial = defaultQuotaBackoff
	}
	maxWait := st.backoffMax
	if maxWait <= 0 {
		maxWait = defaultQuotaBackoffLimit
	}
	wait := initial
	for i := 0; i < attempt; i++ {
		wait *= 2
		if wait > maxWait {
			return maxWait
		}
	}
	if wait > maxWait {
		return maxWait
	}
	return wait
}

// MarkRateLimited records that an engine answered 429 at least once.
func (m *QuotaManager) MarkRateLimited(engine string) {
	st := m.state(engine)
	if st == nil {
		return
	}
	st.mu.Lock()
	st.rateLimited = true
	st.mu.Unlock()
}

// MarkRateExhausted stops the engine for the rest of the run after all 429
// retries were spent. The engine is reported as rate_limited.
func (m *QuotaManager) MarkRateExhausted(engine string) {
	st := m.state(engine)
	if st == nil {
		return
	}
	st.mu.Lock()
	st.rateLimited = true
	st.rateExhausted = true
	st.mu.Unlock()
}

// EngineUsage is a point-in-time view of one engine's budget.
type EngineUsage struct {
	Engine         string
	Limit          *int
	Used           int // committed calls this run
	Attempted      int
	Released       int
	Reserved       int // reserved but not yet settled
	Remaining      *int
	WindowType     string
	WindowSize     time.Duration
	QuotaBlocked   bool
	RateLimited    bool
	RateExhausted  bool
	FailOpen       bool
	FailOpenReason string
}

// Usage returns the current usage for one engine.
func (m *QuotaManager) Usage(engine string) EngineUsage {
	st := m.state(engine)
	if st == nil {
		return EngineUsage{Engine: normalizeEngine(engine), WindowType: string(WindowFixed)}
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	usage := EngineUsage{
		Engine:         st.name,
		Limit:          cloneInt(st.limit),
		Used:           st.committed,
		Attempted:      st.attempted,
		Released:       st.released,
		WindowType:     string(st.windowType),
		WindowSize:     st.windowSize,
		QuotaBlocked:   st.quotaBlocked,
		RateLimited:    st.rateLimited,
		RateExhausted:  st.rateExhausted,
		FailOpen:       st.failOpen,
		FailOpenReason: st.failOpenReason,
	}
	if st.unlimited || st.limit == nil || st.failOpen {
		return usage
	}
	var inWindow int
	if st.windowType == WindowRolling {
		st.pruneLocked(m.now())
		inWindow = st.rolling.Len()
	} else {
		inWindow = st.used
	}
	usage.Reserved = inWindow - st.committed
	if usage.Reserved < 0 {
		usage.Reserved = 0
	}
	remaining := *st.limit - inWindow
	if remaining < 0 {
		remaining = 0
	}
	usage.Remaining = &remaining
	return usage
}

// ResetRun clears per-run counters while keeping the remaining budget.
// QuotaManager is normally one per Service, so this is only needed when a
// long-lived Service executes several independent runs.
func (m *QuotaManager) ResetRun() {
	if m == nil {
		return
	}
	for _, st := range m.engines {
		st.mu.Lock()
		st.attempted = 0
		st.committed = 0
		st.released = 0
		st.quotaBlocked = false
		st.rateLimited = false
		st.rateExhausted = false
		st.mu.Unlock()
	}
}

// Report types. The JSON shape is a stable contract (schema v1).

// SkippedEngine describes one engine that produced no results.
type SkippedEngine struct {
	Engine string `json:"engine"`
	Reason string `json:"reason"`
	Error  string `json:"error,omitempty"`
}

// EngineReport is the per-engine section of a run report.
type EngineReport struct {
	Engine         string `json:"engine"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
	Error          string `json:"error,omitempty"`
	CallsUsed      int    `json:"calls_used"`
	CallsAttempted int    `json:"calls_attempted"`
	Limit          *int   `json:"limit"`
	Remaining      *int   `json:"remaining"`
	Window         string `json:"window,omitempty"`
	QuotaExhausted bool   `json:"quota_exhausted,omitempty"`
	RateLimited    bool   `json:"rate_limited,omitempty"`
	FailOpen       bool   `json:"fail_open,omitempty"`
	FailOpenReason string `json:"fail_open_reason,omitempty"`
	Unconfigured   bool   `json:"unconfigured,omitempty"`
}

// RunReport is the machine-readable result of one Execute call.
type RunReport struct {
	Schema       string          `json:"schema"`
	Enabled      bool            `json:"enabled"`
	GeneratedAt  string          `json:"generated_at,omitempty"`
	Engines      []EngineReport  `json:"engines"`
	Participated []string        `json:"participated"`
	Skipped      []SkippedEngine `json:"skipped"`
}

// RetryAfterDuration parses a Retry-After header. It returns 0 when absent
// or invalid so the caller can fall back to exponential backoff.
func RetryAfterDuration(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := parseHTTPDate(value); err == nil {
		delta := time.Until(when)
		if delta > 0 {
			return delta
		}
	}
	return 0
}

func parseHTTPDate(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC1123, value); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC1123Z, value)
}
