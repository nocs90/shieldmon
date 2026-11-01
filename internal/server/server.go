// Package server is `shieldmon serve`'s HTTP API (docs/adr/0031-server-mode.md): read
// findings, targets, health and reports; triage and record decisions as an authenticated,
// role-checked identity; start a monitoring cycle. It serves JSON and report formats only.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/priority"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

// maxBody bounds a request body.
const maxBody = 64 << 10

// Status is the scheduler's state, for GET /api/v1/status.
type Status struct {
	Scheduler    bool          `json:"scheduler"`
	Interval     time.Duration `json:"interval_seconds"`
	Running      bool          `json:"running"`
	LastStarted  time.Time     `json:"last_started,omitzero"`
	LastFinished time.Time     `json:"last_finished,omitzero"`
	LastStatus   string        `json:"last_status,omitempty"`
	LastRunID    int64         `json:"last_run_id,omitempty"`
	LastError    string        `json:"last_error,omitempty"`
	NextAt       time.Time     `json:"next_at,omitzero"`
}

// MarshalJSON writes the interval in seconds.
func (s Status) MarshalJSON() ([]byte, error) {
	type plain Status
	p := plain(s)
	p.Interval = s.Interval / time.Second
	return json.Marshal(p)
}

// Deps is what the API serves from.
type Deps struct {
	Store  *store.Store
	Policy lifecycle.Policy
	Auth   Authenticator
	// Score ranks a finding now (ADR 0020, with runtime context where configured).
	Score func(store.Finding) priority.Score
	// Monthly builds the monthly report of the month containing t.
	Monthly func(ctx context.Context, t time.Time) (report.Monthly, error)
	Status  func() Status
	// Trigger starts a monitoring cycle now; false when one is running.
	Trigger func() bool
	Now     func() time.Time
	Log     *slog.Logger
}

// Handler returns the API.
func Handler(d Deps) http.Handler {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	a := &api{Deps: d, heavy: make(chan struct{}, maxHeavy)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/v1/findings", a.with(RoleViewer, a.listFindings))
	mux.Handle("GET /api/v1/findings/{id}", a.with(RoleViewer, a.showFinding))
	mux.Handle("POST /api/v1/findings/{id}/transition", a.with(RoleTriager, a.transition))
	mux.Handle("POST /api/v1/findings/{id}/decision", a.with(RoleTriager, a.decide))
	mux.Handle("GET /api/v1/targets", a.with(RoleViewer, a.targets))
	mux.Handle("GET /api/v1/health", a.with(RoleViewer, a.health))
	mux.Handle("GET /api/v1/reports/monthly", a.with(RoleViewer, a.monthly))
	mux.Handle("GET /api/v1/status", a.with(RoleViewer, a.status))
	mux.Handle("POST /api/v1/cycles", a.with(RoleAdmin, a.cycle))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) { writeError(w, http.StatusNotFound, "no such endpoint") })
	return secure(mux)
}

type api struct {
	Deps
	heavy chan struct{}
}

// maxHeavy is how many expensive requests (priority ranking, reports) run at once.
const maxHeavy = 2

type identityKey struct{}

// with authenticates the request and requires role.
func (a *api) with(role Role, h func(http.ResponseWriter, *http.Request, Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := a.Auth.Authenticate(r)
		if !ok {
			// The request's address only: never the header, which may hold a secret.
			a.Log.Warn("api authentication failed", "remote", r.RemoteAddr, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="shieldmon"`)
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if id.Role < role {
			writeError(w, http.StatusForbidden, fmt.Sprintf("%s needs the %s role", r.URL.Path, role))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, id)), id)
	})
}

// secure sets the headers of every response: an API, never rendered or cached by browsers.
func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Cache-Control", "no-store")
		hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		hd.Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		writeError(w, http.StatusInternalServerError, "encoding failed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(b.Bytes())
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// fail answers a store or policy error: not found, refused by the lifecycle, or internal
// (logged, not shown).
func (a *api) fail(w http.ResponseWriter, r *http.Request, err error, refused int) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case refused != 0 && errors.Is(err, lifecycle.ErrRefused):
		writeError(w, refused, redact.Error(err))
	default:
		a.Log.Error("api request failed", "path", r.URL.Path, "error", redact.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func findingID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// decodeBody reads a bounded JSON body into v, refusing unknown fields.
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("request body: %w", err)
	}
	if dec.More() {
		return errors.New("request body: one JSON object expected")
	}
	return nil
}

type findingJSON struct {
	store.Finding
	Severity string         `json:"severity"`
	Priority priority.Score `json:"priority"`
	SLADue   time.Time      `json:"sla_due,omitzero"`
}

func (a *api) row(f store.Finding) findingJSON {
	out := findingJSON{Finding: f, Severity: f.Severity.String(), SLADue: a.Policy.SLADue(lifecycle.Subject{Severity: f.Severity, FirstDetected: f.FirstDetected})}
	if a.Score != nil {
		out.Priority = a.Score(f)
	}
	return out
}

const maxLimit = 1000

func (a *api) listFindings(w http.ResponseWriter, r *http.Request, _ Identity) {
	q := r.URL.Query()
	flt := store.FindingFilter{Digest: q.Get("digest"), VulnID: q.Get("vuln"), Limit: 100}
	for _, s := range q["state"] {
		st, err := model.ParseState(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		flt.States = append(flt.States, st)
	}
	if len(flt.States) == 0 {
		flt.States = []model.State{model.StateOpen, model.StateReopened, model.StateTriaged, model.StateInRemediation}
	}
	if s := q.Get("severity"); s != "" {
		if flt.MinSeverity = model.ParseSeverity(s); flt.MinSeverity == model.SeverityUnknown && s != "unknown" {
			writeError(w, http.StatusBadRequest, "severity: want critical, high, medium, low, negligible or unknown")
			return
		}
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxLimit {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("limit: want 1 to %d", maxLimit))
			return
		}
		flt.Limit = n
	}
	sortBy := q.Get("sort")
	if sortBy != "" && sortBy != "severity" && sortBy != "priority" {
		writeError(w, http.StatusBadRequest, "sort: want severity or priority")
		return
	}
	limit := flt.Limit
	if sortBy == "priority" {
		// Rank the most severe maxRanked, then keep the top: bounded work per request.
		flt.Limit = maxRanked
		if !a.acquire(w, r) {
			return
		}
		defer a.release()
	}
	fs, err := a.Store.ListFindings(r.Context(), flt)
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	rows := make([]findingJSON, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, a.row(f))
	}
	if sortBy == "priority" {
		// Stable: equal priorities keep the store's order (most severe first).
		slices.SortStableFunc(rows, func(x, y findingJSON) int { return y.Priority.Value - x.Priority.Value })
		rows = rows[:min(limit, len(rows))]
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": rows, "count": len(rows), "truncated": sortBy == "priority" && len(fs) == maxRanked})
}

// maxRanked bounds the findings one priority-sorted request ranks.
const maxRanked = 20_000

// acquire waits for one of the slots of expensive requests (ranking, reports), or answers
// 503 when the client gives up first.
func (a *api) acquire(w http.ResponseWriter, r *http.Request) bool {
	select {
	case a.heavy <- struct{}{}:
		return true
	case <-r.Context().Done():
		writeError(w, http.StatusServiceUnavailable, "busy")
		return false
	}
}

func (a *api) release() { <-a.heavy }

type eventJSON struct {
	At     time.Time   `json:"at"`
	From   model.State `json:"from,omitempty"`
	To     model.State `json:"to"`
	Actor  string      `json:"actor"`
	Reason string      `json:"reason,omitempty"`
	ScanID int64       `json:"scan_id,omitempty"`
}

type decisionJSON struct {
	ID            int64       `json:"id"`
	State         model.State `json:"state"`
	Deviation     string      `json:"deviation,omitempty"`
	Justification string      `json:"justification"`
	Author        string      `json:"author"`
	CreatedAt     time.Time   `json:"created_at"`
	ExpiresAt     time.Time   `json:"expires_at,omitzero"`
}

func (a *api) showFinding(w http.ResponseWriter, r *http.Request, _ Identity) {
	id, ok := findingID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid finding ID")
		return
	}
	f, err := a.Store.GetFinding(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	evs, err := a.Store.Events(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	ds, err := a.Store.Decisions(r.Context(), id)
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	out := struct {
		findingJSON
		Events    []eventJSON    `json:"events"`
		Decisions []decisionJSON `json:"decisions"`
	}{findingJSON: a.row(f), Events: []eventJSON{}, Decisions: []decisionJSON{}}
	for _, e := range evs {
		out.Events = append(out.Events, eventJSON{At: e.At, From: e.From, To: e.To, Actor: e.Actor, Reason: e.Reason, ScanID: e.ScanID})
	}
	for _, d := range ds {
		out.Decisions = append(out.Decisions, decisionJSON{
			ID: d.ID, State: d.State, Deviation: d.Deviation, Justification: d.Justification,
			Author: d.Author, CreatedAt: d.CreatedAt, ExpiresAt: d.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// triageStates are the states a triager moves a finding to by hand; closing a finding needs
// scan evidence (lifecycle.Reconcile), never a request.
var triageStates = map[model.State]bool{model.StateTriaged: true, model.StateInRemediation: true, model.StateOpen: true}

func (a *api) transition(w http.ResponseWriter, r *http.Request, id Identity) {
	fid, ok := findingID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid finding ID")
		return
	}
	var req struct {
		To   model.State `json:"to"`
		Note string      `json:"note"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !triageStates[req.To] {
		writeError(w, http.StatusUnprocessableEntity, "to: want triaged, in_remediation or open (decisions have their own endpoint; closure needs scan evidence)")
		return
	}
	if err := a.Store.Transition(r.Context(), fid, req.To, id.Actor(), req.Note, a.Now()); err != nil {
		a.fail(w, r, err, http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": fid, "state": req.To, "actor": id.Actor()})
}

func (a *api) decide(w http.ResponseWriter, r *http.Request, id Identity) {
	fid, ok := findingID(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid finding ID")
		return
	}
	var req struct {
		State         model.State `json:"state"`
		Justification string      `json:"justification"`
		Expires       string      `json:"expires"`
		Deviation     string      `json:"deviation"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.State != model.StateRiskAccepted && req.State != model.StateNotAffected {
		writeError(w, http.StatusUnprocessableEntity, "state: want risk_accepted or not_affected")
		return
	}
	dev, err := lifecycle.ParseDeviation(req.Deviation)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	// The author is who authenticated, never a field of the request.
	d := lifecycle.Decision{State: req.State, Deviation: dev, Justification: req.Justification, Author: id.Actor()}
	if req.Expires != "" {
		t, err := time.Parse(time.DateOnly, req.Expires)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "expires: want YYYY-MM-DD")
			return
		}
		d.ExpiresAt = t.UTC()
	}
	applied, err := a.Store.ApplyDecision(r.Context(), fid, d, a.Policy, a.Now())
	if err != nil {
		a.fail(w, r, err, http.StatusUnprocessableEntity)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": fid, "state": applied.State, "deviation": applied.Deviation, "author": applied.Author, "expires_at": applied.ExpiresAt,
	})
}

func (a *api) targets(w http.ResponseWriter, r *http.Request, _ Identity) {
	ts, err := a.Store.ListTargets(r.Context())
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	type targetJSON struct {
		ID             int64     `json:"id"`
		Ref            string    `json:"ref"`
		Platform       string    `json:"platform"`
		CurrentDigest  string    `json:"current_digest,omitempty"`
		CreatedAt      time.Time `json:"created_at"`
		LastResolvedAt time.Time `json:"last_resolved_at,omitzero"`
		RetiredAt      time.Time `json:"retired_at,omitzero"`
	}
	out := make([]targetJSON, 0, len(ts))
	for _, t := range ts {
		out = append(out, targetJSON{t.ID, t.Ref, t.Platform, t.CurrentDigest, t.CreatedAt, t.LastResolvedAt, t.RetiredAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out, "count": len(out)})
}

func (a *api) health(w http.ResponseWriter, r *http.Request, _ Identity) {
	hs, err := a.Store.ListHealth(r.Context(), r.URL.Query().Get("all") == "true")
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	type healthJSON struct {
		ID          int64     `json:"id"`
		Check       string    `json:"check"`
		Subject     string    `json:"subject"`
		State       string    `json:"state"`
		Severity    string    `json:"severity"`
		Detail      string    `json:"detail"`
		FirstSeen   time.Time `json:"first_seen"`
		LastSeen    time.Time `json:"last_seen"`
		ResolvedAt  time.Time `json:"resolved_at,omitzero"`
		Occurrences int       `json:"occurrences"`
	}
	out := make([]healthJSON, 0, len(hs))
	for _, h := range hs {
		out = append(out, healthJSON{h.ID, h.Check, h.Subject, h.State, h.Severity, h.Detail, h.FirstSeen, h.LastSeen, h.ResolvedAt, h.Occurrences})
	}
	writeJSON(w, http.StatusOK, map[string]any{"health": out, "count": len(out)})
}

func (a *api) monthly(w http.ResponseWriter, r *http.Request, _ Identity) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "json"
	}
	f, ok := report.LookupFormat(format)
	if !ok {
		writeError(w, http.StatusBadRequest, "format: unsupported")
		return
	}
	at := a.Now()
	if m := q.Get("month"); m != "" {
		t, err := time.Parse("2006-01", m)
		if err != nil || t.Year() < 2000 || t.After(at) {
			writeError(w, http.StatusBadRequest, "month: want YYYY-MM, from 2000 up to this month")
			return
		}
		at = t
	}
	if !a.acquire(w, r) {
		return
	}
	defer a.release()
	rep, err := a.Monthly(r.Context(), at)
	if err != nil {
		a.fail(w, r, err, 0)
		return
	}
	var b bytes.Buffer
	if err := f.Render(&b, rep); err != nil {
		a.fail(w, r, err, 0)
		return
	}
	w.Header().Set("Content-Type", f.MediaType)
	if strings.HasPrefix(f.MediaType, "text/html") {
		// The report styles itself inline, loads nothing and needs no script, form or base.
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox")
	}
	if f.Download {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="shieldmon-%s.%s"`, at.Format("2006-01"), f.Name))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bytes())
}

func (a *api) status(w http.ResponseWriter, _ *http.Request, _ Identity) {
	writeJSON(w, http.StatusOK, a.Status())
}

func (a *api) cycle(w http.ResponseWriter, r *http.Request, id Identity) {
	if !a.Trigger() {
		writeError(w, http.StatusConflict, "a monitoring cycle is running")
		return
	}
	a.Log.Info("monitoring cycle requested", "by", id.Name)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}
