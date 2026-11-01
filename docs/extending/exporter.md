# Writing an exporter

An exporter hands ShieldMon's current state to a portfolio tool
([ADR 0027](../adr/0027-exporters.md)). It gets a batch (every monitored target with its
CycloneDX SBOM and its open and risk-accepted findings) and sends it; it never reads the
store, never changes a finding, and never retries by itself: the next `shieldmon export`
sends the current state again.

## 1. Implement `export.Exporter` (and `export.Payloader` for `--dry-run`)

```go
// internal/export/acme.go
type acme struct {
	endpoint *url.URL
	key      string // from the environment, never from config
	client   *http.Client
}

func (a *acme) Export(ctx context.Context, b export.Batch) (export.Result, error) {
	res := export.Result{Failed: map[string]string{}}
	for _, t := range b.Targets {
		body, _ := json.Marshal(t.Findings) // map to the tool's format; bound every field
		err := notify.Post(ctx, a.client, a.endpoint, "application/json", body,
			http.Header{"Authorization": {"Bearer " + a.key}})
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err != nil {
			res.Failed[t.Ref] = redact.String(err.Error())
			continue
		}
		res.Sent++
	}
	return res, nil
}
```

Findings carry hostile text (package names, titles from scanner output): encode them for the
tool's format, and cut fields to the tool's limits, which otherwise fail the import.

## 2. Register it

```go
func init() {
	export.Register(export.Plugin{
		Name: "acme", Description: "ACME portfolio: findings per target",
		Options: []string{"url", "api_key_env"},
		New: func(s export.Spec) (export.Exporter, error) {
			raw, _ := s.Options.String("url", "")
			u, err := notify.ParseURL("url", raw) // https, or http to localhost
			if err != nil {
				return nil, err
			}
			key, err := s.Secret("api_key_env")
			if err != nil || key == "" {
				return nil, errors.New("option api_key_env is required")
			}
			return &acme{endpoint: u, key: key, client: s.HTTPClient()}, nil
		},
	})
}
```

`s.HTTPClient()` follows no redirect and times out; `notify.Post` checks the answer, bounds
it, and names only host and status in errors.

## 3. Pass the conformance kit

```go
func TestACMEConformance(t *testing.T) {
	exporttest.CheckExporter(t, exporttest.Fixture{
		Name: "acme", Secret: "s3cr3t-value", AuthHeader: "Authorization",
		Options: func(u string) map[string]any { return map[string]any{"url": u, "api_key_env": "ACME_KEY"} },
	})
}
```

It sends a hostile batch and checks: one request per target, the credential only in its
header (never in a body or an error, even when the endpoint echoes the request), no redirect
followed, cancellation honoured, and dry-run payloads that are valid JSON with plain names.

## 4. Document it

A row in [docs/processes/exports.md](../processes/exports.md): what the tool gets per target
and which permissions its API key needs.
