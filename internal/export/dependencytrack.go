package export

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/redact"
)

func init() {
	Register(Plugin{
		Name:        "dependency-track",
		Description: "OWASP Dependency-Track: the CycloneDX SBOM of each target as a project BOM (POST /api/v1/bom, autoCreate)",
		Options:     []string{"url", "api_key_env"},
		New:         newDependencyTrack,
	})
}

type dependencyTrack struct {
	endpoint *url.URL
	key      string
	client   *http.Client
}

func newDependencyTrack(s Spec) (Exporter, error) {
	raw, err := s.Options.String("url", "")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New("option url is required: the Dependency-Track API server")
	}
	u, err := notify.ParseURL("url", raw)
	if err != nil {
		return nil, err
	}
	key, err := s.Secret("api_key_env")
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("option api_key_env is required: the variable holding an API key with BOM_UPLOAD (and PROJECT_CREATION_UPLOAD)")
	}
	return &dependencyTrack{endpoint: u.JoinPath("api/v1/bom"), key: key, client: s.HTTPClient()}, nil
}

// project names a target's Dependency-Track project: the repository, versioned by tag (and
// platform when the reference is monitored on several).
func project(t Target) (name, version string) {
	version = t.Tag
	if t.MultiPlatform {
		version += " (" + t.Platform + ")"
	}
	return t.Repository, version
}

// form is the multipart upload of one target.
func (d *dependencyTrack) form(t Target) (body []byte, contentType string, err error) {
	name, version := project(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, f := range [][2]string{{"autoCreate", "true"}, {"projectName", name}, {"projectVersion", version}} {
		if err := w.WriteField(f[0], f[1]); err != nil {
			return nil, "", err
		}
	}
	part, err := w.CreateFormFile("bom", "bom.cdx.json")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(t.SBOM); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func (d *dependencyTrack) Payloads(b Batch) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, t := range b.Targets {
		if t.SBOM != nil {
			name, version := project(t)
			out[fileName(name+"_"+version)+".cdx.json"] = t.SBOM
		}
	}
	return out, nil
}

func (d *dependencyTrack) Export(ctx context.Context, b Batch) (Result, error) {
	res := Result{Failed: map[string]string{}}
	for _, t := range b.Targets {
		if t.SBOM == nil {
			res.Failed[t.Ref] = "no CycloneDX SBOM stored for " + t.Digest + " yet"
			continue
		}
		body, ct, err := d.form(t)
		if err != nil {
			return res, err
		}
		err = notify.Post(ctx, d.client, d.endpoint, ct, body, http.Header{"X-Api-Key": {d.key}})
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err != nil {
			res.Failed[t.Ref] = redact.String(fmt.Sprint(err))
			continue
		}
		res.Sent++
	}
	return res, nil
}
