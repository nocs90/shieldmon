// Package manifests extracts the images Kubernetes manifests run: rendered Helm charts
// (`helm template`), kustomize builds, or `kubectl get -o yaml|json` (docs/adr/0030-manifest-images.md).
// Manifests are hostile input (third-party charts): sizes are bounded, and nothing in them
// is executed or fetched.
package manifests

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Limits on one input.
const (
	MaxBytes = 64 << 20
	// MaxObjectBytes bounds one YAML document or one item of a JSON List before it is
	// decoded: a decoded tree costs many times its text. The API server stores at most
	// about 1.5 MiB per object.
	MaxObjectBytes = 2 << 20
	MaxObjects     = 100_000
	// MaxImages bounds the distinct images one input may add.
	MaxImages = 10_000
	// maxWhere keeps the workloads listed for one image short.
	maxWhere = 5
)

// Image is one image reference and where it is used.
type Image struct {
	Ref string `json:"ref"`
	// Where lists workloads using it, e.g. "Deployment shop/web (container web)".
	Where []string `json:"where"`
	// Charts are the Helm charts (helm.sh/chart label, name-version) that render it.
	Charts []string `json:"charts,omitempty"`
	// Hook is true when only Helm hooks (install/upgrade Jobs, tests) use it.
	Hook bool `json:"hook,omitempty"`
}

// Opaque is a custom resource: an operator may run images for it that rendering cannot show.
type Opaque struct {
	APIVersion string `json:"api_version"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Namespace  string `json:"namespace,omitempty"`
}

// Result is what a set of manifests runs.
type Result struct {
	Images []Image  `json:"images"`
	Opaque []Opaque `json:"opaque,omitempty"`
	// Objects is the number of Kubernetes objects read, Workloads those with a pod template.
	Objects   int `json:"objects"`
	Workloads int `json:"workloads"`
}

type metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type container struct {
	Name  string `yaml:"name"`
	Image string `yaml:"image"`
}

type podSpec struct {
	Containers          []container `yaml:"containers"`
	InitContainers      []container `yaml:"initContainers"`
	EphemeralContainers []container `yaml:"ephemeralContainers"`
}

type template struct {
	Spec podSpec `yaml:"spec"`
}

// object holds the shapes of every kind with a pod template. It is decoded with yaml.v3 for
// JSON too: field names match case-sensitively, as the API server reads them.
type object struct {
	APIVersion string      `yaml:"apiVersion"`
	Kind       string      `yaml:"kind"`
	Metadata   metadata    `yaml:"metadata"`
	Items      []yaml.Node `yaml:"items"`
	Spec       struct {
		podSpec     `yaml:",inline"`
		Template    *template `yaml:"template"`
		JobTemplate *struct {
			Spec struct {
				Template *template `yaml:"template"`
			} `yaml:"spec"`
		} `yaml:"jobTemplate"`
	} `yaml:"spec"`
	// Template is the body of a PodTemplate object.
	Template *template `yaml:"template"`
}

// builtinGroups are the API groups of Kubernetes itself: anything else is a custom resource.
var builtinGroups = map[string]bool{
	"": true, "apps": true, "batch": true, "extensions": true, "autoscaling": true, "policy": true,
	"networking.k8s.io": true, "rbac.authorization.k8s.io": true, "storage.k8s.io": true,
	"apiextensions.k8s.io": true, "admissionregistration.k8s.io": true, "scheduling.k8s.io": true,
	"coordination.k8s.io": true, "discovery.k8s.io": true, "node.k8s.io": true, "certificates.k8s.io": true,
	"events.k8s.io": true, "flowcontrol.apiserver.k8s.io": true, "resource.k8s.io": true,
	"apiregistration.k8s.io": true, "gateway.networking.k8s.io": true,
}

func group(apiVersion string) string {
	g, _, versioned := strings.Cut(apiVersion, "/")
	if !versioned {
		return ""
	}
	return g
}

// ErrNoObjects is returned for input without any Kubernetes object: a render that failed
// and printed nothing must not pass for a chart without images.
var ErrNoObjects = errors.New("no Kubernetes objects in the input")

// Parse reads YAML documents (--- separated), a JSON object or a List in either form.
func Parse(r io.Reader) (Result, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return Result{}, err
	}
	if len(data) > MaxBytes {
		return Result{}, fmt.Errorf("manifests larger than %d bytes", MaxBytes)
	}
	c := collector{images: map[string]*Image{}, hookOnly: map[string]bool{}}
	if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
		err = c.json(t)
	} else {
		err = c.yaml(data)
	}
	if err != nil {
		return Result{}, err
	}
	if c.objects == 0 {
		return Result{}, ErrNoObjects
	}
	return c.result(), nil
}

// docSeparator is a YAML document marker at the start of a line: it cannot occur inside a
// scalar, so splitting on it bounds each document before it is decoded.
var docSeparator = regexp.MustCompile(`^(---|\.\.\.)(\s|$)`)

func (c *collector) yaml(data []byte) error {
	var doc bytes.Buffer
	n := 0
	flush := func() error {
		n++
		defer doc.Reset()
		if len(bytes.TrimSpace(doc.Bytes())) == 0 {
			return nil
		}
		var o object
		if err := yaml.Unmarshal(doc.Bytes(), &o); err != nil {
			return fmt.Errorf("document %d: %w", n, err)
		}
		if err := c.object(o, nil, 0); err != nil {
			return fmt.Errorf("document %d: %w", n, err)
		}
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), MaxObjectBytes+1)
	for sc.Scan() {
		line := sc.Bytes()
		if docSeparator.Match(line) {
			if err := flush(); err != nil {
				return err
			}
			// "--- {...}" or "--- |" may start the next document on the marker's line.
			if rest := bytes.TrimSpace(line[3:]); len(rest) > 0 && line[0] == '-' {
				doc.Write(rest)
				doc.WriteByte('\n')
			}
			continue
		}
		if doc.Len()+len(line) > MaxObjectBytes {
			return fmt.Errorf("document %d is larger than %d bytes (split a large List into documents, or give it as JSON)", n+1, MaxObjectBytes)
		}
		doc.Write(line)
		doc.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return fmt.Errorf("a line is longer than %d bytes", MaxObjectBytes)
		}
		return err
	}
	return flush()
}

// json streams a JSON object; a List's items are read one at a time, each bounded.
func (c *collector) json(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	head := map[string]json.RawMessage{}
	var items []json.RawMessage
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := t.(string)
		if key != "items" {
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return err
			}
			if len(v) > MaxObjectBytes {
				return fmt.Errorf("field %q is larger than %d bytes", truncate(key), MaxObjectBytes)
			}
			head[key] = v
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return errors.New("items: not a list")
		}
		for dec.More() {
			if len(items) == MaxObjects {
				return fmt.Errorf("more than %d objects", MaxObjects)
			}
			var it json.RawMessage
			if err := dec.Decode(&it); err != nil {
				return fmt.Errorf("item %d: %w", len(items), err)
			}
			if len(it) > MaxObjectBytes {
				return fmt.Errorf("item %d is larger than %d bytes", len(items), MaxObjectBytes)
			}
			items = append(items, it)
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		head["items"] = json.RawMessage("[]")
	}
	if _, err := dec.Token(); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON object")
	}
	// The object without its items, then each item: JSON is YAML, and yaml.v3 matches field
	// names case-sensitively and refuses duplicate keys.
	var o object
	b, err := json.Marshal(head)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, &o); err != nil {
		return err
	}
	if _, hasItems := head["items"]; !hasItems || !isList(o) {
		return c.object(o, nil, 0)
	}
	parent := o
	for i, it := range items {
		var item object
		if err := yaml.Unmarshal(it, &item); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
		if err := c.object(item, &parent, 1); err != nil {
			return fmt.Errorf("item %d: %w", i, err)
		}
	}
	return nil
}

// isList is a Kubernetes List or typed list (DeploymentList): a custom resource whose kind
// happens to end in "List" is not.
func isList(o object) bool {
	return strings.HasSuffix(o.Kind, "List") && builtinGroups[group(o.APIVersion)]
}

type collector struct {
	images    map[string]*Image
	hookOnly  map[string]bool
	opaque    []Opaque
	workloads int
	objects   int
}

// object adds one object; items of a List are added with the List as parent, which gives
// typed lists' items (DeploymentList from the raw API) their kind and apiVersion.
func (c *collector) object(o object, parent *object, depth int) error {
	if parent != nil {
		if o.Kind == "" && o.APIVersion == "" {
			o.Kind, o.APIVersion = strings.TrimSuffix(parent.Kind, "List"), parent.APIVersion
		}
	}
	if o.Kind == "" {
		return errors.New("an object without kind: not a Kubernetes manifest")
	}
	if isList(o) && (o.Items != nil || parent == nil) {
		if depth > 0 {
			return errors.New("nested lists")
		}
		for i := range o.Items {
			var item object
			if err := o.Items[i].Decode(&item); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
			if err := c.object(item, &o, depth+1); err != nil {
				return fmt.Errorf("item %d: %w", i, err)
			}
		}
		return nil
	}
	c.objects++
	if c.objects > MaxObjects {
		return fmt.Errorf("more than %d objects", MaxObjects)
	}
	if !builtinGroups[group(o.APIVersion)] {
		c.opaque = append(c.opaque, Opaque{
			APIVersion: truncate(o.APIVersion), Kind: truncate(o.Kind), Name: truncate(o.Metadata.Name), Namespace: truncate(o.Metadata.Namespace),
		})
		return nil
	}
	var specs []podSpec
	switch o.Kind {
	case "Pod":
		specs = append(specs, o.Spec.podSpec)
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		if o.Spec.Template != nil {
			specs = append(specs, o.Spec.Template.Spec)
		}
	case "CronJob":
		if jt := o.Spec.JobTemplate; jt != nil && jt.Spec.Template != nil {
			specs = append(specs, jt.Spec.Template.Spec)
		}
	case "PodTemplate":
		if o.Template != nil {
			specs = append(specs, o.Template.Spec)
		}
	}
	if len(specs) == 0 {
		return nil
	}
	c.workloads++
	hook := o.Metadata.Annotations["helm.sh/hook"] != ""
	chart := o.Metadata.Labels["helm.sh/chart"]
	where := o.Kind + " " + truncate(cmp.Or(o.Metadata.Namespace, "default")+"/"+o.Metadata.Name)
	for _, s := range specs {
		for _, g := range []struct {
			kind string
			list []container
		}{{"container", s.Containers}, {"init container", s.InitContainers}, {"ephemeral container", s.EphemeralContainers}} {
			for _, ct := range g.list {
				ref := strings.TrimSpace(ct.Image)
				if ref == "" {
					return fmt.Errorf("%s: %s %q has no image", where, g.kind, truncate(ct.Name))
				}
				if err := c.use(ref, where+" ("+g.kind+" "+truncate(ct.Name)+")", chart, hook); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *collector) use(ref, where, chart string, hook bool) error {
	img := c.images[ref]
	if img == nil {
		if len(c.images) == MaxImages {
			return fmt.Errorf("more than %d distinct images", MaxImages)
		}
		img = &Image{Ref: ref}
		c.images[ref] = img
		c.hookOnly[ref] = true
	}
	if !hook {
		c.hookOnly[ref] = false
	}
	if len(img.Where) < maxWhere && !slices.Contains(img.Where, where) {
		img.Where = append(img.Where, where)
	}
	if chart = truncate(chart); chart != "" && !slices.Contains(img.Charts, chart) && len(img.Charts) < maxWhere {
		img.Charts = append(img.Charts, chart)
	}
	return nil
}

func (c *collector) result() Result {
	r := Result{Opaque: c.opaque, Objects: c.objects, Workloads: c.workloads}
	for ref, img := range c.images {
		img.Hook = c.hookOnly[ref]
		slices.Sort(img.Charts)
		r.Images = append(r.Images, *img)
	}
	slices.SortFunc(r.Images, func(a, b Image) int { return cmp.Compare(a.Ref, b.Ref) })
	return r
}

// truncate bounds a name taken from the manifests to 160 bytes, on a character boundary.
func truncate(s string) string {
	if len(s) <= 160 {
		return s
	}
	n := 160
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
