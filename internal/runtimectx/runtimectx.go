// Package runtimectx reads where images run and whether they are reachable from outside a
// cluster, from a read-only Kubernetes object list the operator exports (`kubectl get pods,
// services,ingresses,httproutes -A -o json`). ShieldMon runs no agent and holds no cluster
// credentials (docs/adr/0029-runtime-context.md). The list is hostile input: object names
// and labels come from every tenant of the cluster.
package runtimectx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits bound what one inventory may hold.
const (
	MaxBytes = 256 << 20
	MaxItems = 500_000
	// maxReasons keeps the exposure reasons of one image short in reports.
	maxReasons = 3
)

// Context is what an inventory says about one image digest.
type Context struct {
	// Running is true when a running container uses the image.
	Running bool `json:"running"`
	// Pods is the number of running pods using it.
	Pods int `json:"pods"`
	// Exposed is true when one of those pods is reachable from outside the cluster.
	Exposed bool `json:"exposed"`
	// Exposure says how (at most a few examples), e.g. "prod: Service default/web (LoadBalancer)".
	Exposure []string `json:"exposure,omitempty"`
}

// Inventory is one cluster's export.
type Inventory struct {
	Cluster string
	// Taken is when the export was written (the file's modification time).
	Taken  time.Time
	images map[string]*Context
}

// Images is the number of distinct image digests running.
func (inv *Inventory) Images() int { return len(inv.images) }

type meta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

type object struct {
	Kind     string          `json:"kind"`
	Metadata meta            `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
	Status   json.RawMessage `json:"status"`
}

type podContainer struct {
	Ports []struct {
		HostPort int `json:"hostPort"`
	} `json:"ports"`
}

type podSpec struct {
	HostNetwork bool           `json:"hostNetwork"`
	Containers  []podContainer `json:"containers"`
	// InitContainers include native sidecars (restartPolicy: Always), which run for the
	// pod's lifetime.
	InitContainers []podContainer `json:"initContainers"`
}

type containerStatus struct {
	ImageID string `json:"imageID"`
	State   struct {
		Running *struct{} `json:"running"`
	} `json:"state"`
}

type podStatus struct {
	Phase                      string            `json:"phase"`
	ContainerStatuses          []containerStatus `json:"containerStatuses"`
	InitContainerStatuses      []containerStatus `json:"initContainerStatuses"`
	EphemeralContainerStatuses []containerStatus `json:"ephemeralContainerStatuses"`
}

type serviceSpec struct {
	Type        string            `json:"type"`
	Selector    map[string]string `json:"selector"`
	ExternalIPs []string          `json:"externalIPs"`
}

type backend struct {
	Service *struct {
		Name string `json:"name"`
	} `json:"service"`
}

type ingressSpec struct {
	DefaultBackend *backend `json:"defaultBackend"`
	Rules          []struct {
		HTTP *struct {
			Paths []struct {
				Backend backend `json:"backend"`
			} `json:"paths"`
		} `json:"http"`
	} `json:"rules"`
}

type routeSpec struct {
	Rules []struct {
		BackendRefs []struct {
			Kind      string `json:"kind"`
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"backendRefs"`
	} `json:"rules"`
}

var digestRE = regexp.MustCompile(`sha256:[0-9a-f]{64}$`)

// imageDigest extracts the digest the kubelet pulled from a container status imageID:
// "docker.io/library/nginx@sha256:…", "docker-pullable://nginx@sha256:…" or "sha256:…".
func imageDigest(id string) string {
	return digestRE.FindString(strings.TrimSpace(id))
}

// decodeList streams a List's items, failing at the first item past MaxItems: decoding
// them all first would let a small file of empty items allocate far more than its size.
// kubectl prints "kind" after "items", so the kind is returned once the object is read.
func decodeList(data []byte) (string, []object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", nil, errors.New("not a JSON object")
	}
	var kind string
	var items []object
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return "", nil, err
		}
		key, _ := t.(string)
		switch key {
		case "kind":
			if err := dec.Decode(&kind); err != nil {
				return "", nil, fmt.Errorf("kind: %w", err)
			}
		case "items":
			if t, err := dec.Token(); err != nil || t != json.Delim('[') {
				if err == nil && t == nil {
					continue // "items": null
				}
				return "", nil, errors.New("items: not a list")
			}
			for dec.More() {
				if len(items) == MaxItems {
					return "", nil, fmt.Errorf("more than %d objects", MaxItems)
				}
				var o object
				if err := dec.Decode(&o); err != nil {
					return "", nil, fmt.Errorf("item %d: %w", len(items), err)
				}
				items = append(items, o)
			}
			if _, err := dec.Token(); err != nil { // ]
				return "", nil, err
			}
		default:
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return "", nil, err
			}
		}
	}
	if _, err := dec.Token(); err != nil { // }
		return "", nil, err
	}
	if dec.More() {
		return "", nil, errors.New("trailing data")
	}
	return kind, items, nil
}

// Parse reads a Kubernetes List (or PodList, ServiceList, …) as `kubectl get -o json` prints it.
func Parse(data []byte, cluster string, taken time.Time) (*Inventory, error) {
	if len(data) > MaxBytes {
		return nil, fmt.Errorf("runtime inventory %s: %d bytes exceeds %d", cluster, len(data), MaxBytes)
	}
	listKind, items, err := decodeList(data)
	if err != nil {
		return nil, fmt.Errorf("runtime inventory %s: %w", cluster, err)
	}
	if !strings.HasSuffix(listKind, "List") {
		return nil, fmt.Errorf("runtime inventory %s: want a Kubernetes List, got kind %q", cluster, truncate(listKind))
	}
	itemKind := strings.TrimSuffix(listKind, "List")
	list := struct{ Items []object }{items}

	type pod struct {
		meta
		digests []string
		host    string // hostNetwork or hostPort
	}
	var pods []pod
	services := map[string]serviceSpec{} // namespace/name
	exposedServices := map[string]string{}
	routed := map[string]string{} // namespace/service -> how it is routed from outside
	for _, it := range list.Items {
		kind := it.Kind
		if kind == "" {
			kind = itemKind
		}
		key := it.Metadata.Namespace + "/" + it.Metadata.Name
		switch kind {
		case "Pod":
			var st podStatus
			var sp podSpec
			if err := decodeOptional(it.Status, &st); err != nil {
				return nil, fmt.Errorf("runtime inventory %s: pod %q: %w", cluster, truncate(key), err)
			}
			if err := decodeOptional(it.Spec, &sp); err != nil {
				return nil, fmt.Errorf("runtime inventory %s: pod %q: %w", cluster, truncate(key), err)
			}
			if st.Phase != "Running" {
				continue
			}
			p := pod{meta: it.Metadata}
			// An init container still running is a native sidecar: it runs with the pod.
			for _, cs := range slices.Concat(st.ContainerStatuses, st.InitContainerStatuses, st.EphemeralContainerStatuses) {
				if d := imageDigest(cs.ImageID); d != "" && cs.State.Running != nil && !slices.Contains(p.digests, d) {
					p.digests = append(p.digests, d)
				}
			}
			if sp.HostNetwork {
				p.host = "hostNetwork"
			}
			for _, c := range slices.Concat(sp.Containers, sp.InitContainers) {
				for _, port := range c.Ports {
					if port.HostPort > 0 && p.host == "" {
						p.host = "hostPort"
					}
				}
			}
			pods = append(pods, p)
		case "Service":
			var sp serviceSpec
			if err := decodeOptional(it.Spec, &sp); err != nil {
				return nil, fmt.Errorf("runtime inventory %s: service %q: %w", cluster, truncate(key), err)
			}
			services[key] = sp
			switch {
			case sp.Type == "LoadBalancer" || sp.Type == "NodePort":
				exposedServices[key] = "Service " + key + " (" + sp.Type + ")"
			case len(sp.ExternalIPs) > 0:
				exposedServices[key] = "Service " + key + " (externalIPs)"
			}
		case "Ingress":
			var sp ingressSpec
			if err := decodeOptional(it.Spec, &sp); err != nil {
				return nil, fmt.Errorf("runtime inventory %s: ingress %q: %w", cluster, truncate(key), err)
			}
			route := func(b *backend) {
				if b != nil && b.Service != nil && b.Service.Name != "" {
					routed[it.Metadata.Namespace+"/"+b.Service.Name] = "Ingress " + key
				}
			}
			route(sp.DefaultBackend)
			for _, r := range sp.Rules {
				if r.HTTP == nil {
					continue
				}
				for i := range r.HTTP.Paths {
					route(&r.HTTP.Paths[i].Backend)
				}
			}
		case "HTTPRoute", "GRPCRoute", "TLSRoute", "TCPRoute", "UDPRoute":
			var sp routeSpec
			if err := decodeOptional(it.Spec, &sp); err != nil {
				return nil, fmt.Errorf("runtime inventory %s: route %q: %w", cluster, truncate(key), err)
			}
			// Only backends in the route's namespace: another namespace needs a
			// ReferenceGrant the export does not hold, and a route a Gateway rejects must
			// not make another tenant's image look exposed.
			for _, r := range sp.Rules {
				for _, b := range r.BackendRefs {
					sameNamespace := b.Namespace == "" || b.Namespace == it.Metadata.Namespace
					if (b.Kind == "" || b.Kind == "Service") && b.Name != "" && sameNamespace {
						routed[it.Metadata.Namespace+"/"+b.Name] = kind + " " + key
					}
				}
			}
		}
	}
	for svc, how := range routed {
		if _, ok := exposedServices[svc]; !ok {
			exposedServices[svc] = how + " → Service " + svc
		}
	}
	// Exposed services by namespace: a Service selects pods of its own namespace only.
	type exposed struct {
		selector map[string]string
		how      string
	}
	byNamespace := map[string][]exposed{}
	for key, how := range exposedServices {
		sp, ok := services[key]
		if !ok {
			continue // routed to a Service the export does not contain
		}
		ns, _, _ := strings.Cut(key, "/")
		byNamespace[ns] = append(byNamespace[ns], exposed{sp.Selector, how})
	}

	inv := &Inventory{Cluster: cluster, Taken: taken, images: map[string]*Context{}}
	for _, p := range pods {
		var reasons []string
		if p.host != "" {
			reasons = append(reasons, "Pod "+p.Namespace+"/"+p.Name+" ("+p.host+")")
		}
		for _, e := range byNamespace[p.Namespace] {
			if selects(e.selector, p.Labels) {
				reasons = append(reasons, e.how)
			}
		}
		slices.Sort(reasons)
		for _, d := range p.digests {
			c := inv.images[d]
			if c == nil {
				c = &Context{}
				inv.images[d] = c
			}
			c.Running = true
			c.Pods++
			for _, r := range reasons {
				c.Exposed = true
				r = cluster + ": " + truncate(r)
				if len(c.Exposure) < maxReasons && !slices.Contains(c.Exposure, r) {
					c.Exposure = append(c.Exposure, r)
				}
			}
		}
	}
	return inv, nil
}

// selects reports whether a Service selector picks a pod: every key matches. An empty
// selector selects nothing (its endpoints are managed by hand).
func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func decodeOptional(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return json.Unmarshal(raw, v)
}

// truncate bounds a name taken from the export to 160 bytes, on a character boundary.
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

// maxClockSkew is how far in the future an export's time may be: beyond it, the time cannot
// be trusted to judge freshness.
const maxClockSkew = 5 * time.Minute

// Load reads a cluster's export from path. An export older than maxAge (0: no limit) at now
// is refused with ErrStale: it would rank images by where they ran, not where they run.
func Load(path, cluster string, maxAge time.Duration, now time.Time) (*Inventory, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("runtime inventory %s: %w", cluster, err)
	}
	// Not a FIFO or a device on a shared volume, which would block every command.
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("runtime inventory %s: not a regular file", cluster)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("runtime inventory %s: %w", cluster, err)
	}
	defer f.Close()
	if st, err = f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("runtime inventory %s: not a regular file", cluster)
	}
	taken := st.ModTime()
	switch {
	case taken.After(now.Add(maxClockSkew)):
		return nil, fmt.Errorf("%w: %s written %s, in the future (clock skew?)", ErrStale, cluster, taken.UTC().Format(time.RFC3339))
	case maxAge > 0 && now.Sub(taken) > maxAge:
		return nil, fmt.Errorf("%w: %s written %s, older than %s", ErrStale, cluster, taken.UTC().Format(time.RFC3339), maxAge)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("runtime inventory %s: %w", cluster, err)
	}
	return Parse(data, cluster, st.ModTime().UTC())
}

// Set is the inventories of every configured cluster.
type Set []*Inventory

// Failure is a configured export that could not be used, and why.
type Failure struct {
	Cluster string
	Reason  string
}

// ErrStale marks an inventory older than the configured maximum age.
var ErrStale = errors.New("runtime inventory is stale")

// Lookup merges what every inventory says about an image, by any of its digests (the
// platform manifest digest and the index digest the kubelet may have pulled by).
func (s Set) Lookup(digests ...string) Context {
	var out Context
	digests = slices.Compact(slices.Sorted(slices.Values(digests)))
	for _, inv := range s {
		for _, d := range digests {
			c := inv.images[d]
			if d == "" || c == nil {
				continue
			}
			out.Running = true
			out.Pods += c.Pods
			out.Exposed = out.Exposed || c.Exposed
			for _, r := range c.Exposure {
				if len(out.Exposure) < maxReasons && !slices.Contains(out.Exposure, r) {
					out.Exposure = append(out.Exposure, r)
				}
			}
		}
	}
	return out
}
