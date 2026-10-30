package lineage

import (
	"testing"

	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/sbom"
)

func TestClassify(t *testing.T) {
	const base1, base2, app = "sha256:" + "11", "sha256:" + "22", "sha256:" + "aa"
	comp := func(purl string, layers ...string) sbom.Component {
		return sbom.Component{Name: "x", Type: "library", PURL: purl, Layers: layers}
	}
	image := []sbom.Component{
		comp("pkg:apk/alpine/zlib@1.3-r0?arch=x86_64&distro=alpine-3.20.0", base1),       // base, upgraded in the newest base
		comp("pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64", base2),                     // base, same version in the newest base
		comp("pkg:apk/alpine/musl@1.2.5-r0", base1),                                      // base, gone from the newest base
		comp("pkg:pypi/Requests@2.31.0", app),                                            // the application's
		comp("pkg:apk/alpine/ssl_client@1.36.1-r29"),                                     // no layer recorded
		comp("pkg:apk/alpine/openssl@3.3.0-r0", app, base1),                              // in both: the base has it
		comp("pkg:apk/alpine/zlib@1.3-r0?arch=x86_64&distro=alpine-3.20.0", base1),       // listed again by another generator
		comp("pkg:apk/alpine/busybox@1.36.1-r29?arch=x86_64&package-id=deadbeef", base2), // with scanner-specific qualifiers
	}
	newest := []sbom.Component{
		comp("pkg:apk/alpine/zlib@1.3.1-r1?arch=x86_64"),
		comp("pkg:apk/alpine/busybox@1.36.1-r29?arch=aarch64&distro=alpine-3.20.3"),
		comp("pkg:apk/alpine/openssl@3.3.2-r0"),
	}
	p := Classify(image, []string{base1, base2}, newest)
	of := func(raw string) Remedy {
		purl, _ := normalize.CanonicalPURL(raw, "", "", "")
		return p.Of(purl)
	}
	for raw, want := range map[string]Remedy{
		"pkg:apk/alpine/zlib@1.3-r0":           RemedyRebuild,
		"pkg:apk/alpine/busybox@1.36.1-r29":    RemedyBase,
		"pkg:apk/alpine/musl@1.2.5-r0":         RemedyRebuild,
		"pkg:pypi/requests@2.31.0":             RemedyApplication,
		"pkg:apk/alpine/ssl_client@1.36.1-r29": RemedyUnknown,
		"pkg:apk/alpine/openssl@3.3.0-r0":      RemedyRebuild,
		"pkg:npm/not-in-the-sbom@1.0.0":        RemedyUnknown,
	} {
		if got := of(raw); got != want {
			t.Errorf("%s: %s, want %s", raw, got, want)
		}
	}

	// Seen in python:3.12-alpine3.20: syft puts every apk package in the layer that last
	// rewrote /lib/apk/db/installed (the image's own `apk add`), trivy in the layer that added
	// it. Whichever generator is read first, the base layer decides.
	for _, order := range [][]sbom.Component{
		{comp("pkg:apk/alpine/musl@1.2.5-r1", app), comp("pkg:apk/alpine/musl@1.2.5-r1", base1)},
		{comp("pkg:apk/alpine/musl@1.2.5-r1", base1), comp("pkg:apk/alpine/musl@1.2.5-r1", app)},
	} {
		if r := Classify(order, []string{base1}, newest).Of(mustPURL("pkg:apk/alpine/musl@1.2.5-r1")); r != RemedyRebuild {
			t.Errorf("a package another generator places in the base is the base's: %s", r)
		}
	}

	// Without a proven base nothing is attributed; without the newest base's SBOM, base
	// packages are unknown but the application's are still the application's.
	if r := Classify(image, nil, newest).Of(mustPURL("pkg:pypi/requests@2.31.0")); r != RemedyUnknown {
		t.Errorf("no proven base: %s", r)
	}
	q := Classify(image, []string{base1, base2}, nil)
	if q.Of(mustPURL("pkg:apk/alpine/zlib@1.3-r0")) != RemedyUnknown || q.Of(mustPURL("pkg:pypi/requests@2.31.0")) != RemedyApplication {
		t.Error("no SBOM of the newest base")
	}
}

func mustPURL(raw string) string {
	purl, _ := normalize.CanonicalPURL(raw, "", "", "")
	return purl
}
