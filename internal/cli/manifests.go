package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/oci"
)

// readManifestImages returns the image references the manifests at path ("-": stdin) run,
// after printing to stderr what they cannot show (docs/adr/0030-manifest-images.md). An
// image that is not a valid reference fails the whole read: adding the others would leave
// a workload unmonitored without anyone noticing.
func readManifestImages(cmd *cobra.Command, path string) ([]string, error) {
	r := cmd.InOrStdin()
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	res, err := manifests.Parse(r)
	if err != nil {
		// Parse errors quote names from the manifests: escape them for the terminal.
		return nil, fmt.Errorf("%s: %s", path, printable(err.Error()))
	}
	w := cmd.ErrOrStderr()
	var refs, bad []string
	for _, img := range res.Images {
		if _, err := oci.ParseReference(img.Ref, false); err != nil {
			bad = append(bad, fmt.Sprintf("%q in %s", printable(short(img.Ref, 120)), printable(img.Where[0])))
			continue
		}
		refs = append(refs, img.Ref)
		if img.Hook {
			fmt.Fprintf(w, "note: %s is used by Helm hooks only (%s)\n", printable(img.Ref), printable(strings.Join(img.Where, "; ")))
		}
	}
	if len(bad) > 0 {
		return nil, fmt.Errorf("%s: %d image(s) are not valid references, nothing added: %s", path, len(bad), firstOf(bad, maxListed))
	}
	for i, o := range res.Opaque {
		if i == maxListed {
			fmt.Fprintf(w, "warning: and %d more custom resources\n", len(res.Opaque)-maxListed)
			break
		}
		name := o.Name
		if o.Namespace != "" {
			name = o.Namespace + "/" + name
		}
		fmt.Fprintf(w, "warning: %s %s (%s) is a custom resource: images its operator runs are not in the manifests; add them by hand\n",
			printable(o.Kind), printable(name), printable(o.APIVersion))
	}
	fmt.Fprintf(w, "%s: %d image(s) in %d workload(s) of %d object(s)\n", path, len(refs), res.Workloads, res.Objects)
	return refs, nil
}

// maxListed bounds the items one message lists.
const maxListed = 20

func firstOf(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
}
