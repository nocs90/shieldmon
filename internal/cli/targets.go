package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/oci"
)

// Bounds on what an input or a registry listing can add in one command.
const (
	maxTargetsFileBytes = 1 << 20
	maxListedTags       = 1000
)

// targetsAddCmd registers references as monitoring targets without scanning them: the next
// `monitor` cycle resolves and scans them (F1).
func (a *app) targetsAddCmd() *cobra.Command {
	var file, platform, base, by string
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "add [IMAGE...]",
		Short: "Add image references as monitoring targets (from arguments and/or a file)",
		Long: `Add image references as monitoring targets. Nothing is pulled or scanned now: the
next 'shieldmon monitor' cycle resolves and scans them.

A file (-f, "-" for stdin) holds one reference per line; blank lines and lines starting
with # are ignored. Every reference is checked before any is added.

--base records the base image the new targets are built on (see 'targets set-base').`,
		Example: "  shieldmon targets add alpine:3.20 ghcr.io/org/app:1.4\n  shieldmon targets add -f images.txt --dry-run\n" +
			"  shieldmon targets add ghcr.io/org/api:2.1 --base registry.access.redhat.com/ubi9/nodejs-22-minimal:latest",
		RunE: func(cmd *cobra.Command, args []string) error {
			refs := args
			if file != "" {
				fromFile, err := readTargetsFile(cmd.InOrStdin(), file)
				if err != nil {
					return err
				}
				refs = append(refs, fromFile...)
			}
			if len(refs) == 0 {
				return errors.New("give image references or -f FILE")
			}
			for _, r := range refs {
				if _, err := oci.ParseReference(r, false); err != nil {
					return fmt.Errorf("%q: %w", r, err)
				}
			}
			if base != "" {
				var err error
				if base, err = baseRef(base); err != nil {
					return err
				}
				if by == "" {
					return errors.New("--base needs --by (who; default from $SHIELDMON_ACTOR or $USER)")
				}
			}
			return a.addTargets(cmd, refs, platform, base, by, dryRun)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", `file with one reference per line ("-" for stdin)`)
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be added, add nothing")
	cmd.Flags().StringVar(&base, "base", "", "base image tag the new targets are built on (docs/adr/0022-base-image-lineage.md)")
	cmd.Flags().StringVar(&by, "by", engine.ActorFromEnv(), "who records the base")
	a.platformFlag(cmd, &platform)
	return cmd
}

// readTargetsFile reads references, at most maxTargetsFileBytes, reporting the line of a
// malformed one.
func readTargetsFile(stdin io.Reader, path string) ([]string, error) {
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	sc := bufio.NewScanner(io.LimitReader(r, maxTargetsFileBytes+1))
	var refs []string
	read := 0
	for line := 1; sc.Scan(); line++ {
		read += len(sc.Bytes()) + 1
		if read > maxTargetsFileBytes {
			return nil, fmt.Errorf("%s: larger than %d bytes", path, maxTargetsFileBytes)
		}
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if _, err := oci.ParseReference(s, false); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		refs = append(refs, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return refs, nil
}

// targetsAddRepoCmd adds tags of a repository, or of every repository under a path, picked
// through the registry's provider.
func (a *app) targetsAddRepoCmd() *cobra.Command {
	var tagRegex, platform string
	var latest, maxRepos int
	var under, dryRun bool
	cmd := &cobra.Command{
		Use:   "add-repo REPOSITORY",
		Short: "Add tags of a repository (or of every repository under a path) as targets",
		Long: `Add tags of a repository as monitoring targets, newest first: by push time where the
registry says (ECR), otherwise by version. --tag-regex keeps matching tags (RE2 syntax),
--latest keeps the newest N of those.

With --under, REPOSITORY is a path (a GitLab group, an ECR prefix) and every repository
below it is handled the same way, at most --max-repos of them. Listing goes through the
registry's provider ('shieldmon plugins', docs/processes/registries.md).`,
		Example: "  shieldmon targets add-repo 123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/api --tag-regex '^v[0-9.]+$' --latest 3\n" +
			"  shieldmon targets add-repo registry.gitlab.com/platform --under --latest 1 --dry-run",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := a.setup(cmd); err != nil {
				return err
			}
			re, err := regexp.Compile(tagRegex)
			if err != nil {
				return fmt.Errorf("--tag-regex: %w", err)
			}
			if latest < 0 || maxRepos < 1 {
				return errors.New("--latest must be ≥ 0 and --max-repos ≥ 1")
			}
			repo, err := name.NewRepository(args[0])
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			defer cancel()
			p, err := a.registries.For(repo.RegistryStr())
			if err != nil {
				return err
			}
			repos := []name.Repository{repo}
			if under {
				names, err := p.Repositories(ctx, repo.RegistryStr(), repo.RepositoryStr(), maxRepos)
				if err != nil {
					return err
				}
				repos = repos[:0]
				for _, n := range names {
					r, err := name.NewRepository(n)
					if err != nil {
						return err
					}
					repos = append(repos, r)
				}
			}
			var refs []string
			for _, r := range repos {
				tags, err := p.Tags(ctx, r, maxListedTags)
				if err != nil {
					return fmt.Errorf("%s: %w", r.Name(), err)
				}
				kept := 0
				for _, t := range tags {
					if !re.MatchString(t.Name) || (latest > 0 && kept == latest) {
						continue
					}
					refs = append(refs, r.Name()+":"+t.Name)
					kept++
				}
			}
			if len(refs) == 0 {
				return fmt.Errorf("no tags of %s match", repo.Name())
			}
			return a.addTargets(cmd, refs, platform, "", "", dryRun)
		},
	}
	cmd.Flags().StringVar(&tagRegex, "tag-regex", "", "keep tags matching this regular expression (RE2)")
	cmd.Flags().IntVar(&latest, "latest", 0, "keep the newest N matching tags per repository (0: all)")
	cmd.Flags().BoolVar(&under, "under", false, "REPOSITORY is a path: handle every repository below it")
	cmd.Flags().IntVar(&maxRepos, "max-repos", 100, "with --under, at most this many repositories")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show what would be added, add nothing")
	a.platformFlag(cmd, &platform)
	return cmd
}

// addTargets registers refs for platform, reporting which are new.
// addTargets adds new targets for refs; base, when set, is recorded for each new one by actor.
func (a *app) addTargets(cmd *cobra.Command, refs []string, platform, base, actor string, dryRun bool) error {
	if a.store == nil {
		if err := a.setup(cmd); err != nil {
			return err
		}
	}
	p, err := a.platform(platform)
	if err != nil {
		return err
	}
	existing, err := a.store.ListTargets(cmd.Context())
	if err != nil {
		return err
	}
	have := map[string]bool{}
	retired := map[string]int64{}
	for _, t := range existing {
		have[t.Ref+" "+t.Platform] = true
		if !t.RetiredAt.IsZero() {
			retired[t.Ref+" "+t.Platform] = t.ID
		}
	}
	w := cmd.OutOrStdout()
	added, present := 0, 0
	seen := map[string]bool{}
	for _, raw := range refs {
		// Stored in the form engine.Scan registers, so that monitor finds the same target
		// (alpine:3.20 is index.docker.io/library/alpine:3.20).
		parsed, err := oci.ParseReference(raw, false)
		if err != nil {
			return fmt.Errorf("%q: %w", raw, err)
		}
		ref := parsed.Name()
		key := ref + " " + p.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		if id, ok := retired[key]; ok {
			// Adding back is a decision with its own record: restore.
			fmt.Fprintf(w, "%s (%s) is retired target #%d: 'shieldmon targets restore %d' to monitor it again\n", ref, p, id, id)
			present++
			continue
		}
		if have[key] {
			present++
			continue
		}
		added++
		if dryRun {
			fmt.Fprintf(w, "would add %s (%s)\n", ref, p)
			continue
		}
		t, err := a.store.UpsertTarget(cmd.Context(), ref, p.String(), time.Now().UTC())
		if err != nil {
			return err
		}
		if base == "" {
			fmt.Fprintf(w, "added %s (%s)\n", ref, p)
			continue
		}
		if err := a.store.SetTargetBase(cmd.Context(), t.ID, base, actor, time.Now().UTC()); err != nil {
			return err
		}
		fmt.Fprintf(w, "added %s (%s), built on %s\n", ref, p, base)
	}
	verb := "added"
	if dryRun {
		verb = "would add"
	}
	fmt.Fprintf(w, "%s %d target(s), %d already targets; 'shieldmon monitor' scans them\n", verb, added, present)
	return nil
}
