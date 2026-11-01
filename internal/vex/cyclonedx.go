package vex

import (
	"encoding/json"
	"fmt"
	"time"
)

// cdxJustifications maps CycloneDX analysis justifications to OpenVEX's.
var cdxJustifications = map[string]string{
	"code_not_present":                "vulnerable_code_not_present",
	"code_not_reachable":              "vulnerable_code_not_in_execute_path",
	"requires_configuration":          "vulnerable_code_cannot_be_controlled_by_adversary",
	"requires_dependency":             "component_not_present",
	"requires_environment":            "vulnerable_code_cannot_be_controlled_by_adversary",
	"protected_by_compiler":           "inline_mitigations_already_exist",
	"protected_at_runtime":            "inline_mitigations_already_exist",
	"protected_at_perimeter":          "inline_mitigations_already_exist",
	"protected_by_mitigating_control": "inline_mitigations_already_exist",
}

type cdxComponent struct {
	BOMRef string `json:"bom-ref"`
	PURL   string `json:"purl"`
}

type cdxDocument struct {
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Timestamp string       `json:"timestamp"`
		Component cdxComponent `json:"component"`
		Authors   []struct {
			Name string `json:"name"`
		} `json:"authors"`
	} `json:"metadata"`
	Components      []cdxComponent `json:"components"`
	Vulnerabilities []struct {
		ID         string `json:"id"`
		References []struct {
			ID string `json:"id"`
		} `json:"references"`
		Analysis struct {
			State         string `json:"state"`
			Justification string `json:"justification"`
			Detail        string `json:"detail"`
		} `json:"analysis"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
		Published string `json:"published"`
		Updated   string `json:"updated"`
	} `json:"vulnerabilities"`
}

// parseCycloneDX reads the vulnerabilities of a CycloneDX BOM (VEX or BOM with analysis).
// The product is metadata.component, which must identify the image (pkg:oci PURL); each
// affects reference names a package component, or the product itself for every package.
func parseCycloneDX(data []byte, author string, now time.Time) ([]Statement, []Skipped, error) {
	var doc cdxDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("CycloneDX: %w", err)
	}
	if len(doc.Vulnerabilities) > MaxStatements || len(doc.Components) > MaxStatements {
		return nil, nil, fmt.Errorf("CycloneDX: more than %d vulnerabilities or components", MaxStatements)
	}
	digest, repo, err := product(doc.Metadata.Component.PURL)
	if err != nil {
		return nil, nil, fmt.Errorf("CycloneDX: metadata.component: %w", err)
	}
	if len(doc.Metadata.Authors) > 0 && doc.Metadata.Authors[0].Name != "" {
		author = doc.Metadata.Authors[0].Name
	}
	refs := map[string]string{}
	for _, c := range doc.Components {
		if c.BOMRef != "" {
			refs[c.BOMRef] = c.PURL
		}
	}
	docTime, _ := time.Parse(time.RFC3339, doc.Metadata.Timestamp)
	var out []Statement
	var skipped []Skipped
	for _, v := range doc.Vulnerabilities {
		id, err := vulnID(v.ID)
		if err != nil {
			skipped = append(skipped, Skipped{short(v.ID), err.Error()})
			continue
		}
		if v.Analysis.State != "not_affected" && v.Analysis.State != "false_positive" {
			skipped = append(skipped, Skipped{id, "analysis state " + short(v.Analysis.State) + ": only not_affected and false_positive are recorded"})
			continue
		}
		var alias []string
		for _, r := range v.References {
			alias = append(alias, r.ID)
		}
		s := Statement{VulnID: id, Aliases: aliases(id, alias), Author: author, Source: short(doc.SerialNumber), Digest: digest, Repository: repo}
		if v.Analysis.Justification != "" {
			j, ok := cdxJustifications[v.Analysis.Justification]
			if !ok {
				skipped = append(skipped, Skipped{id, "unknown justification " + short(v.Analysis.Justification)})
				continue
			}
			s.Justification = j
		}
		if s.Impact, err = text(v.Analysis.Detail); err != nil {
			skipped = append(skipped, Skipped{id, err.Error()})
			continue
		}
		if v.Analysis.State == "false_positive" && s.Impact == "" {
			s.Impact = "false positive"
		}
		s.Timestamp = docTime
		for _, t := range []string{v.Published, v.Updated} {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				s.Timestamp = parsed
			}
		}
		s.Timestamp = s.Timestamp.UTC()
		if len(v.Affects) == 0 {
			skipped = append(skipped, Skipped{id, "affects names no component"})
			continue
		}
		for _, a := range v.Affects {
			ss := s
			switch {
			case a.Ref == doc.Metadata.Component.BOMRef && a.Ref != "":
			case refs[a.Ref] != "":
				purl, anyVersion, err := pkgPURL(refs[a.Ref])
				if err != nil {
					skipped = append(skipped, Skipped{id, err.Error()})
					continue
				}
				ss.PURL, ss.AnyVersion = purl, anyVersion
			default:
				purl, anyVersion, err := pkgPURL(a.Ref)
				if err != nil {
					skipped = append(skipped, Skipped{id, "affects " + short(a.Ref) + ": not a component of this BOM nor a PURL"})
					continue
				}
				ss.PURL, ss.AnyVersion = purl, anyVersion
			}
			finish(ss, now, &out, &skipped)
		}
	}
	return out, skipped, nil
}
