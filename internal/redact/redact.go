// Package redact removes credentials from strings before they are logged,
// persisted or returned in errors (security requirement S2).
package redact

import "regexp"

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// Authorization headers: Basic, Bearer, token.
	{regexp.MustCompile(`(?i)(authorization:\s*)(basic|bearer|token)\s+[A-Za-z0-9._~+/=-]+`), "${1}${2} [REDACTED]"},
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}`), "${1} [REDACTED]"},
	// user:password@host in URLs.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`), "${1}[REDACTED]@"},
	// key=value / key: value for well-known secret names.
	{regexp.MustCompile(`(?i)\b((?:aws_)?(?:secret_access_key|session_token|access_token|refresh_token|id_token|password|passwd|secret|token|api[_-]?key|private[_-]?token|job[_-]?token))(["']?\s*[:=]\s*["']?)[^\s"'&,;]+`), "${1}${2}[REDACTED]"},
	// Query-string credentials.
	{regexp.MustCompile(`(?i)([?&](?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|access_token|token|sig)=)[^&\s"']+`), "${1}[REDACTED]"},
	// AWS access key IDs.
	{regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`), "[REDACTED-AWS-KEY-ID]"},
	// GitLab tokens (glpat-, gldt-, glcbt-, ...) and GitHub tokens.
	{regexp.MustCompile(`\bgl[a-z]{2,4}-[A-Za-z0-9_-]{16,}\b`), "[REDACTED-GITLAB-TOKEN]"},
	{regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`), "[REDACTED-GITHUB-TOKEN]"},
	// JWTs.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), "[REDACTED-JWT]"},
}

// String returns s with known credential shapes replaced.
func String(s string) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}

// Error returns a redacted copy of err's message, or "" for nil.
func Error(err error) string {
	if err == nil {
		return ""
	}
	return String(err.Error())
}
