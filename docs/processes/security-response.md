# Security response

1. **Intake**: private vulnerability report (GitHub advisory) or a public issue that turns
   out to be a vulnerability → hide it and open a private advisory.
2. **Acknowledge** within 72 hours; assign a maintainer.
3. **Assess** against THREAT_MODEL.md: which asset, which boundary, exploitability.
   Priority classes: credential exposure, closure without evidence / audit tampering,
   escape of size/time bounds, injection.
4. **Fix** in a private fork of the advisory; add a regression test (and a fuzz seed if a
   parser was involved); update THREAT_MODEL.md.
5. **Release** a patched version; publish the advisory with credit; request a CVE via
   GitHub when applicable.
6. **Scanner compromise upstream** (e.g. a malicious trivy release): do not bump pins;
   check `scanner_checksum_mismatch` health findings; publish guidance; bump only to a
   verified release.
