# GitHub launch and growth checklist

This is the maintainer-facing checklist for presenting Angerona clearly,
earning trust, and converting repository visits into installs, stars, useful
issues, and contributions. Marketing claims must stay inside the capability
boundaries documented in the README and security policy.

## Repository metadata to set on GitHub

**About description (copy/paste):**

> Local-first AI-assisted EDR, NDR, SOAR and DFIR desktop suite with MITRE ATT&CK, safe purple-team drills, local Ollama, and privacy-first telemetry.

**Topics (GitHub allows up to 20):**

```text
endpoint-security edr ndr soar xdr blue-team dfir threat-hunting incident-response
mitre-attack purple-team yara sigma windows-security linux-security local-ai
ollama security-automation python pyside6
```

- Link the website field to the latest release or a future project site.
- Upload a 1280×640 social-preview image showing the synthetic public-demo
  dashboard, the product name, and the line “Local-first AI cyber defense.”
- Enable Issues and Discussions. Use Discussions for setup questions, demos,
  ideas, and release announcements; keep Issues actionable.
- Pin a “Start here” discussion with supported platforms, the fastest install
  route, demo data disclosure, and links to security/support policies.

GitHub documents topics as a discovery/classification mechanism and recommends
README, license, contribution, security, and community-health files:
[repository topics](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics),
[repository best practices](https://docs.github.com/en/repositories/creating-and-managing-repositories/best-practices-for-repositories), and
[community profiles](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories).

## Highest-impact adoption work

1. **Sign the Windows release.** Authenticode/MSIX publisher identity removes
   the most visible installation trust warning. Keep checksums and provenance,
   but do not present them as a substitute for publisher authentication.
2. **Publish a 60–90 second demo.** Show installation, a synthetic alert, its
   evidence/path detail, a safe Red Team run with live kill-chain highlighting,
   containment review, and the After-Action Report. Never capture real host
   identities, paths, addresses, or secrets.
3. **Make the first run effortless.** Measure clean-machine installation and
   time-to-first-use on current Windows, macOS Apple Silicon, and Linux. Put the
   working one-command/one-click path before source-build instructions.
4. **Publish honest performance evidence.** Report idle/active CPU, memory,
   event latency, startup time, and test-machine specs. Include Chill Mode and
   clearly distinguish Windows Protect from macOS/Linux Observe/Detect.
5. **Provide stable release notes.** Lead each release with user outcomes,
   screenshots, upgrade notes, known limitations, checksums, attestations, and
   the exact supported-platform matrix. GitHub Releases are the download page,
   not the README history archive.
6. **Create contributor-sized work.** Label a small number of reproducible,
   bounded issues `good first issue` and `help wanted`; document the relevant
   module, expected tests, safety boundary, and definition of done.
7. **Seek independent evidence.** A third-party code review, clean-machine
   installer test, defensive lab evaluation, or responsible security assessment
   is more persuasive than adding more feature claims.

## Content rhythm

- Release: outcome-focused notes plus one short demo clip.
- Monthly: one technical deep dive (for example, event authentication, safe
  purple-team verification, privacy-bounded IR, or cross-platform contracts).
- Ongoing: convert resolved support questions into documentation and keep the
  first-screen README concise.

Useful, defensible search phrases include: local-first cybersecurity,
AI-assisted EDR, privacy-first SOC, local LLM security, MITRE ATT&CK coverage,
purple-team validation, detection engineering, DFIR workbench, SOAR automation,
YARA and Sigma, Windows ETW security, and Linux endpoint observation.

## Trust rules for promotional material

- Say **Windows Protect**, **macOS Observe preview**, and **Linux Observe +
  Detect**; do not flatten them into one enforcement claim.
- Say **safe adversary simulation** or **purple-team validation**, not real
  exploitation or persistence.
- Say **local by default** and list the optional features that can create egress.
- Use synthetic screenshots and label them.
- Keep module/test counts generated or date-stamped; do not let badges or copy
  silently drift from verified results.
- Keep known limitations visible. Clear boundaries increase trust.

