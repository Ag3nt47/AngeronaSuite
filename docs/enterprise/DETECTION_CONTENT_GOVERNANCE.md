# Detection-content governance

Every detection package requires:

- stable owner and reviewer roles;
- version, changelog, expiry, rollback digest, and supported schema;
- required telemetry and its unknown/degraded behavior;
- ATT&CK mapping, severity, confidence, rationale, and false-positive risk;
- positive, negative, boundary, malformed, and performance fixtures;
- signature and digest verification before activation;
- privacy classification and proof fixtures contain no real credentials or PII.

The Detection Maintainer authors content. A Security Reviewer approves semantic
and abuse-case behavior. A Privacy Reviewer approves new fields or egress. The
Release Maintainer signs and promotes content only after automated gates pass.
High-impact response coupling requires a second independent approval.

Feedback does not silently weaken detection. Allow/trust actions bind exact
identity and scope, expire or remain revocable, and retain an audit reason.
Fleet replay compares candidate and current content before canary promotion.
