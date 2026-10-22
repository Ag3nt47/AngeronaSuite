"""Sourced field guide, never an actor attribution engine or active blocklist.

Research associations describe the cited report, not the origin of a local
finding. Detection applies to observed behavior regardless of nationality.
This deliberately bounded catalog is not a claim to cover every country/tool.
"""
from __future__ import annotations

from dataclasses import dataclass


CATALOG_REVIEWED = "2026-10-21"
CATALOG_SCOPE = (
    "SpywareGuard follows persistence, process, DNS, and egress evidence from any country. "
    "The examples below explain published research associations; a local match does not "
    "identify an operator, government, vendor, or spyware family. This is a selected field "
    "guide, not a complete world inventory. Mobile research is context, not a phone scanner."
)


@dataclass(frozen=True)
class SpywareProfile:
    key: str
    title: str
    association: str
    description: str
    signals: str
    limitation: str
    source_title: str
    source_url: str
    published: str

    def plain_text(self) -> str:
        return (
            f"{self.title}\n\nResearch association: {self.association}\n\n"
            f"{self.description}\n\nRelevant evidence to investigate\n{self.signals}"
            f"\n\nCoverage boundary\n{self.limitation}\n\n"
            f"Primary source: {self.source_title}\nPublished: {self.published}\n"
            f"{self.source_url}\n\nCatalog reviewed: {CATALOG_REVIEWED}"
        )


SPYWARE_PROFILES = (
    SpywareProfile(
        "pegasus", "Pegasus / NSO: zero-click message processing", "Israel-based commercial vendor; international customers",
        "Google Project Zero analyzed FORCEDENTRY, an NSO exploit delivered through iMessage "
        "without user interaction. Malicious media processing supplied an initial code-execution "
        "path. A patched historical exploit illustrates why a familiar file type or an unopened "
        "message does not establish safety.",
        "Investigate renderer or message-helper process anomalies, executable memory without a "
        "file mapping, unexpected children, and corroborating network or persistence evidence. "
        "These are generic investigative signals; normal applications can produce some of them.",
        "A desktop scanner cannot establish that an iPhone is free of Pegasus. SpywareGuard "
        "reports the telemetry it actually receives and does not implement mobile forensic acquisition.",
        "Project Zero: A deep dive into an NSO zero-click iMessage exploit",
        "https://projectzero.google/2021/12/a-deep-dive-into-nso-zero-click.html", "2021-12-15",
    ),
    SpywareProfile(
        "adfection", "Candiru / Integrity Labs: AdFection and ad-tech delivery",
        "Citizen Lab research into Discover-Tech / Controlium and commercial spyware links",
        "Citizen Lab's October 2026 investigation documented Candiru infections delivered through "
        "targeted advertisements at Al Jazeera. It describes Discover-Tech's Controlium platform "
        "and connections with Candiru/Integrity Labs, Bindecy, and Intelos. Rendering an ad can "
        "supply the delivery opportunity without a click; an ad identifier can support target selection. "
        "A business relationship or a company name alone is not an actionable indicator.",
        "Review externally supplied DNS/egress events, renderer-to-child transitions, approved "
        "infrastructure indicators, and suspicious persistence. Preserve the original report URL "
        "and distinguish reported infrastructure from ordinary ad exchanges or shared hosting.",
        "SpywareGuard does not decrypt HTTPS, remove mobile IDFA/GAID, or inspect every RTB "
        "auction. Narrative reports do not automatically authorize vendor-wide blocking. Renderer "
        "telemetry cannot by itself prove an AdFection infection.",
        "Citizen Lab: Exposing AdFection",
        "https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/",
        "2026-10-15",
    ),
    SpywareProfile(
        "graphite", "Paragon / Graphite: messenger-focused surveillance",
        "Israel-founded commercial vendor; suspected deployments in multiple countries",
        "Citizen Lab mapped Graphite-related infrastructure and examined devices belonging to "
        "civil society targets. Its March 2025 report describes collaboration with WhatsApp on a "
        "zero-click investigation and Android artifacts indicating spyware loaded into messaging "
        "and other applications. Reported customers and infrastructure are research findings, not "
        "a license to attribute an unrelated desktop event to Paragon.",
        "Investigate approved infrastructure matches, suspicious memory mappings, and process "
        "activity supported by authenticated endpoint telemetry. Track the evidence source and "
        "timestamp because infrastructure changes and stale indicators can mislead.",
        "No Signal or WhatsApp content is decrypted here. Monitoring an authorized Signal beacon "
        "channel does not provide mobile spyware inspection or guarantee secure delivery from a compromised host.",
        "Citizen Lab: A First Look at Paragon's Proliferating Spyware Operations",
        "https://citizenlab.ca/research/a-first-look-at-paragons-proliferating-spyware-operations/",
        "2025-03-19",
    ),
    SpywareProfile(
        "predator", "Predator / Intellexa: exploit chains and traffic redirection",
        "Commercial surveillance; Google's report describes a campaign in Egypt",
        "Google Threat Analysis Group documented an iPhone exploit chain used to install "
        "Predator and a network interception delivery path that redirected unencrypted HTTP "
        "traffic. The vulnerabilities were patched. The case shows that an expected destination "
        "and a successful page load can coexist with malicious redirection earlier in a connection.",
        "Correlate DNS observations, reported redirection endpoints, unusual browser children, "
        "and outbound volume. Keep network metadata and host events together; a single network "
        "heuristic remains a signal rather than a family attribution.",
        "SpywareGuard is not a network interception sensor. It depends on the installed NDR or "
        "endpoint telemetry sources and does not certify mobile exploit detection.",
        "Google TAG: 0-days exploited by commercial surveillance vendor in Egypt",
        "https://blog.google/threat-analysis-group/0-days-exploited-by-commercial-surveillance-vendor-in-egypt/",
        "2023-09-22",
    ),
    SpywareProfile(
        "snake", "Snake: long-term state espionage",
        "Russia's FSB, as attributed by the cited joint government advisory",
        "New Zealand's NCSC and international partners published an advisory on Snake as a "
        "long-term intelligence collection capability. Long-lived implants can use host artifacts "
        "and network communications that differ from short ransomware incidents, so retention "
        "of timestamps and repeated observations matters.",
        "Investigate unauthorized services and startup hooks, approved file hashes, persistent "
        "communications, and available DNS telemetry. Compare the original technical advisory "
        "with local evidence before assigning a malware name.",
        "Generic persistence inspection is not a complete implementation of every Snake "
        "hunting procedure. Missing artifacts or a clean scan cannot exclude a privileged implant.",
        "New Zealand NCSC: Russian intelligence Snake malware (joint advisory)",
        "https://www.ncsc.govt.nz/alerts/russian-intelligence-snake-malware/", "2023-05-10",
    ),
    SpywareProfile(
        "apt40", "APT40: web access, persistence, and collection",
        "PRC state-sponsored activity, as attributed by ASD's ACSC and partners",
        "The Australian advisory describes APT40 tradecraft, including exploitation of exposed "
        "systems and the use of compromised devices as operational infrastructure. A destination's "
        "country, a legitimate service name, or a home router address alone cannot establish "
        "whether a connection is malicious.",
        "Review new persistence entries, suspicious scripts or services, approved indicators, "
        "and unusual data transfer when telemetry provides byte counts. Investigate exposed "
        "applications and keep incident response informed by the cited advisory.",
        "SpywareGuard's local view does not audit every router or cloud account. It does not "
        "infer APT40 from geography or the presence of a commonly abused administration tool.",
        "ASD's ACSC: APT40 Advisory — PRC MSS tradecraft in action",
        "https://www.cyber.gov.au/advisory/apt40-advisory", "2024-07-09",
    ),
    SpywareProfile(
        "applejeus", "AppleJeus: trojanized finance applications",
        "DPRK / Lazarus, as attributed by FBI, CISA, and the US Treasury",
        "The joint AppleJeus advisory documents malicious cryptocurrency trading applications "
        "used to gain access to victims on Windows and macOS and facilitate theft. Download "
        "sites and installers can look legitimate while the installed program introduces a "
        "backdoor and a second-stage retrieval path.",
        "Investigate new LaunchAgents or services, unusual startup commands, known malicious "
        "hashes, and network activity tied to the installing process. Verify reported hashes "
        "against the exact local binary; a filename is insufficient.",
        "SpywareGuard does not inspect cryptocurrency transactions or guarantee protection of "
        "wallet contents. Restrict privileges and retain source provenance when reviewing indicators.",
        "CISA / FBI / Treasury: AppleJeus, AA21-048A",
        "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a", "2021-02-17",
    ),
    SpywareProfile(
        "mint", "Mint Sandstorm: credential theft and social engineering",
        "Iran-affiliated activity, as attributed by Microsoft Threat Intelligence",
        "Microsoft describes espionage targeting dissidents, journalists, academics, government "
        "organizations, and others internationally. Techniques include credential harvesting, "
        "spear phishing, information stealers, and malicious content delivered through documents. "
        "Account compromise may occur without a persistent implant on this computer.",
        "Investigate unauthorized startup scripts and credential-related endpoint evidence when "
        "a trusted producer supplies it. Retain browser or account security alerts separately "
        "from a local artifact match and rotate affected credentials through a trusted device.",
        "SpywareGuard cannot intercept every browser-profile read or determine whether a remote "
        "mailbox has been compromised. A credential-related event does not establish Iranian attribution.",
        "Microsoft Security Insider: Mint Sandstorm",
        "https://www.microsoft.com/en-us/security/security-insider/threat-landscape/mint-sandstorm",
        "2024-01-25",
    ),
)
