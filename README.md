# Google SecOps (`GTI_IOC`) Parsing Bug: Domain IOCs Ingested as `IP_ADDRESS` Entities

## Summary

In Google SecOps, the Google-managed `GTI_IOC` threat intelligence feed (`GLOBAL_CONTEXT`, `parser_version: 6.0`) appears to misclassify certain malicious **domain** indicators as **`IP_ADDRESS`** entities whenever the hostname contains an IPv4-like substring.

In our tenant, this caused `127.0.0.1` (localhost) to be ingested as a malicious IP address and trigger a burst of **"ATI Medium Priority Rule Match for Ip Address IoCs"** detections on both `principal.ip` and `target.ip`. Further investigation showed dozens of additional `GTI_IOC` `IP_ADDRESS` entities whose underlying VirusTotal source is a domain rather than an IP, dating back to at least April 2026.

---

## 1. The Triggering Case: `127.0.0.1`

We observed a wave of curated detections from **"ATI Medium Priority Rule Match for Ip Address IoCs"** matching loopback traffic (`127.0.0.1`).

Inspecting the matched `GTI_IOC` entity inside the detection revealed conflicting metadata — an `IP_ADDRESS` entity populated with domain-level WHOIS, registrar, and VirusTotal domain references:

| Field | Observed Value |
| :--- | :--- |
| `metadata.source_type` | `GLOBAL_CONTEXT` |
| `metadata.product_name` / `vendor_name` | `GTI_IOC` |
| `metadata.event_metadata.parser_version` | `6.0` |
| `metadata.event_metadata.id` | `b"AAAAADW8LYhNl/xkk8zQ5bfEx0gAAAAABwAAAAUAAAA="` |
| `metadata.collected_timestamp` | `2026-11-22T15:01:52Z` |
| `metadata.entity_type` | `IP_ADDRESS` |
| `metadata.product_entity_id` | `ip_127.0.0.1` |
| `entity.ip[0]` | `127.0.0.1` |
| `metadata.threat_intel.verdict` | `VERDICT_MALICIOUS` |
| `metadata.threat_intel.severity` | `SEVERITY_MEDIUM` |
| `metadata.threat_intel.threat_score` | `60` |
| `metadata.threat_intel.stable` | `true` |
| `metadata.threat_intel.soaked` | `true` |
| `metadata.threat_intel.attributed_malware` | `NANOCORE` |
| `attributes_mandiant_id` | `fqdn--48125eee-17b3-561c-bf52-bb627726b4ee` |
| `entity.domain.registrar` | `HOSTINGER operations, UAB` |
| `entity.artifact.whois` | Domain `TRYPORTWARP[.]CC` |
| `metadata.threat[0].url_back_to_product` | `https://www.virustotal.com/api/v3/domains/127.0.0.1yige0gph.free.tryportwarp[.]cc` |

The underlying indicator is the domain `127.0.0.1yige0gph.free.tryportwarp[.]cc` (a subdomain on what appears to be a free port-forwarding/tunneling service), not the IP address `127.0.0.1`.

### Additional Observation on Entity Search Visibility

While investigating the alert in UDM Entity Search:

* Querying the exact `url_back_to_product` of the malformed entry (`.../domains/127.0.0.1yige0gph.free.tryportwarp.cc`) returned **0 results** (search window: November 2025 to November 2026). Searching for its Mandiant ID (`fqdn--48125eee-17b3-561c-bf52-bb627726b4ee`) also returned nothing.
* A regex query (`graph.metadata.threat.url_back_to_product = /yige0gph/`) returned only the correctly typed `DOMAIN_NAME` entity for `yige0gph.free.tryportwarp[.]cc`, not the malformed `IP_ADDRESS` entry.
* Querying `graph.metadata.product_entity_id = "ip_127.0.0.1"` returned only a **benign** loopback record (`collected_timestamp: 2026-11-26T15:00:16Z`, `event_metadata.id: b"AAAAAIpUSnPZFnimySsj19lTtX4AAAAABwAAAAoAAAA="`).
* Despite only the benign record appearing in Entity Search, ATI detections for `127.0.0.1` continued to fire.

### The Real Domain Is Stored Correctly

`yige0gph.free.tryportwarp[.]cc` exists in `GTI_IOC` as a separate, correctly typed `DOMAIN_NAME` entity (`VERDICT_MALICIOUS`, same `NANOCORE` attribution, Mandiant ID `fqdn--59e0c42e...`, with an A record). The malformed `127.0.0.1yige0gph...` object has a different Mandiant ID, no DNS resolution data, and appeared ~3 hours later. All other `*.free.tryportwarp[.]cc` subdomains in the feed use 8-character random labels, so the malformed name looks like two malware config hosts (`127.0.0.1` + the real C2) concatenated upstream, and then parsed as an IP during ingestion.

---

## 2. Systemic Pattern Across `GTI_IOC`

This is not an isolated incident affecting only `127.0.0.1`. Running the following UDM Entity Search query in our tenant returned dozens of `GTI_IOC` entities typed as `IP_ADDRESS` whose `url_back_to_product` points to `/api/v3/domains/...`:

```text
graph.metadata.product_name = "GTI_IOC" AND
graph.metadata.entity_type = "IP_ADDRESS" AND
graph.metadata.threat.url_back_to_product = /\/domains\//
```

*(Note: In our tenant, the malformed `127.0.0.1` entry did not appear in Entity Search results even while alerts were firing, so check your ATI detections in addition to running this query.)*

### Observed Examples

*(Domains defanged for safety)*

| Extracted `entity.ip` | Source Domain (`metadata.threat.url_back_to_product`) | Pattern Observed |
| :--- | :--- | :--- |
| `69.232.109.208` | `.../domains/69.232.109.208.host.secureserver[.]net` | PTR-style hostname (`*.host.secureserver[.]net` typically embeds reversed octets) |
| `82.165.110.7` | `.../domains/instagram.82.165.110.7.backname[.]io` | IPv4 substring extracted from the middle of a hostname |
| `82.19.57.23` | `.../domains/82.19.57.23.71.23.krakentxy[.]com` | First 4 octets extracted from a 6-octet numeric sequence |
| `36.13.32.95` | `.../domains/36.13.32.95.67.100.23.krakentxy[.]com` | First 4 octets extracted from a 7-octet numeric sequence |
| `36.37.33.155` | `.../domains/36.37.33.155.c752sa3k9oeb2eg2ehpgc8fnhkeyyyyyn.domsearch[.]net` | Leading IPv4 substring extracted from subdomain |
| `37.165.178.68` | `.../domains/37.165.178.68.host.secureserver[.]net` | PTR-style hostname (`*.host.secureserver[.]net` typically embeds reversed octets) |
| `65.75.69.31` | `.../domains/198.265.75.69.312.11.6e7e8e5e1e2e4e6e2e.ar0u[.]com` | IPv4 carved out of the middle of longer numbers (`2`**`65.75.69.31`**`2`), ignoring adjacent digits |

Based on these examples, the parser appears to match any IPv4-like substring anywhere inside a domain string — without anchoring, digit boundaries, or validating that the source indicator is actually an IP rather than an FQDN — and emit it as a `GLOBAL_CONTEXT` `IP_ADDRESS` entity.

---

## 3. Why This Matters

* **Alert fatigue on local traffic:** Any malicious domain containing `127.0.0.1` (or other private/loopback IP strings) can flood ATI queues with false positives.
* **False positives and unintended blocks on unrelated public IPs:** Unlike `127.0.0.1`, public IP addresses extracted from reversed PTR hostnames, numeric subdomain labels, or mid-hostname substrings do not look obviously wrong during triage. SOC teams may spend time investigating benign IPs or trigger automated SOAR/firewall blocks against unrelated infrastructure.
* **Potential missed domain-level coverage:** If a malicious domain IOC is emitted only as a misparsed `IP_ADDRESS` entity instead of a `DOMAIN_NAME` entity, domain-based detection coverage for the actual indicator may also be affected. In the `127.0.0.1` case this did not happen: the real domain is present as a `DOMAIN_NAME` entity (see Section 1). We have not verified the other cases.

---

## 4. Temporary Mitigation & Verification

1. **Verify you have no actual traffic to the underlying domain** in your UDM events (without the `graph.` prefix):
   ```text
   target.hostname = /tryportwarp\.cc/ nocase OR
   network.dns.questions.name = /tryportwarp\.cc/ nocase OR
   target.url = /tryportwarp\.cc/ nocase
   ```
2. **Add a rule exclusion for loopback:** Exclude `127.0.0.1` (or `127.0.0.0/8` if your exclusion editor supports CIDR) on `principal.ip` and `target.ip` on the **"ATI Medium Priority Rule Match for Ip Address IoCs"** curated detection rule to stop loopback alert bursts.
3. **Audit ATI IP alerts carefully:** Because a loopback exclusion does not mitigate unrelated public IPs affected by the same parsing behavior, check `metadata.threat.url_back_to_product` and `entity.artifact.whois` on unexpected ATI IP detections before taking automated or manual blocking actions.
