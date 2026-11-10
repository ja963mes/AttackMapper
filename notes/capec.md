# CAPEC data notes

Source: https://capec.mitre.org/data/downloads.html
File: data/1000.csv (Mechanisms of Attack, view 1000)
Version: CAPEC 3.9

## Related Weaknesses (CAPEC → CWE)
- Example (CAPEC-49): `::521::262::263::257::654::307::308::309::`
- Bare CWE numbers separated by `::`, no "CWE-" prefix.
- Add "CWE-" so they match OSV's format (e.g. `CWE-307`).

## Taxonomy Mappings (CAPEC → ATT&CK)
- Example (CAPEC-49): `TAXONOMY NAME:ATTACK:ENTRY ID:1110.001:ENTRY NAME:Brute Force:Password Guessing::`
- Entries are separated by `::`. A row can have several.
- ATT&CK IDs have no "T". Add it: `1110.001` → `T1110.001`.
- Other taxonomies appear too (WASC, OWASP Attacks). Keep only `TAXONOMY NAME:ATTACK`.
- Some entries have no ENTRY ID (e.g. the OWASP ReDoS entry). Don't assume it's there.
- ENTRY NAME can contain colons (`Masquerading: Invalid Code Signature`). Only use ENTRY ID.
- Some rows have no ATT&CK mapping at all.
- Some rows have taxonomy entries but none for ATTACK (e.g. only WASC + OWASP). WASC entries also have ENTRY IDs, so always check TAXONOMY NAME first.
