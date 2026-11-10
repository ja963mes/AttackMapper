# AttackMapper
a tool that turns your dependencies into an attack map

## Limitations

### Most weaknesses don't map to ATT&CK
AttackMapper links weaknesses (CWE) to attacker techniques (ATT&CK) through MITRE's attack patterns (CAPEC). That link only exists where CAPEC lists an ATT&CK technique.

In CAPEC 3.9, **149 of 336 CWEs (about 44%)** reach at least one ATT&CK technique. Vulnerabilities whose weakness falls in the other 56% stop at CAPEC and do not appear on the attack map. The report counts them as "no ATT&CK" dead ends, so they are not lost silently.
