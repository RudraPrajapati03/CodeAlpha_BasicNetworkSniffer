# NIDS Alert Response Playbook

## Scope

This playbook documents a human-reviewed response workflow for the educational Suricata demo. The current custom rule detects ICMP Echo Requests only. It does not automatically block traffic, and a ping alert alone is not evidence of an attack.

## Response workflow

1. **Review the alert:** Check timestamp, signature/message, source and destination addresses, interface, and related log entries.
2. **Validate context:** Confirm whether the activity came from an authorized test, monitoring system, or known host. Correlate with other logs before classifying it.
3. **Assess severity:** Treat the included ICMP test alert as informational unless independent evidence indicates otherwise.
4. **Escalate when uncertain:** Share the alert and relevant sanitized logs with the responsible network/security administrator.
5. **Contain only with authorization:** If independent evidence confirms a threat, an authorized administrator may isolate the affected endpoint or apply an approved firewall rule under the organization's incident-response procedure. Confirm business impact and preserve evidence first.
6. **Record the outcome:** Document the decision, actions, owner, time, and verification that service was restored safely.
7. **Close and improve:** Review whether the alert was expected, a false positive, or part of a wider incident. Tune rules only after testing.

## Safe lab validation

- Generate the included ping test only against your own host or local gateway.
- Confirm that the alert appears in `logs/fast.log`.
- Do not automatically block ICMP or change firewall rules on a shared/production network for this demonstration.
- Never describe the playbook as automated prevention: the current project is alert-only.
