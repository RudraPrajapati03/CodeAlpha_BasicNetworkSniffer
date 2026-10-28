# NIDS Alert Response Playbook

## Scope
This playbook documents a human-reviewed response workflow for the educational Suricata demo. The current custom rule detects ICMP Echo Requests only. It does not automatically block traffic, and a ping alert alone is not evidence of an attack.

## Response workflow
1. Review the timestamp, signature/message, source and destination addresses, interface, and related log entries.
2. Validate context: confirm whether the activity came from an authorized test, monitoring system, or known host. Correlate with other logs before classifying it.
3. Assess severity: treat the included ICMP test alert as informational unless independent evidence indicates otherwise.
4. Escalate uncertain events to the responsible network/security administrator with sanitized logs.
5. Contain only with authorization: if independent evidence confirms a threat, an authorized administrator may isolate an endpoint or apply an approved firewall rule under the organization's incident-response procedure. Consider business impact and preserve evidence first.
6. Record the decision, actions, owner, time, and verification that service was restored safely.
7. Review whether the alert was expected, a false positive, or part of a wider incident. Tune rules only after testing.

## Safe lab validation
- Generate the included ping test only against your own host or local gateway.
- Confirm the alert appears in `logs/fast.log`.
- Do not automatically block ICMP or change firewall rules on a shared/production network for this demonstration.
- This playbook is a human-reviewed workflow, not automated prevention.
