# Agent transparency and operator responsibilities

Users should be able to inspect the software that shapes an agent's behavior.
Source access is necessary for that goal but does not by itself attest what a
particular service is running or reveal a proprietary model's internals.

## What is published

This snapshot includes Peirce's durable source principles, two source-defined
skills, project-gateway implementation and tests, an access ledger, illustrative
configuration, and research image tooling. The gateway exposes seven bounded
capabilities; the contracts identify which decisions are host-controlled and
which remain agent judgment.

The source also documents limitations worth inspecting: shared profile memory,
soft cross-session/project boundaries, external model and web providers, and a
significant-risk reporting capability. The latter can report to an
operator-configured administrative destination without announcing the report
to the requester. There is no claim that prompts alone provide isolation or
that model-generated research is correct.

## What this snapshot does not establish

- That a running service uses this exact source, prompts, configuration, or
  model. Installation identities and memory starters here are sanitized.
- The full assembled prompt of a particular session, live learned skills,
  runtime memory, or private project context.
- A proprietary model's weights, hidden reasoning, training data, or internal
  behavior.
- A reproducible deployed image, host-hardening certification, or protection
  from every prompt-injection attempt.

Credentials, private research, conversations, and user data are not part of this
public preview. This is a statement of the preview's contents, not a legal
exemption for software required in another deployment's corresponding source.

## AGPL source access

Original Peirce material is licensed under GNU AGPL version 3 only. If you
modify a covered program and it supports remote network interaction, section
13 requires a prominent opportunity for all users interacting with that version
to receive its corresponding source from a network server at no charge. Other
AGPL obligations also apply when conveying covered works. The full
[`LICENSE`](../LICENSE) controls, not this summary.

Offer source corresponding to the version users actually interact with,
including applicable modifications, notices, and required build/install/run
material. Merely linking to this older or sanitized snapshot may be
insufficient. Prompts, skills, or configuration may be part of corresponding
source depending on their role; do not omit required software by labeling it
"private configuration."

Separate secrets and user data from software and provide non-secret instructions
for required setup. If privacy, third-party terms, or licensing obligations
conflict, resolve that before operating or distributing the covered version.
This guide does not decide the legal boundary of every model/plugin/host
combination, nor impose the license on unrelated agents.

## Recommended deployment disclosures

Operators should provide an easily accessible About or help entry identifying:

- The operator, deployed source version, and a working source-download link.
- Material source-defined instructions, skills, and differences from a named
  public release.
- Current model/provider choices and where user material may be sent.
- Available capabilities, access boundaries, memory sharing, and administrative
  reporting behavior.
- Which information is deployment-specific, private user data, or unavailable
  from an external model provider.

These are project transparency recommendations, not extra AGPL terms or a
feature already implemented by this preview. Any changes to a live service,
including its source offer and disclosures, need separate deployment work.
