# Peirce

An AI research collaborator for Slack, built on
[Hermes](https://github.com/NousResearch/hermes-agent). Peirce brings research
questions, source inspection, computational work, and reviewable GitHub changes
into a channel's conversation.

**This repository is a sanitized source preview, not a hosted service or a
turnkey deployment.** It contains real implementation and tests, with example
installation identities and empty memory starters. It does not claim to be the
exact source and configuration of any running Peirce instance.

## What Peirce does

- Research questions, inspect evidence, and state assumptions and uncertainty.
- Use a research computing environment to create and check artifacts.
- Work with the current Slack channel's GitHub project through bounded tools.
- Prepare task-branch changes and pull requests for human review.
- Keep durable project knowledge in the project's repository.

For example, a configured instance can be asked to inspect an argument, check a
computation, or propose a documented change in the current project. These are
illustrative requests, not claims that this snapshot has run a particular study.
Humans create repositories, grant access, review changes, merge, and deploy.

## Inspect the agent

Users should be able to understand the software they are interacting with.
Start with the following source and contracts:

| Component | What it tells you |
| --- | --- |
| [`SOUL.md`](SOUL.md) | Peirce's durable behavioral principles |
| [`skills/`](skills/) | Source-defined usage and self-development guidance |
| [`plugins/project-gateway/`](plugins/project-gateway/) | Seven bounded Slack/GitHub project capabilities and their implementation |
| [`docs/access-and-permissions.md`](docs/access-and-permissions.md) | Authority, credentials, and trust boundaries |
| [`config.yaml`](config.yaml) | Illustrative model, tool, memory, and Slack configuration |
| [`ops/image/recipe/`](ops/image/recipe/) | Research-computing image recipe, not a distributed image |
| [`docs/transparency.md`](docs/transparency.md) | What this source reveals, what it cannot prove, and operator responsibilities |

The gateway handles repository access, channel association, workspaces,
bookmarks, Git, GitHub, and significant-risk reporting. Its
[capability contract](plugins/project-gateway/README.md) describes the exact
actions and restrictions.

**Important limits:** profile memory and learned skills are shared across
authorized channels. Some cross-project/session boundaries depend on agent
instructions rather than mechanical isolation. Model outputs can be wrong, and
untrusted content can attempt prompt injection. This is not a hardened
multi-tenant service. Read the trust ledger before considering deployment.

## Explore and test

The gateway source tests use Python's standard library and local temporary Git
repositories. They do not need Slack, GitHub, or model credentials. Use Python
3.12 or newer and Git:

```sh
python3 -m unittest discover -s plugins/project-gateway/tests -p 'test_*.py'
```

Optional offline image-validator tests use an isolated environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r ops/image/verify/requirements.txt
.venv/bin/python -m pytest ops/image/verify/tests
```

No image has been built or deployed as part of this source release. Linux
descriptor checks, host permissions, provider integration, and live Slack
behavior require separate operator verification.

## Using a deployment

The [usage guide](docs/using-peirce.md) describes interaction with an instance
that its operator has configured and approved. This repository does not grant
access to a Slack workspace, private project, GitHub App, or model service.

Slack is disabled in the example configuration. Repository IDs `101` and `202`,
the `peirce-example` organization, and host paths are unverified examples, not
destinations to use. Adapting them requires a coordinated review of the source,
configuration, tests, credentials, and host controls; enabling Slack alone is
not an installation procedure. The public repository is not a live source/admin
project association.

The development baseline used Hermes `v2026.8.3` at commit
`3c27eb6234bf91b8ceee9e9071591b31e9b148cb`. Hermes, its bundled skills, model
weights, and private deployment integrations are not included. See
[`THIRD_PARTY.md`](THIRD_PARTY.md) for scope and provenance.

## License and credit

Original Peirce code, prompts, skills, configuration, tests, and documentation
in this snapshot are licensed under **GNU Affero General Public License version
3 only**, SPDX `AGPL-3.0-only`, except material identified under separate terms.
See [`LICENSE`](LICENSE), [`NOTICE`](NOTICE), and [`THIRD_PARTY.md`](THIRD_PARTY.md).
The license text itself retains its own copying notice.

If you modify covered software and operate it for remote users, AGPL section 13
requires an appropriate offer of its corresponding source. A link to an older
or materially different snapshot is not a substitute for that source. See the
[transparency guide](docs/transparency.md); the license text controls.

Initial development: **Qingyuan Zhao**, with AI-assisted development. See
[`AUTHORS.md`](AUTHORS.md) for credit and [`CITATION.cff`](CITATION.cff) for citation
metadata. Please cite the release you use; this request adds no license term.

## Contributing and publishing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting work. This repository
is a curated public snapshot, not an automatic mirror of private development or
live learning. Pushes and pull requests are already publication: privacy review
must happen beforehand, not only before merging.

The [publication record](docs/publication.md) describes the source baseline,
sanitization, and limits of this release. Do not include private research,
personal profiles, credentials, or live conversations in public contributions.
