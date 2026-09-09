# Third-party scope and provenance

The AGPL-3.0-only scope described in `README.md` applies to original Peirce
material, not to unrelated dependencies, services, model weights, or their
outputs. Referencing a dependency is not a claim to own or relicense it.

## Hermes

Peirce is a plugin/profile for [Nous Research's Hermes agent](https://github.com/NousResearch/hermes-agent).
The development baseline used `v2026.8.3`, commit
`3c27eb6234bf91b8ceee9e9071591b31e9b148cb`. Its top-level license is
[MIT, copyright 2025 Nous Research](https://github.com/NousResearch/hermes-agent/blob/3c27eb6234bf91b8ceee9e9071591b31e9b148cb/LICENSE).

This snapshot does not vendor Hermes, its bundled skills, or deployment
backports. References to built-in skills in `config.yaml` are configuration,
not copies of their contents. The two definitions under `skills/` are Peirce
source material. Hermes bundles some components with separate terms; consult
the actual files and notices for any version you redistribute rather than
assuming the top-level MIT license covers every bundled component.

MIT permits integration with AGPL software subject to its notice requirements.
The legal boundary of a combined plugin/runtime depends on the integration;
this document is not a finding that every possible deployment is an aggregate
or that unrelated services become AGPL-covered.

## Research image and test dependencies

`ops/image/recipe/` contains a recipe and dependency lists, not an OCI image,
package archive, model, or bundled operating system. Ubuntu packages, CPython,
R, CRAN packages, and Python dependencies retain their own terms. Operators
building or distributing an image must satisfy the applicable licenses,
notices, and source obligations for its actual contents. No image-license audit
or reproduction of a historical deployment is claimed by this source release.

The image-evidence validator uses PyYAML and pytest for offline tests. Gateway
source tests use Python's standard library and local Git. Provider services and
model weights are external and subject to their own terms and privacy policies.

## Future additions

Record the origin, version, license, and required notices of any copied or
adapted third-party material before publication. Preserve its original terms.
Do not include material with unresolved redistribution rights. See
`CONTRIBUTING.md` for the rights and attribution policy.
