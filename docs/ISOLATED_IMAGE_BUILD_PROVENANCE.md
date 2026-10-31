# Isolated Docker Image: Reproducible Build Inputs

**Gate 5A (2026-10-10):** Source hardening and offline testing only.
No image, container, Docker engine resource, model, registered attack, or
research experiment was run in this gate.

## Approved upstream evidence

The separately verified Gate 5A-N records live outside Git at:

`/home/zain/fyp-provenance/gate5an-3dddff40389c-py313-linux-amd64/`

Independent evidence-index SHA-256:
`5a251d0a4911a15e2a5dbebcd673dc59595aa1b106777d988c1fd3788f81fd43`

- Official `python:3.13-slim` Linux AMD64 child manifest:
  `sha256:8fb4cfa1a2616d7b8e0c2175cc6ad68f5729c34ea8488c0b360d2934b7be9024`.
- Official multi-platform index:
  `sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f`.
- Exactly 33 PyPI wheel artifacts with independently matched filenames, sizes,
  SHA-256 digests and CPython 3.13 Linux AMD64 compatibility.
- 38 applicable dependency relationships with no missing dependency in the
  recorded candidate set.

The wheel selection is specific to the recorded retrieval time and target.
It is not runtime acceptance and it does not claim signed wheel provenance.

## Implemented source controls

- `dummy_apps/vulnerable_store/Dockerfile` pins the verified Linux AMD64
  child manifest. It installs from the HTTPS official PyPI index with
  `--require-hashes` and `--only-binary=:all:`, then installs the local
  FYP package using `--no-deps --no-build-isolation`. Build-time setuptools
  is among the hashed wheels; this avoids an unbounded second dependency
  resolver for project packaging.
- `requirements/isolated-py313-linux-amd64.lock` contains exactly 33
  selected wheel hashes. An alternate wheel, a changed wheel, a source
  distribution or a missing artifact must fail installation rather than
  silently substituting another package.
- `.dockerignore` allows only the Dockerfile's 11 copied directory roots and
  two copied top-level files, followed by mandatory secret/cache/runtime
  exclusions. The Dockerfile is supplied separately by the builder.
- `scripts/verify_isolated_build_inputs.py` checks independently pinned
  evidence against its actual raw files and 33 wheel bytes, then compares
  the Dockerfile, wheel lock, project requirements and .dockerignore policy.
  Its **CLI** also requires a clean `development` checkout matching an
  externally authorized Git HEAD and tree, and emits hashes for relevant
  committed build inputs. It never calls Docker, installs packages or
  contacts any network.

## After a separately approved local source commit

The following is a **read-only example for a future authorization**, not
a command run in Gate 5A. The expected HEAD and tree must be updated from
the future reviewed commit; do not reuse the old `3dddff4` values.

```bash
ROOT="/home/zain/Documents/RED FYP/autonomous-red-blue-fyp"
PROVENANCE="/home/zain/fyp-provenance/gate5an-3dddff40389c-py313-linux-amd64"
python3 -B "$ROOT/scripts/verify_isolated_build_inputs.py" \
  --repo "$ROOT" \
  --evidence "$PROVENANCE" \
  --evidence-index-sha256 5a251d0a4911a15e2a5dbebcd673dc59595aa1b106777d988c1fd3788f81fd43 \
  --expected-head "<approved future 40-character HEAD>" \
  --expected-tree "<approved future 40-character Git tree>"
```

Record the JSON output and its SHA-256 in an independently approved external
evidence directory. The record identifies the approved committed source,
selected build-input bytes, base manifest and hashed package resolution.
It is **not an image build or container attestation**.

## Future build and independent image attestation

Require separate permissions to prepare an isolated build context, retrieve
the pinned Python base layers and allow the Dockerfile's hashed PyPI downloads,
and build an image. Prefer building from a disposable, new, clean `git archive`
of the approved commit **outside** the live checkout. This eliminates any
Git-ignored files from the build source, even if they would have been allowed
by a Docker context pattern. Audit the archive contents against the committed
source manifest before permitting a build.

Build the intended image exactly once and give it the isolated tag
`fyp-r4c4f-red-blue-lab:local`; never rebuild or retag the historical
`fyp-red-blue-lab:local`. Require independently checked provenance labels
for the approved HEAD, tree, pre-build input manifest and isolated Compose
project (`com.docker.compose.project=fyp-r4c4f-red-blue-lab`).
Container-level Compose labels alone do **not** authenticate the image.
Capture build logs, resolved base/config digests, the resulting image ID and
label values and independently cross-check them before any container startup.
Labels are assertions, not cryptographic proof of build correctness.

Separate subsequent approvals remain required for image-build mutations,
isolated container startup, container-exec runtime source verification, and
one registered development-only attack observation. No automatic cleanup,
retries, inference, generated patches or final research experiments.

## Known limits

A source verifier can detect pin drift and reconstruct an approved input
manifest, but without a real authorized image build it cannot prove pip
installation, source packaging, image content, container health or a complete
source-to-image link. Upstream artifact content and dependency integrity
were checked through official registry/PyPI metadata and SHA-256, not via
verified publisher signatures. A pinned image manifest may later become
unavailable remotely; builds should then fail, not substitute a moving tag.

The original Compose files, vulnerable source, registered tests, frozen
historical mock receipts and security policies were not modified in Gate 5A.
