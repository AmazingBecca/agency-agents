# Shared Composition Stack v1

This directory makes the reusable composition layer available inside the repository without changing the repo's normal dependency manifests or installing anything globally.

## Profiles

`base` provides provider-neutral HTTP/config/model-validation and deterministic test tooling.

`mirofish` adds the upstream MiroFish composition primitives: Flask, Flask-CORS, OpenAI-compatible client, Zep Cloud, CAMEL/OASIS, PyMuPDF, charset tools, and the base profile.

## Install

Base profile:

```bash
python3 .stack/bootstrap.py --profile base
```

MiroFish/social-simulation profile:

```bash
python3.11 .stack/bootstrap.py --profile mirofish
```

Dry-run without downloading:

```bash
python3 .stack/bootstrap.py --profile base --dry-run
```

The installer creates only `.stack/.venv` and `.stack/receipts`. Both are ignored by the nested `.gitignore`. It does not write Git refs, cloud resources, credentials, Docker configuration, repository dependency manifests, or production state.

## Compatibility boundary

`camel-oasis==0.2.5` declares Python `>=3.10,<3.12`. For that reason the `mirofish` profile deliberately requires CPython 3.11 even though current MiroFish metadata is broader. This avoids a silent Python 3.12 dependency conflict.

## Composition principle

Use mature primitives for ordinary execution and keep promotion/authority controls separate. Exact source identity, deterministic tests, receipts, and independent review remain the proof layer. A portable analysis or simulation environment is not promotion authority.
