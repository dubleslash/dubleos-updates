# dubleos-updates — the Duble//OS update feed

Static, public update feed served by GitHub Pages at:

    https://dubleslash.github.io/dubleos-updates

Every installed copy of Duble//OS pings `latest.json` at session start (a plain GET — no
identifiers, no telemetry) and, when a newer version exists, fetches that version's **signed**
bundle from `<version>/bundle.json`.

## What's here

    latest.json           # {version, kind, headline} — the pointer installs poll
    <version>/bundle.json # the signed integration-intent bundle for that version
    <version>/assets/...  # files a bundle carries, each pinned by sha256 inside the signature
    .nojekyll             # keep GitHub Pages from filtering files

## Assets

Intents are prose an install reconciles into its own files. When a release must deliver a file
**byte-exact** (a template, a verified shell, the updater's own engine), the intent lists it under
`assets` and `build.mjs --release` copies it here and pins its `sha256` inside the signed bundle.
Installs fetch it from this host, hash it, and refuse to write it on any mismatch — so this host
stays untrusted by design, exactly as it is for bundles.

## Sequencing — `latest.json` is a release valve, not just a pointer

A bundle may depend on machinery an earlier one installed, and installs apply versions in
ascending order. When a release upgrades the updater itself, **publish the whole chain but hold
`latest.json` at the bootstrap version** until installs have picked it up, then move the pointer
forward. Re-running `node build.mjs --release <older>` last is what sets the pointer back.

## Publishing a release

Never hand-edit these files. Build them in the product repo (`~/Documents/dubleos`):

    node build.mjs --release <version>     # signs with the private key
    cp -R dist/updates/. ../dubleos-updates/
    cd ../dubleos-updates && git add -A && git commit -m "release <version>" && git push

Bundles are signed with the Duble//Slash private key (`.dubleslash-signing-key`, never committed,
backed up offline). Installs verify every bundle against the public key baked into them, so a
tampered or unsigned file here is refused whole — this host is untrusted by design.

## Don't

- Don't delete or rename old `<version>/` folders — installs on older editions still fetch them.
- Don't change the Pages URL: it is baked permanently into every shipped copy and no update can
  rewrite it.
