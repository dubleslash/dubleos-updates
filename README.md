# dubleos-updates — the Duble//OS update feed

Static, public update feed served by GitHub Pages at:

    https://dubleslash.github.io/dubleos-updates

Every installed copy of Duble//OS pings `latest.json` at session start (a plain GET — no
identifiers, no telemetry) and, when a newer version exists, fetches that version's **signed**
bundle from `<version>/bundle.json`.

## What's here

    latest.json          # {version, kind, headline} — the pointer installs poll
    <version>/bundle.json # the signed integration-intent bundle for that version
    .nojekyll            # keep GitHub Pages from filtering files

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
