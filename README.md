# AUR-pkgs
Glucy2's AUR packages, with automatic update checks and publishing.

## How it works
- `.automation/packages.json` is the registry: which packages are maintained (`enabled`), how their upstream is detected (`detector`) and which files are published to the AUR (`files`). Packages with `detector: "disabled"` are drafts and are never checked, built or published.
- `scripts/aur_update.py check` detects a new upstream version, refreshes checksums and `.SRCINFO`, then builds the package in a disposable Arch container (`scripts/arch-package.sh`) and verifies every declared architecture's sources.
- `scripts/aur_update.py publish` pushes only verified, whitelisted files on top of the existing AUR history. It never force-pushes. If the AUR master moved to different content, the package is reported as a conflict.
- `nali-nt-git` is built as-is first. Its automatic version bump is discarded when the build succeeds; only a failed build triggers one retry against the freshly fetched upstream HEAD.
- `.automation/aur-state.json` records the AUR master commit each package was last published from.

## Credentials
One dedicated Ed25519 key is used for both GitHub (repository Deploy key with write access) and the AUR (account key). The private half lives only in the `AUR_GITHUB_SSH_KEY` repository secret and is exposed to the publish step alone. Revoking access means removing the public key from both the repository Deploy keys and the AUR account, and deleting the secret.

## Local use
```sh
python3 scripts/aur_update.py matrix
python3 scripts/aur_update.py inspect --package wakatime
python3 scripts/aur_update.py check --package wakatime --work-dir "$(mktemp -d)/w" --result-dir "$(mktemp -d)/r"
python3 -m unittest discover -s scripts/tests -v
```
`check` needs Docker and the `archlinux:base-devel` image.
