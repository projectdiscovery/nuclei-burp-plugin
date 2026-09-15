# Releasing

## 1. Cut the GitHub release

Create a release with a `v`-prefixed tag (e.g. `v1.1.4`). The tag is the source
of truth for the version, so nothing needs to be committed to `main` first.

`.github/workflows/ci.yml` builds the shaded jar at that version and attaches
`nuclei-burp-plugin-<version>.jar` to the release.

## 2. Submit to the BApp Store

Run the **Submit to BApp Store** workflow and give it the version (e.g. `1.1.4`).
It performs both steps PortSwigger requires:

1. Opens a pull request on [`PortSwigger/nuclei-template-generator`](https://github.com/PortSwigger/nuclei-template-generator)
   from `projectdiscovery:main`. Updates are only accepted from the parent
   repository of that fork.
2. Opens an update submission issue on
   [`PortSwigger/extension-portal`](https://github.com/PortSwigger/extension-portal)
   linking that pull request.

The portal comments on the issue within a few minutes. On failure, fix the
problem and comment `/resubmit` on that same issue. Do not open a second one.

Emailing bapps@portswigger.net is no longer part of the process; the portal
replaced it.

### Token

Uses the organisation secret `PDTEAMX_CLASSIC_PAT`, so there is nothing to set up.

It has to be a classic PAT belonging to an account outside PortSwigger, because
both steps act on repositories in another organisation. `GITHUB_TOKEN` cannot be
used: its permissions are limited to the repository containing the workflow.
