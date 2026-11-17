# Security Policy

This repository contains the source code of a diploma thesis on attack
detection in Software Defined Networks (SDN). It is an academic prototype,
not production software.

## Supported versions

Only the latest commit on `master` is maintained.

## Reporting a vulnerability

Please do **not** open a public issue for security problems.
Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository.

You can expect an initial reply within 7 days.

## Demo credentials

The API tokens in `app_sdn/docker-compose.yml` and the demo scripts
(`SWITCH_API_KEY`, `ADMIN_API_KEY`) are **public demo defaults** for running
the experiments locally. They are not secrets. If you deploy this code
anywhere reachable from a network, override them with your own values via
environment variables.
