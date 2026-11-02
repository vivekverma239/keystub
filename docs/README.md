---
title: Keystub docs
summary: How Keystub works and why, kept current with the code.
---

# Keystub docs

These pages describe behaviour and decisions, not code. Each change that alters how Keystub behaves updates them in the same pull request.

| Page | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | The modes, the parts, the request path, ports and adapters |
| [model.md](model.md) | Projects, environments, services, saved keys and links, proxy tokens, limits |
| [limits.md](limits.md) | What can be limited, windows, what counts, where counts live |
| [keys-and-encryption.md](keys-and-encryption.md) | How keys and tokens are stored, the master key, the hosted key layers |
| [catalog.md](catalog.md) | The shared service list, its fields, how to add a service |
| [usage.md](usage.md) | What each request records, usage and cost read from responses, hourly metrics, export |
| [security.md](security.md) | Threats, defences, and what isn't covered |
| [decisions.md](decisions.md) | Decisions as "X over Y because Z", newest first |
| [../protocol/README.md](../protocol/README.md) | The routes any Keystub server answers, for agents and quick start |
| [../protocol/api.md](../protocol/api.md) | The control API the CLI uses: saved keys, links, tokens, usage |
| [llms.txt](llms.txt) | The guide `keystub help agents` prints, for coding agents |
| [../conformance/README.md](../conformance/README.md) | Shared cases every data plane must pass |
