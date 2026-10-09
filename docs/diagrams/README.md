# Operator diagrams

Self-contained **HTML** slides (open locally in a browser) plus **SVG** for GitHub / markdown embeds. Static HTML+SVG; no Mermaid deliverable; no secrets.

**Mode C (standalone):** plates live here. Craft/export uses a **vendor bridge** to MiscRepos’s pinned [diagram-design](https://github.com/cathrynlavery/diagram-design) skill (SHA in that repo’s `.cursor/skills/diagram-design/VENDOR.md`) — this tree does not vendor the full skill. Export:

```text
python <MiscRepos>/.cursor/skills/diagram-design/scripts/export_svg.py docs/diagrams/<name>.html docs/diagrams/<name>.svg
```

Tokens: dark paper `#2d3142`, ink `#f5f5f5`, accent `#f08a59`. Audience=operator, detail=simplified, size=slide-16x9.

## Catalog

| File | Type | Why |
|------|------|-----|
| [scp-pipeline.html](scp-pipeline.html) · [svg](scp-pipeline.svg) | Data flow | Inspect → sanitize → contain/quarantine → sinks — operator view of the content gate |
