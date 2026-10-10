# Third-party research code

## SCALE / Comment4Vul

- Source: https://github.com/Xin-Cheng-Wen/Comment4Vul
- Paper: SCALE: Constructing Structured Natural Language Comment Trees for
  Software Vulnerability Detection, ISSTA 2024.
- Imported components: the public repository is retained under
  `third_party/Comment4Vul` as a research reference for its symbolic rules and
  experiment layout.
- Security cleanup: legacy comment-generation scripts were removed because
  the public files contained hard-coded historical API credentials. Nested Git
  history was also removed so those credentials are not retained locally.
- Licensing: no repository-level license file was present when retrieved.
  Treat the vendored material as research reference code and do not redistribute
  it without obtaining permission from the authors.

`adaptive_mulvul.scale_transformer` is a modern integration adapter. It follows
SCALE's public two-stage design but is not presented as an exact reproduction
of unreleased MulVul preprocessing.
