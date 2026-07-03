# CodeRabbit Round: Asset Source Notes

## Round 1

- Scope: local
- Round number: 1
- Command or trigger: `coderabbit review --agent --type all --base main -c AGENTS.md`
- Started: 2026-07-03T10:42:00-0500
- Completed: 2026-07-03T10:48:00-0500
- Availability: completed
- Fallback review thread: not needed

## Findings To Address

| Finding | Severity | Decision | Notes |
| --- | --- | --- | --- |
| `WorkingTreeIntentContent::AssetBytes` allowed bytes and content hash drift | major | addressed | Removed independent `content_hash` from the public intent variant; hashes are derived from bytes at encode/materialization boundaries. |
| Asset payload structs and batches lacked explicit bounds | major | addressed | Added v1 max Asset byte and batch count guardrails in core materialization/planning paths. |
| Working-tree materialization cloned unbounded Asset bytes | major | addressed | Core now rejects Assets above the shared size limit before cloning into the binary projection map. |
| OKF asset target planning could collapse duplicate filenames | major | addressed | Product Client import planning now tracks planned targets and copies duplicate Asset targets to unique paths. |
| OKF Markdown link rewriting excluded Asset entries | major | addressed | Product Client link rewriting can resolve Source Note links to imported Asset target paths while keeping Asset entries non-Markdown. |
| `fbrain` Source Note matching used raw substring checks | major | addressed | CLI scanner now requires exact path-token boundaries and covers prefix collisions such as `file.pdf` versus `file.pdf.bak`. |
| `fbrain` file traversal and Asset byte handling were unbounded | major | addressed | CLI scanner now bounds file count, recursion depth, Asset reads, Asset encode, and Asset decode. |
| Imported Product Client Asset projection trusted stale OKF metadata | major | addressed | Imported Asset projection now derives size and content hash from the imported bytes. |

## Findings Not Addressed

| Finding | Reason |
| --- | --- |
| None | |

## Result

- Continue: yes
- Escalate: no
- Notes: All round 1 findings were addressed with focused tests and verification.

## Round 2

- Scope: local
- Round number: 2
- Command or trigger: `coderabbit review --agent --type all --base main -c AGENTS.md`
- Started: 2026-07-03T10:51:00-0500
- Completed: 2026-07-03T10:54:00-0500
- Availability: completed
- Fallback review thread: not needed

## Findings To Address

| Finding | Severity | Decision | Notes |
| --- | --- | --- | --- |
| None | | | CodeRabbit raised 0 issues. |

## Findings Not Addressed

| Finding | Reason |
| --- | --- |
| None | |

## Result

- Continue: yes
- Escalate: no
- Notes: CodeRabbit round 2 completed with 0 issues.
