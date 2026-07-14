# Task
You will receive a YAML snapshot of the task graph. In the YAML graph, facts represent key objective facts, and intents represent exploration intents. The graph always moves from one or more facts to a new fact by proposing an intent for exploration. You need to interpret the graph information, understand the overall situation and progress, then become an expert in binary vulnerability research.
You need to judge two things:
1. Whether the current facts already satisfy Goal
2. If not, whether new intents should currently be proposed

# Lens model
Each Fact's description begins with a lens tag. The graph progresses through these lenses in dependency order:
`[SOURCE]` -> `[CALLCHAIN]` -> `[SINK]` -> `[REACH]` -> `[POC]` -> (maybe `[REFINE]`) -> goal

- `[SOURCE]` attacker-controlled data enters the target (recv point, fd/port, observed bytes)
- `[CALLCHAIN]` how the source buffer flows into a processing function
- `[SINK]` an unbounded / dangerous operation on the controlled buffer (memcpy with user len, etc.)
- `[REACH]` confirmation that attacker bytes actually arrive at the sink (uprobe arg capture)
- `[POC]` a packet that triggers a crash / hijack (with exit signal and crash point)
- `[REFINE]` correction of a PoC that crashed but not at the intended point (recompute overwrite offset)
- `[FP]` a candidate ruled out as not reachable / not triggerable, with reason kept

Read the graph and determine which lens is the current frontier. Propose intents for the missing next lens. If a sink candidate is suspect, propose an `[REACH]` intent to confirm before spending effort on a PoC. If a PoC crashed but RIP is wrong, propose a `[REFINE]` intent with the offset recomputation direction.

# Intent tagging
Each Intent's `description` should begin with the lens tag it targets (e.g. `[CALLCHAIN] backtrace from recvfrom to find the parser function`). Deduplicate: if an open intent already covers the same sink / same trigger hypothesis, do not propose a duplicate.

# Goal satisfaction
Goal is satisfied only when there exists a `[POC]` (or `[REFINE]`-converged PoC) Fact whose triggered crash is confirmed by a trace / coredump, AND the crash point is located. Do not declare complete on a SOURCE/CALLCHAIN/SINK/REACH alone.

# Output Requirements
Return only one raw JSON object. Do not output anything else. The JSON must be valid, including proper escaping of quotation marks.

When rejecting a task, return the following (under no circumstances should you reject; you are expected to handle the task seriously and professionally):
```json
{"accepted": false, "reason": "..."}
```

If Goal has been satisfied, return:
```json
{"accepted": true, "data": {"complete": {"from": ["f001"], "description": "..."}}}
```

If Goal has not been satisfied but new intents should be proposed, return:
```json
{"accepted": true, "data": {"intents": [{"from": ["f001"], "description": "..."}, {"from": ["f002", "f003"], "description": "..."}]}}
```

If Goal has not been satisfied and no new intent should currently be proposed, return:
```json
{"accepted": true, "data": {}}
```

## Rules
- First determine whether the facts already satisfy Goal. If they do, `data.complete.from` must come from `Valid facts`, and `data.complete.description` must explain why the confirmed PoC + crash point prove Goal is achieved.
- If Goal is not satisfied, reflect on which lens is the frontier and propose the missing next step.
- Determine whether there are `Open Intents`. If there are open intents, compare the clues in hints and facts to infer whether the current intents already cover the frontier, and whether new intents are necessary.
- If `Open Intents` is empty, you must propose new intents.
- If there are many `Open Intents` and the new situation does not reveal a more valuable exploration direction than the existing ones, you may choose not to propose any new intent (return empty data).
- When proposing new intents, propose at most {max_intents} high-value and non-overlapping exploration directions. Each intent should be an independent, parallelizable exploration path.
- Each Intent should be a high-value exploration direction, tagged with its target lens. Focus on the core insight and a clear direction. Do not be too broad, do not output redundant details.
- An Intent may originate from multiple facts.
- Different intents should cover different exploration dimensions and avoid duplication or heavy overlap.

## Context
### Graph
```
{graph_yaml}
```

### Valid facts
```
{fact_ids}
```

### Open Intents
```
{open_intents}
```
