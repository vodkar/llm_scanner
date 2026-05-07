# Ranking System for Context Nodes

## 1. Purpose and Role in the Pipeline

The ranking system orders **context nodes** retrieved around a candidate finding before they are rendered into the LLM prompt. Its goal is to maximize the security-relevance density of the prompt under a hard **token budget**: nodes are ranked, then rendered greedily; once the budget is exhausted the remaining nodes are dropped (`context_assembler.py:127-147`). Ranking quality therefore translates directly into which lines of code reach the model and which are truncated — it is the principal lever that determines whether the LLM sees the source, sink, sanitizer, or only adjacent boilerplate.

A context node carries the following ranking-relevant attributes: a graph **depth** from the root finding (number of hops in the Code Property Graph), a **node kind** (function, class, code block, variable), a **file path**, a **repeat count** (how many times the node was reached during BFS expansion), an optional per-edge-type depth dictionary `edge_depths` (used by the CPG-structural variant), and a `taint_score` produced upstream by taint-flow analysis.

## 2. Score Composition

Ranking is a **multi-signal linear scoring scheme** with four top-level components:

$$
S_{\text{final}}(n) = w_{fe}\,S_{fe}(n) + w_{sp}\,S_{sp}(n) + w_{t}\,S_{t}(n) + w_{c}\,S_{c}(n)
$$

where $w_{fe}, w_{sp}, w_{t}, w_{c} \in [0,1]$ are the *combiner* weights (`CombinerWeights`) and the components are:

- $S_{fe}$ — **finding-evidence score**: how directly an analyzer (Bandit, Dlint) has flagged this node.
- $S_{sp}$ — **security-path score**: lexical and CWE evidence that the node sits on a vulnerable data path.
- $S_{t}$ — **taint score**: precomputed by the taint pipeline and injected into the node prior to ranking.
- $S_{c}$ — **context score**: graph-structural relevance, irrespective of security signals.

Every component and sub-score is clamped to $[0,1]$ via `_clamp_score` before composition, so $S_{\text{final}} \in [0,1]$.

### 2.1 Finding-evidence score $S_{fe}$

For a node $n$ with the multiset $F(n)$ of analyzer findings directly attached to it via `StaticAnalysisReports` edges:

$$
S_{fe}(n) = \alpha\,\sigma^*(n) + \beta\,\kappa^*(n) + \gamma\,A(n)
$$

with

- $\sigma^*(n) = \max_{f \in F(n)} \sigma(f)$, the maximum severity over findings, where $\sigma$ maps Bandit/Dlint severity tiers (LOW / MEDIUM / HIGH) to numeric scores.
- $\kappa^*(n) = \max_{f \in F(n)} \kappa(f)$, an analogous confidence proxy derived from the same severity tier.
- $A(n)$, an **agreement** indicator: highest when both Bandit and Dlint flag the node, partial when multiple findings of one analyzer agree, zero for an isolated finding. This rewards multi-analyzer corroboration.

If $F(n) = \emptyset$, then $S_{fe}(n) = 0$. Dlint findings are mapped to severity tiers via fixed `issue_id` ranges (`DLINT_SEVERITY_BY_ISSUE_RANGE`).

### 2.2 Security-path score $S_{sp}$

This component captures **lexical heuristics** for source/sink/guard semantics over the node's snippet text $T(n)$, plus a CWE-driven boost. Define indicators:

$$
\mathbf{1}_{\text{sink}}(n), \mathbf{1}_{\text{source}}(n), \mathbf{1}_{\text{guard}}(n) \in \{0,1\}
$$

corresponding to the presence of any token from curated keyword lists (`SINK_HINTS`, `SOURCE_HINTS`, `GUARD_HINTS`) inside $T(n)$ — e.g. `subprocess`, `eval`, `pickle.loads` for sinks; `request`, `argv`, `getenv` for sources; `validate`, `sanitize`, `escape` for guards.

A path-evidence term $E_{\text{path}}(n)$ is activated when a Bandit finding on $n$ carries a **high-risk CWE** (e.g. CWE-78 OS-command injection, CWE-89 SQLi, CWE-502 unsafe deserialization):

$$
E_{\text{path}}(n) = \begin{cases} \max(\mathbf{1}_{\text{sink}}(n), \tau_{\text{cwe}}) & \exists f \in F(n): \text{cwe}(f) \in \mathcal{C}_{\text{HR}} \\ 0 & \text{otherwise} \end{cases}
$$

where $\tau_{\text{cwe}}$ is a fixed evidence floor. Then:

$$
S_{sp}(n) = \rho_s\,\mathbf{1}_{\text{sink}} + \rho_o\,\mathbf{1}_{\text{source}} + \rho_g\,\mathbf{1}_{\text{guard}} + \rho_e\,E_{\text{path}}
$$

This term lets the ranker upgrade nodes that look like sinks/sources/guards even in the absence of analyzer findings, while still rewarding the corroboration when both signals coincide.

### 2.3 Context score $S_{c}$

The context score is itself a weighted sum of three sub-scores:

$$
S_{c}(n) = \omega_d\,D(n) + \omega_s\,U(n) + \omega_p\,P(n)
$$

**Depth term $D(n)$.** A monotonically non-increasing **hop-decay** function applied to the BFS distance from the root finding:

$$
D(n) = \delta(\text{depth}(n))
$$

where $\delta$ is a discrete decay table (1.0 at depth 0, decreasing with depth) plus a default for depths past the table. Intuitively: code nearest the alleged finding is most relevant; relevance attenuates with each hop.

**Structure term $U(n)$.** A combination of the node's *render kind* (function > class > code block > variable, reflecting the LLM-utility of each granularity) and a **repeat bonus** that rewards nodes reached multiple times during expansion (these are graph-theoretic *hubs* in the local neighborhood):

$$
U(n) = \mu_k\,K(\text{kind}(n)) + \mu_r\,\frac{r(n)}{\max_{n'} r(n')}
$$

The repeat bonus is normalized by the maximum repeat count in the current context window, so it is scale-invariant per query.

**File-prior term $P(n)$.** A **locality** prior over file paths:

$$
P(n) = \pi_f\,\mathbf{1}_{\text{same file}} + \pi_m\,M(n) - \pi_g\,\mathbf{1}_{\text{generated}}
$$

with $M(n) \in \{0, 0.5, 1\}$ scoring whether the node lives in the same module as an *anchor* (the file(s) of the shallowest, root-most nodes), and a penalty when the file looks generated (filename suffix, path marker, or "do not edit" header). $P(n)$ is then floored at 0.

### 2.4 Aggregation and de-duplication

Before scoring, `_aggregate_context_nodes` collapses repeated occurrences of the same `NodeID` into one entry, retaining the **shallowest** depth and **summing the repeat counts**. This step turns the multiset of BFS visits into a unique node set whose $r(n)$ encodes recurrence frequency — a cheap proxy for centrality in the local neighborhood subgraph.

## 3. Ranking Strategies

Several strategies share the score-component machinery above and differ in two places: how depth is measured (Sec. 4), and how components are combined into a sortable key.

### 3.1 Additive (`NodeRelevanceRankingService`)

Final score is the canonical linear combination of Sec. 2. Sort key:

$$
(\;\mathbf{1}[\text{depth}(n) \neq 0],\; -S_{\text{final}}(n),\; \text{depth}(n)\;)
$$

The lexicographic first key keeps **root nodes** (the actual finding location, depth 0) at the top of the prompt regardless of their score — they are the anchor of the question.

### 3.2 Multiplicative-boost (`MultiplicativeBoostNodeRankingStrategy`)

Replaces the additive combiner with a multiplicative one in which the context score is the *base* and security signals act as a *boost*:

$$
S_{\text{final}}(n) = S_c(n)\,\bigl(1 + \beta_{\text{sec}}\,(S_{fe}(n) + S_{sp}(n))\bigr)
$$

This couples context and security multiplicatively: a node with no contextual relevance ($S_c = 0$) cannot be lifted by security signals alone, while a contextually relevant node gets amplified when corroborated by analyzer or path evidence.

### 3.3 Depth-and-repeats (`DepthRepeatsContextNodeRankingStrategy`)

Discards security signals at sort time and orders by graph-structural priors only:

$$
\text{key}(n) = (\mathbf{1}[\text{depth}(n) \neq 0], \text{depth}(n), -r(n), -S_c(n))
$$

A useful baseline that isolates the value of the structural signal versus the security signal.

### 3.4 CPG-structural (`CPGStructuralRankingStrategy`)

Discussed in Sec. 4. Adds a security-tier bucket to the sort key:

$$
\text{key}(n) = \bigl(\mathbf{1}[\text{depth}(n) \neq 0],\; \mathbf{1}[S_{fe} + S_{sp} \le \theta_{\text{tier}}],\; -S_{\text{final}}(n),\; \text{depth}(n),\; \text{path},\; \text{line}\bigr)
$$

so that nodes whose combined direct security signal exceeds a threshold $\theta_{\text{tier}}$ form a privileged tier above the rest, and ties are broken deterministically by file path and line number.

### 3.5 Baselines

`RandomNodeRankingStrategy` and `DummyNodeRankingStrategy` exist purely to provide non-informative baselines for benchmarking the value added by the scoring scheme.

## 4. Edge-aware Depth (CPG-structural)

The Code Property Graph (CPG) connects code entities by **typed edges** — `FLOWS_TO`, `SANITIZED_BY`, `CALLS`, `CALLED_BY`, `DEFINED_BY`, `USED_BY`, `CONTAINS`. The default $D(n) = \delta(\text{depth}(n))$ is **edge-blind**: a 2-hop call is treated identically to a 2-hop dataflow. The CPG-structural strategy replaces this with a per-edge-type formulation. Given $\text{depth}_e(n)$ — the shortest distance from the root reachable via edges of type $e$ — and per-edge weight $w_e$ and decay $\lambda_e$:

$$
D(n) = \max_{e \in E(n)} w_e \cdot \lambda_e^{\text{depth}_e(n)}
$$

The $\max$ semantics says: a node is "as close as its strongest semantic link to the root makes it." A node 1-hop away on `FLOWS_TO` (high weight, slow decay) outranks one 1-hop away on `CONTAINS` (low weight, fast decay).

**Source-sink path bonus.** When the node set contains both a sink-like and a source-like node (lexically classified per Sec. 2.2), every node reachable via `FLOWS_TO` within a budget $D_{\max}$ receives an additive bonus to $S_{sp}$:

$$
S_{sp}(n) \leftarrow S_{sp}(n) + b_{\text{sink-bypass}} \cdot \bigl(1 - (1 - \eta_{\text{san}})\,\mathbf{1}[\text{SANITIZED\_BY}\le D_{\max}]\bigr)
$$

i.e. the bonus is **damped by $\eta_{\text{san}} \in [0,1]$** when a `SANITIZED_BY` edge is also reachable within $D_{\max}$, modeling the intuition that an unsanitized source→sink path is more dangerous than a guarded one.

## 5. From Score to Prompt

After `rank_nodes` produces an ordered list, the assembler executes a four-pass renderer (`context_assembler.py:94-160`):

1. Collect the set of file lines covered by all ranked nodes.
2. Read each file once and cache the line content (deduplicates I/O).
3. Iterate nodes **in rank order**, accumulating snippets while estimating tokens; the first node whose addition would exceed `token_budget` *and all nodes after it* are dropped.
4. Emit the kept lines in file/line order to produce the final prompt.

Two consequences of this pipeline are worth emphasizing:

- The ranker's job is not just to surface the single best node but to produce an **ordering** such that any prefix is a high-quality summary of the neighborhood — early termination is the rule, not the exception.
- Because step 4 emits lines in file order, the ranking does not directly control the *visual* order of the final text; it controls **inclusion** under the budget. The rank therefore behaves as a *priority* over which lines are kept.

## 6. Discrete Lookup Tables

While the combiner and breakdown weights are continuous in $[0,1]$ and tunable, several inputs to the formulas above are not free parameters but **strict, discrete mappings** from a categorical domain to a numeric score. These tables encode prior beliefs about the relative importance of categories and are applied verbatim before the linear combination.

**Hop-decay $\delta(\text{depth})$.** The depth term $D(n)$ in $S_c$ is not computed from a closed-form curve but from a fixed lookup table `HOP_DECAY_BY_DEPTH`:

$$
\delta : \mathbb{N} \to [0,1], \qquad
\delta(d) = \begin{cases}
v_d & d \in \{0, 1, 2, 3, 4\} \\
v_{\text{default}} & d > 4
\end{cases}
$$

with $v_0 > v_1 > \cdots > v_4 > v_{\text{default}}$ — strictly monotone. Values past the explicit table fall through to a single default. The same table is used as a fallback inside the CPG-structural strategy when `edge_depths` is empty.

**Severity tiers.** Both $\sigma$ (severity score) and $\kappa$ (confidence proxy) are total functions on a three-element domain:

$$
\sigma, \kappa : \{\text{LOW}, \text{MEDIUM}, \text{HIGH}\} \to [0,1]
$$

implemented as direct dictionary lookups (`SEVERITY_SCORES`, `CONFIDENCE_BY_SEVERITY`). Unknown finding types fall back to fixed sentinel constants (`UNKNOWN_FINDING_SEVERITY_SCORE`, `UNKNOWN_FINDING_CONFIDENCE_SCORE`).

**Dlint issue → severity.** Dlint findings expose a numeric `issue_id` rather than a severity tier; the ranker maps it to a tier via a fixed list of integer ranges (`DLINT_SEVERITY_BY_ISSUE_RANGE`):

$$
\text{tier}(id) = \begin{cases}
\text{HIGH}   & id \in [100, 106) \\
\text{MEDIUM} & id \in [106, 131) \\
\text{LOW}    & id \in [131, 138) \\
\text{MEDIUM} & \text{otherwise (default)}
\end{cases}
$$

The result is fed into $\sigma$ and $\kappa$ as above.

**Agreement score $A(n)$.** A three-valued function over the analyzer multiset:

$$
A(n) = \begin{cases}
a_{\text{both}}     & \text{Bandit and Dlint both flag } n \\
a_{\text{multiple}} & |F(n)| > 1 \text{ but only one analyzer} \\
0                   & \text{otherwise}
\end{cases}
$$

with $a_{\text{both}} > a_{\text{multiple}} > 0$ as fixed constants.

**Render kind $K(\text{kind})$.** A categorical map over node kinds (`RENDER_KIND_SCORES`):

$$
K : \{\text{FunctionNode}, \text{ClassNode}, \text{CodeBlockNode}, \text{VariableNode}, \dots\} \to [0,1]
$$

with $K(\text{Function}) > K(\text{Class}) > K(\text{CodeBlock}) > K(\text{Variable})$. Any kind not in the table falls back to `RENDER_KIND_DEFAULT_SCORE`.

**High-risk CWE set $\mathcal{C}_{\text{HR}}$.** The path-evidence term $E_{\text{path}}$ is gated on a fixed `frozenset` of CWE IDs (e.g. CWE-22 path traversal, CWE-78 OS-command injection, CWE-79 XSS, CWE-89 SQLi, CWE-94 code injection, CWE-502 unsafe deserialization, CWE-918 SSRF). Membership is a boolean test — there is no graded notion of "how risky" a CWE is.

**Same-module score $M$.** A three-valued function over file-path comparison:

$$
M(n, a) = \begin{cases}
1.0  & \text{node and anchor share parent directory} \\
0.5  & \text{they share at least one common path prefix} \\
0.0  & \text{no common prefix}
\end{cases}
$$

**Generated-file detection.** A boolean indicator built from three rules ORed together: filename suffix in `GENERATED_FILE_SUFFIXES` (e.g. `_pb2.py`), path component in `GENERATED_PATH_MARKERS` (e.g. `generated/`, `autogen/`), or a header-line marker in `GENERATED_HEADER_MARKERS` (e.g. `do not edit`).

These tables are intentionally **not** subject to the YAML-driven tuner — they encode domain knowledge whose ordering must be preserved (e.g. HIGH severity must always score above LOW; a function must always score above a variable). The tuner moves the *continuous* weights that combine these scores; the tables themselves are part of the methodology, not the operating point.

## 7. Tunable Coefficients

All weights ($w_*, \omega_*, \mu_*, \pi_*, \rho_*, \alpha, \beta, \gamma, \delta, \lambda_e, w_e, \theta_{\text{tier}}, \beta_{\text{sec}}, \eta_{\text{san}}, b_{\text{sink-bypass}}, D_{\max}$) are externalized as a `RankingCoefficients` Pydantic model loadable from YAML (`ranking_config.py`). This decouples the *methodology* in `ranking.py` from the *operating point*: coefficient tuning (e.g. via Optuna over an LLM-judge reward, see the `llm-scanner tune-ranking-coefficients` CLI command) explores the parameter space without changing code, and a strategy can be re-evaluated under different coefficient sets in benchmarks.

## 8. Summary

The ranking system is a hybrid **rule-based + heuristic** scoring scheme that fuses four complementary signals — direct analyzer evidence, lexical security-path heuristics, taint-flow output, and graph-structural context priors — into a single scalar in $[0, 1]$. Strategies differ along two axes: (i) whether depth is measured edge-blind or per CPG-edge-type, and (ii) whether security and context combine additively or multiplicatively. Root nodes are always pinned to the top, and the ordered list is consumed by a token-budget-aware renderer, so the practical effect of ranking is to decide *which evidence the LLM is allowed to see* when the budget is tight. The full methodology is parameterized by a single coefficient object, which makes it amenable to data-driven tuning against an external LLM-judge reward signal.
