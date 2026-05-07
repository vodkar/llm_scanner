# Evidence-Aware Budgeted Ranking System

## 1. Motivation and Pipeline Role

The ranking system orders **context nodes** retrieved around a candidate finding before they are rendered into the LLM prompt. The pipeline is bounded by a hard **token budget** $B \in \mathbb{N}_{>0}$: the renderer consumes the ordered node list greedily and drops any node whose addition would exceed $B$. Ranking quality therefore translates directly into which lines of code reach the model.

The earlier system (Sec. 2 of [`ranking_system.md`](./ranking_system.md)) is a **multi-signal linear** combiner of the form

$$
S_{\text{final}}(n) = w_{fe}\,S_{fe}(n) + w_{sp}\,S_{sp}(n) + w_{t}\,S_{t}(n) + w_{c}\,S_{c}(n)
$$

with $14+$ continuous coefficients. Empirically this scheme suffered from two failure modes:

1. **Unstable importance estimates.** Small coefficient changes in one shared helper (e.g. the structure score) propagated into strategies that did not even nominally use that signal — because helpers were shared across `NodeRelevanceRankingService`, `MultiplicativeBoostNodeRankingStrategy`, and `DepthRepeatsContextNodeRankingStrategy`.
2. **Over-saturation under aggregation.** Linear addition with bounded inputs produced a long tail of mid-relevance nodes; under tight budgets, structurally important context (root, source, sink) was displaced by mid-tail BoilerPlate.

The evidence-aware budgeted scheme described here addresses both. The methodology is **fixed**; only a compact operating-point configuration $\theta$ is tuned. Component scores are combined via the **noisy-OR** rule rather than weighted sums, and node selection is performed under an explicit **token-budget** constraint with a gain function that trades relevance against token cost.

## 2. Notation

| Symbol | Meaning |
|---|---|
| $\mathcal{N}$ | Set of context nodes retrieved by the assembler around a finding. |
| $n \in \mathcal{N}$ | A single context node; carries `depth`, `repeats`, `taint_score`, `finding_evidence_score`, optional per-edge depths $E(n)$, and a file path. |
| $\mathcal{C}$ | Set of ranking candidates produced from $\mathcal{N}$. In this scheme $|\mathcal{C}| \le |\mathcal{N}|$ (one candidate per unique node identifier). |
| $\mathcal{R}$ | Finite set of evidence roles (Sec. 4.1). |
| $\rho : \mathcal{R} \to [0,1]$ | Fixed role-prior table (Sec. 4.2). |
| $\theta$ | Tunable operating-point configuration (Sec. 9). |
| $B$ | Token budget supplied at strategy construction time. |
| $\tau(c) \in \mathbb{N}$ | Estimated token cost of candidate $c$. |
| $\ell(c) \subset \mathbb{N}$ | The line-range $[a, b]$ of $c$, treated as a set of integers. |
| $\sigma : \mathcal{C} \to [0,1]$ | Final relevance score (output of the evidence scorer, Sec. 7). |

We write $\operatorname{clamp}(x) = \min(1, \max(0, x))$ for projection onto the unit interval.

## 3. Architecture

The strategy is decomposed into seven stateless stages:

```
𝒩  ──► CandidateBuilder ──► SemanticAnnotator ──► GraphDistanceScorer
                                                       │
                                              ContextScorer    EvidenceScorer
                                                       │             │
                                                       └──► BudgetedSelector ──► NodeMapper ──► ordered list
```

Stages are intentionally pure: each consumes candidates with a partial state and returns candidates with one additional field populated. This decoupling enables per-stage testing and avoids the shared-helper coupling that destabilized the linear scheme.

## 4. Roles and Priors

### 4.1 Role taxonomy

Each candidate is assigned a (possibly empty) subset of roles $\mathcal{R}(c) \subseteq \mathcal{R}$ where

$$
\mathcal{R} = \{\text{ROOT}, \text{SINK}, \text{SOURCE}, \text{SANITIZER}, \text{GUARD}, \text{PROPAGATION}, \\
\text{DEFINITION}, \text{IMPORT}, \text{CALLEE}, \text{CALLER}, \text{ENTRYPOINT}, \\
\text{ENCLOSING\_CONTEXT}, \text{BOILERPLATE}\}.
$$

The taxonomy is closed and not subject to tuning. Roles encode *what kind of evidence the candidate provides*, not how strong the evidence is — strength is captured separately (Sec. 7).

### 4.2 Role priors

Roles are ordered by a fixed prior $\rho : \mathcal{R} \to [0,1]$:

$$
\begin{aligned}
\rho(\text{ROOT}) &= 1.00, & \rho(\text{SINK}) &= 0.95, & \rho(\text{SOURCE}) &= 0.90, \\
\rho(\text{SANITIZER}) &= 0.85, & \rho(\text{GUARD}) &= 0.85, & \rho(\text{PROPAGATION}) &= 0.75, \\
\rho(\text{DEFINITION}) &= 0.65, & \rho(\text{IMPORT}) &= 0.60, & \rho(\text{CALLEE}) &= 0.55, \\
\rho(\text{CALLER}) &= 0.55, & \rho(\text{ENTRYPOINT}) &= 0.55, & \rho(\text{ENCLOSING\_CONTEXT}) &= 0.50, \\
\rho(\text{BOILERPLATE}) &= 0.15. &&&&
\end{aligned}
$$

The strict ordering $\text{ROOT} > \text{SINK} > \text{SOURCE} > \text{SANITIZER} \ge \text{GUARD} > \text{PROPAGATION} > \text{DEFINITION} > \text{IMPORT} > \text{CALLER, CALLEE, ENTRYPOINT} > \text{ENCLOSING\_CONTEXT} > \text{BOILERPLATE}$ is part of the fixed methodology. Tuning may not alter individual values; it may only shape the prior globally via a temperature parameter $T$ (Sec. 7.2):

$$
\rho_{\text{eff}}(r; T) = \rho(r)^T,
$$

which preserves the ordering for all $T > 0$ but compresses the dynamic range when $T < 1$ (lifting low-prior roles toward 1) and expands it when $T > 1$ (suppressing them toward 0).

## 5. Candidate Construction

The candidate builder produces exactly one ranking candidate per unique node identifier. Multi-candidate splitting is rejected for a structural reason: the renderer keys de-duplication by `(file_path, identifier)`, so sub-candidates sharing one identifier collapse at render time, defeating the budget tracking.

### 5.1 Aggregation

For an input multiset $\mathcal{N}$, candidates are built over the deduplicated node set obtained by the same merge rule as the additive baseline:

$$
\text{merge}(n_1, n_2) \mapsto n' \text{ with } \begin{cases}
\text{depth}(n') = \min(\text{depth}(n_1), \text{depth}(n_2)) \\
\text{repeats}(n') = \text{repeats}(n_1) + \text{repeats}(n_2) + 1
\end{cases}
$$

This guarantees the new strategy sees the same node set as the legacy strategies — only the scoring differs.

### 5.2 Token estimation and window clipping

Token cost is estimated using the renderer's own formula

$$
\tau(c) = \max\!\left(1, \left\lfloor \frac{|T(c)|}{3} \right\rfloor\right)
$$

where $T(c)$ is the snippet text. Using the renderer's exact formula is essential: a divergence between the selector's projection and the renderer's accounting would let "selected" candidates overflow at render time.

When $\tau(c)$ exceeds an operating-point threshold $\tau^*$ (the *small-node* threshold), the candidate's line range is clipped to a window of radius $w$ centered on $a = \text{line\_start}(c)$:

$$
\ell(c) \leftarrow [\max(1, a - w),\, a + w].
$$

The window is intended as a budget-saving approximation: the rendered span is concentrated around the "hot line" rather than the entire enclosing function. The radius $w$ and threshold $\tau^*$ are part of the tunable configuration $\theta$.

## 6. Semantic Annotation

The annotator computes three quantities per candidate: the role set $\mathcal{R}(c)$, a CPG confidence $\kappa(c) \in [0,1]$, and a lexical-fallback flag $\phi(c) \in \{0, 1\}$.

### 6.1 Role assignment

Rules are deterministic and applied in order. Each rule contributes roles to a running set; multiple rules may fire on a single candidate.

| Trigger | Role contributed |
|---|---|
| File matches generated/vendor markers | $\{\text{BOILERPLATE}\}$ (terminal — overrides) |
| $\text{depth}(c) = 0$ | $\text{ROOT}$ |
| $E(c)$ contains `SANITIZED_BY` | $\text{SANITIZER}$ |
| $E(c)$ contains `FLOWS\_TO` or $\text{taint\_score}(c) > 0$ | $\text{PROPAGATION}$ |
| $E(c)$ contains `CALLS` | $\text{CALLER}$ |
| $E(c)$ contains `CALLED_BY` | $\text{CALLEE}$ |
| $E(c)$ contains `DEFINED_BY` | $\text{DEFINITION}$ |
| Snippet matches `SINK_HINTS` | $\text{SINK}$ |
| Snippet matches `SOURCE_HINTS` | $\text{SOURCE}$ |
| Snippet matches `GUARD_HINTS` | $\text{GUARD}$ |
| $\text{finding\_evidence\_score}(c) \ge 0.5$ and no other rule fired | $\text{SINK}$ |
| (no rule fired) | $\text{ENCLOSING\_CONTEXT}$ |

Generated-file detection is a hard override: such candidates carry only the BOILERPLATE role and bypass the rest of the pipeline's positive-evidence assignment, ensuring they cannot be lifted by lexical coincidence.

### 6.2 CPG confidence

Define $\mathcal{E} = \{\text{FLOWS\_TO}, \text{SANITIZED\_BY}, \text{CALLS}, \text{CALLED\_BY}, \text{DEFINED\_BY}, \text{USED\_BY}, \text{CONTAINS}\}$, the closed set of CPG edge types we observe. Then

$$
\kappa(c) = \frac{|\{e \in \mathcal{E} : e \in E(c)\}|}{|\mathcal{E}|} \in [0, 1].
$$

A candidate with no CPG evidence has $\kappa(c) = 0$; one reachable via every edge type has $\kappa(c) = 1$.

### 6.3 Lexical fallback flag

The flag $\phi(c) = 1$ if and only if the candidate has *no* analyzer or CPG evidence:

$$
\phi(c) = \begin{cases}
1 & \text{if } E(c) = \emptyset \,\wedge\, \text{taint\_score}(c) = 0 \,\wedge\, \text{finding\_evidence\_score}(c) < 0.5 \\
0 & \text{otherwise}.
\end{cases}
$$

Lexical-only evidence (matches against `SINK_HINTS` etc.) is a weaker signal than analyzer or CPG evidence: it can fire on benign code that merely *mentions* a dangerous identifier. The flag is consumed downstream as an upper bound on relevance (Sec. 7.4).

## 7. Evidence Composition

The evidence scorer composes per-signal evidence into a single relevance score $\sigma(c) \in [0, 1]$.

### 7.1 Per-signal evidence

Three "channels" are scaled by tunable factors $\alpha_{fe}, \alpha_{te}, \alpha_{re}$ from $\theta$, then clamped:

$$
\begin{aligned}
e_{fe}(c) &= \operatorname{clamp}\big(\alpha_{fe} \cdot \text{finding\_evidence\_score}(c)\big), \\
e_{te}(c) &= \operatorname{clamp}\big(\alpha_{te} \cdot \text{taint\_score}(c)\big), \\
e_{re}(c) &= \operatorname{clamp}\big(\alpha_{re} \cdot \rho_{\text{eff}}(c; T) \cdot D(c)\big),
\end{aligned}
$$

where the *role evidence* couples the role prior and the graph-distance score:

$$
\rho_{\text{eff}}(c; T) = \left(\max_{r \in \mathcal{R}(c)} \rho(r)\right)^T, \qquad
D(c) = \begin{cases}
\max_{e \in E(c)} \delta^{\, d_e(c)} & E(c) \ne \emptyset \\
\delta^{\, \text{depth}(c)} & \text{otherwise}.
\end{cases}
$$

Here $\delta = \theta_{\text{depth\_decay}} \in [0, 1]$ is the per-hop attenuation, $d_e(c)$ is the shortest distance from the root via edge type $e$, and the $\max$ semantics says *"the candidate is as close as its strongest semantic link to the root makes it"* — a 1-hop `FLOWS_TO` edge dominates a 1-hop `CONTAINS` edge.

### 7.2 Noisy-OR composition

Independent evidence channels are combined via the noisy-OR rule:

$$
\operatorname{nor}(\mathbf{x}) = 1 - \prod_{i} \big(1 - \operatorname{clamp}(x_i)\big).
$$

We compose security evidence first:

$$
e_{\text{sec}}(c) = \operatorname{nor}\!\big(e_{fe}(c),\; e_{te}(c),\; e_{re}(c),\; \kappa(c)\big),
$$

then fuse with the (down-weighted) context score:

$$
\sigma_0(c) = \operatorname{nor}\!\big(e_{\text{sec}}(c),\; \beta \cdot S_c(c)\big),
$$

where $\beta = \theta_{\text{context\_strength}} \in [0,1]$ controls how much non-security context can lift a candidate's relevance.

The noisy-OR is preferred over a weighted sum for three reasons:

1. **Saturation.** Two strong signals (e.g. analyzer-flagged AND on a tainted path) saturate near 1, where they belong, instead of the linear sum's monotonic drift past 1.
2. **Substitutability.** Evidence is treated as redundant probabilistic estimators of the same latent quantity ("is this code security-relevant?"). The noisy-OR is the maximum-entropy combiner under that assumption.
3. **Calibration.** All inputs and outputs lie in $[0, 1]$, so individual scaling factors $\alpha_*$ retain a probabilistic interpretation rather than being free linear gains.

### 7.3 Context score

The context score $S_c(c) \in [0, 1]$ is a *non-security* prior. It is computed as a copy (not a shared call) of the additive system's structure-and-locality formula:

$$
S_c(c) = \tfrac{1}{2}\bigl(K(c) + \mu_r \cdot R(c)\bigr) \;+\; \tfrac{1}{2}\, F(c),
$$

where $K(c)$ is the render-kind score (function > class > block > variable), $R(c) \in [0,1]$ is the repeat ratio normalized by the maximum repeat count in the input batch, and $F(c)$ is the file-locality score (same-file, same-module, with a hard-zero override for BOILERPLATE candidates).

### 7.4 Lexical-fallback cap

If $\phi(c) = 1$, we apply a hard cap

$$
\sigma(c) = \min\!\big(\sigma_0(c),\; \kappa^*\big), \qquad \kappa^* = \theta_{\text{lexical\_fallback\_cap}}.
$$

Otherwise $\sigma(c) = \sigma_0(c)$. The cap encodes *a priori* skepticism toward lexical-only signals: a candidate that "looks like a sink" syntactically but has no corroborating analyzer or CPG evidence cannot reach the relevance ceiling reserved for corroborated candidates.

## 8. Budgeted Selection

Given scored candidates and a token budget $B$, the selector returns a partition $(\mathcal{C}_S, \mathcal{C}_R)$ of the candidate set into *selected* and *rejected* subsets such that $\sum_{c \in \mathcal{C}_S} \tau(c) \le \gamma B$, where $\gamma = \theta_{\text{budget\_safety\_ratio}} \in (0, 1]$ provides a margin against the renderer's exact accounting.

### 8.1 Gain function

Selection is greedy by marginal **gain**. At each iteration the candidate $c^*$ that maximizes

$$
G(c \mid \mathcal{C}_S, \theta) = \frac{\sigma(c) \cdot \mu(c, \mathcal{C}_S) \cdot \nu(c, \mathcal{C}_S)}{\max\big(1,\; \tau(c)^{p}\big)}
$$

is added to $\mathcal{C}_S$, where:

- $\mu(c, \mathcal{C}_S) = 1 + \beta_r \cdot \big|\mathcal{R}(c) \setminus \bigcup_{c' \in \mathcal{C}_S} \mathcal{R}(c')\big|$ is the **role-coverage multiplier** with $\beta_r = \theta_{\text{role\_coverage\_bonus}}$. It rewards candidates that introduce previously-uncovered roles, encouraging diversity.
- $\nu(c, \mathcal{C}_S) = \max\!\big(0,\; 1 - \beta_n \cdot \operatorname{Jacc}(\ell(c), L_S)\big)$ is the **redundancy penalty** with $\beta_n = \theta_{\text{novelty\_penalty}}$ and $L_S = \bigcup_{c' \in \mathcal{C}_S} \ell(c')$. It penalizes candidates whose lines overlap already-selected lines.
- $p = \theta_{\text{token\_cost\_power}} \in [0, 2]$ is the **token-cost exponent**. Setting $p = 0$ ignores token cost (pure relevance ranking); $p = 1$ recovers density-style "value per token"; $p \in (0, 1)$ is a sub-linear discount that prefers small-but-relevant snippets over large rich ones, but not as aggressively as $p = 1$.

### 8.2 Algorithm

```
Algorithm 1: BudgetedGreedySelect(candidates, B, θ)
─────────────────────────────────────────────────────
  S ← []                            # selected
  used ← 0                          # accumulated tokens
  effective_budget ← max(1, ⌊γ · B⌋)
  remaining ← list(candidates)
  while remaining is non-empty:
      best ← argmin over c ∈ remaining of
                ( -G(c | S, θ),  -σ(c),  str(file_path(c)),  line_start(c) )
              subject to: used + τ(c) ≤ effective_budget
      if best is None: break
      append best to S; used ← used + τ(best); remove best from remaining
  return (S, remaining)
```

Tie-breaking is deterministic on $(-\sigma(c), \text{file\_path}(c), \text{line\_start}(c))$, which makes the output reproducible across runs even when multiple candidates have identical gain. This determinism is necessary to produce stable inputs for downstream LLM-judge evaluation.

### 8.3 Complexity

For $|\mathcal{C}| = m$ and final $|\mathcal{C}_S| = k$, the algorithm computes $G$ at most $\sum_{i=0}^{k-1}(m - i) = O(km)$ times. Each $G$ evaluation costs $O(|\mathcal{R}| + |L_S|)$ for the Jaccard computation; in practice $|\mathcal{R}| = 13$ is constant and $|L_S|$ grows with the budget. The overall complexity is $O(km \cdot \bar{|L_S|})$, dominated in the typical regime ($m \approx 100$, $k \approx 20$) by ranking-stage Pydantic work, not by the algorithm itself.

### 8.4 Optimality remarks

The greedy procedure is *not* optimal for the underlying knapsack-like problem (which is NP-hard in general). However:

1. The objective is **submodular** in $\mathcal{C}_S$ when both $\mu$ and $\nu$ are aggregated over $\bigcup \mathcal{R}(c')$ and $\bigcup \ell(c')$ respectively (additional candidates yield non-increasing marginal coverage and non-decreasing redundancy). For monotone submodular objectives under a knapsack constraint, the greedy heuristic yields a $(1 - 1/e)$-approximation when token costs are uniform; the bound degrades gracefully under heterogeneous costs.
2. The exponent $p$ provides empirical control over the cost-vs-relevance trade-off in the regime where the approximation bound does not bite. Tuning $p$ on a held-out set is cheaper than solving the integer program.

## 9. Operating-Point Configuration

The configuration $\theta$ is a 14-tuple $(\delta, \beta, T, \alpha_{fe}, \alpha_{te}, \alpha_{re}, \kappa^*, p, \beta_n, \beta_r, \tau^*, w, m^*, \gamma)$:

| Symbol | Field | Default | Range | Role |
|---|---|---|---|---|
| $\delta$ | `depth_decay` | $0.60$ | $[0.25, 1.20]$ | Per-hop graph-distance decay base. |
| $\beta$ | `context_strength` | $0.45$ | $[0.10, 0.75]$ | Weight of the non-security context channel in the noisy-OR. |
| $T$ | `role_prior_temperature` | $1.00$ | $[0.60, 1.80]$ | Compression of the role-prior dynamic range. |
| $\alpha_{fe}$ | `finding_evidence_scale` | $1.00$ | $[0.60, 1.50]$ | Pre-clamp scaling on analyzer findings. |
| $\alpha_{te}$ | `taint_evidence_scale` | $1.00$ | $[0.60, 1.50]$ | Pre-clamp scaling on taint signal. |
| $\alpha_{re}$ | `cpg_role_evidence_scale` | $1.00$ | $[0.60, 1.50]$ | Pre-clamp scaling on the role $\times$ distance product. |
| $\kappa^*$ | `lexical_fallback_cap` | $0.40$ | $[0.20, 0.60]$ | Upper bound on $\sigma(c)$ for lexical-only candidates. |
| $p$ | `token_cost_power` | $0.35$ | $[0.00, 0.80]$ | Sub-linear penalty on candidate token cost. |
| $\beta_n$ | `novelty_penalty` | $0.40$ | $[0.00, 0.70]$ | Strength of the redundancy discount. |
| $\beta_r$ | `role_coverage_bonus` | $0.20$ | $[0.05, 0.40]$ | Per-new-role multiplier increment. |
| $\tau^*$ | `small_node_token_threshold` | $220$ | $[120, 420]$ | Above this token cost, the candidate is window-clipped. |
| $w$ | `local_window_radius` | $3$ | $[1, 6]$ | Window radius (in lines) when clipping. |
| $m^*$ | `max_candidates_per_node` | $8$ | $[4, 12]$ | Reserved for future multi-candidate splitting. |
| $\gamma$ | `budget_safety_ratio` | $0.95$ | $[0.85, 1.00]$ | Margin between selector and renderer accounting. |

The deliberate compactness of $\theta$ — fourteen scalars with bounded ranges — is what makes Bayesian optimization (e.g. Optuna's TPE) tractable. The legacy linear scheme exposed $14+$ coefficients **per breakdown**, leading to an unstable search space.

## 10. Output Ordering

The strategy must produce a list of `CodeContextNode` objects (the existing renderer's contract). The ordering protocol is:

1. **Pinned root.** Every candidate $c$ with $\text{ROOT} \in \mathcal{R}(c)$ appears first, in selection order.
2. **Selected non-root.** Remaining selected candidates follow, in selection order.
3. **Rejected tail.** Rejected candidates appear last, in their original input order.

The renderer walks this list and `break`s on first overflow. Rule (1) guarantees the finding location is always rendered (an information-theoretic prerequisite: the LLM must know what it is reasoning about). Rule (3) ensures rejected candidates are dropped deterministically. Duplicates by node identifier are collapsed: the first appearance wins.

## 11. Theoretical Properties

### 11.1 Boundedness

By construction, every output of `noisy_or` and every clamped pre-input lies in $[0, 1]$, so $\sigma(c) \in [0, 1]$ for all $c$. The cap step (Sec. 7.4) preserves this bound.

### 11.2 Monotonicity in evidence

$\sigma(c)$ is monotone non-decreasing in each per-signal evidence value $e_*$. This follows directly from $\frac{\partial}{\partial x_i}\operatorname{nor}(\mathbf{x}) = \prod_{j \ne i}(1 - x_j) \ge 0$.

### 11.3 Determinism

For fixed inputs $(\mathcal{N}, B, \theta)$, the strategy is a pure function: it allocates no random state and the tie-breaker $(-\sigma, \text{str}(\text{file\_path}), \text{line\_start})$ is total. Reproducibility under repeated invocation is therefore guaranteed.

### 11.4 Independence from existing strategies

The strategy reuses no scoring helper from `NodeRelevanceRankingService`, `CPGStructuralRankingStrategy`, or any other ranker. It imports only stateless caches (the snippet reader) and pure constants (lexical hint sets, generated-file markers). Modifications to $\theta$ cannot — by construction — alter the behavior of legacy strategies.

## 12. Comparison to the Additive Scheme

| Aspect | Additive (legacy) | Evidence-aware budgeted |
|---|---|---|
| Combiner | weighted sum | noisy-OR |
| Number of tunables | 14+ per breakdown | 14 total |
| Saturation | linear; can drift past 1 | bounded in $[0, 1]$ by construction |
| Token-budget awareness | post-hoc (renderer drops overflow) | explicit; selector respects $\gamma B$ |
| Diversity | structural-only repeat bonus | role-coverage multiplier |
| Redundancy handling | implicit (de-duplication step only) | explicit Jaccard penalty |
| Helper sharing across strategies | yes (cause of Phase 1 regression) | none |
| Algorithmic complexity | $O(m)$ scoring + $O(m \log m)$ sort | $O(km)$ greedy with submodular gain |
| Search-space tractability | unstable | TPE-tractable |

The two systems can be evaluated against the same LLM-judge benchmark; the budgeted scheme is intended as a successor, not a replacement to be applied silently. Continuous benchmarking on the held-out test split is the basis for the decision to switch.

## 13. Summary

The evidence-aware budgeted ranking system reframes context-node selection as a **bounded probabilistic-evidence problem** with an explicit token budget. Per-signal evidence values are scaled, role-modulated, and combined via noisy-OR; the resulting relevance feeds a greedy selector with role-coverage and redundancy shaping. Methodology is fixed (role taxonomy, role priors, role-assignment rules); only a compact 14-scalar operating point is tuned, preserving search-space tractability while permitting data-driven calibration on an LLM-judge reward signal.
