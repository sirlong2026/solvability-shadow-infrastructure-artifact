# Formalization — Soundness and Falsifiability Completeness

This note expands the proof sketches of Section 3.4 of the manuscript. The paper
is self-contained; this file records the derivation in one place and names the
finite checks that discharge its premises.

## 1. Objects

- Observable dimensions $O = \{o_1,\dots,o_6\}$: TTL diversity, clock-skew
  clusters, temporal certificate rotation, SNI distribution, TTL/path divergence,
  and the cross-view certificate union.
- Backend hypotheses $C = \{c_1,\dots,c_5,c_8\}$: single host, round-robin pool,
  sticky pool, multi-homed egress, SNI-shared front end, perfectly camouflaged
  cluster. $c_6,c_7$ are auxiliary infrastructure hypotheses and never falsify a
  backend hypothesis (orthogonal auxiliary axis).
- Instance matrix $M$ with $H(c,o) \in \{+,-,\circ\}$: the polarity hypothesis
  $c$ predicts for dimension $o$ when $c$ holds, no prediction, or structurally
  not applicable. The published $6\times8$ matrix appears as Table II of the paper.
- A two-sensor comparison yields $\obs \in
  \{\textsf{positive},\textsf{negative},\textsf{unobservable}\}^6$.
- $\kappa$ is the fraction of evaluated (non-unobservable) dimensions.

## 2. Standing premises

**P1 (gate closure).** Every reading consumed by $V$ satisfies its observability
premise; $\kappa$ is computed over that same evaluated set. A dimension whose
premise is unmet is recorded as `unobservable`, never as `negative`.

**P2 (matrix correctness).** $M$ agrees with physical causality: whenever $c$
holds, each evaluated dimension reads as $H(c,o)$ predicts.

## 3. Verdict function

$V$ applies four steps in order: (1) if $\kappa < 1/3$ return *unobservable* with
the failed-dimension set; (2) eliminate every hypothesis contradicted by an
evaluated reading; (3) collapse behaviorally indistinguishable survivors into an
equivalence class and return *decidable* or *conditionally decidable* with the
winning class; (4) otherwise return *indistinguishable* with the tied set, or
*unobservable* with the failed readings. Steps 1–4 are the only output channels.

## 4. Property 1 — soundness

Claim: a *decidable* or *conditionally decidable* output cannot name a false
winner. Two output forms exhaust step 3.

**(a) Single surviving $c^\star$ leading by $\geq 2$.** Suppose $c^\star$ is not
true and let $c$ be the true hypothesis. $M$ is separating by construction: for
each distinct pair $(c,c^\star)$ some dimension $o$ carries incompatible
predictions. This is a finite check on the published $6\times8$ matrix, and is
reproduced by `scripts/evaluate.py` against the `EXPECT` table. On that $o$, P1
guarantees the reading exists and was evaluated; P2 guarantees it matches
$H(c,o)$, which is incompatible with $H(c^\star,o)$; step 2 therefore eliminates
$c^\star$ — contradiction. *Conditionally decidable* inherits the argument with
the lead-of-1 clause recorded in the audit trail.

**(b) Survivors $\subseteq \{c_1,c_8\}$.** This branch is reached under all-negative
readings. A single host and a perfectly camouflaged cluster are action-equivalent
on every evaluated dimension: no reading in $O$ distinguishes them, which is the
definition of the equivalence class. The collapsed output "at most one back end"
licenses exactly the action set common to both members, so it holds in either
world. It is not an assertion that $c_1$ is the physical truth.

## 5. Property 2 — falsifiability completeness

Claim: if no hypothesis is supported by all evaluated evidence, $V$ cannot emit
*decidable* or *conditionally decidable*. The premise splits exhaustively:

- **(i) Some reading fails its premise.** That dimension is unobservable under P1.
  The unevaluated fraction either drives $\kappa < 1/3$, so step 1 returns
  *unobservable*, or leaves the surviving set empty on those dimensions, so
  step 4 returns its named failure set. The unevaluated dimensions are named by
  construction.
- **(ii) All readings are evaluated, but each hypothesis fails on at least one.**
  The surviving set is empty or a tie with diverging actions; step 4 returns
  *indistinguishable* naming the tied set, or *unobservable* naming the failed
  readings.

Both step-3 forms require one hypothesis supported on all evaluated dimensions,
the negation of the premise; hence neither can fire. The split is exhaustive
because the four steps admit no other output channel. The grader hard-checks that
every emitted output carries its failure set and that an empty or out-of-bounds
result fails grading (`scripts/evaluate.py`, ten `EXPECT` fields).

## 6. Finite checks shipped with this artifact

| Claim | Check |
|---|---|
| Matrix separation for every distinct hypothesis pair | `engine/sensor_compare.py`, `tests/test_sensor_semantics.py` (29 cases) |
| Camouflage anchor $c_1 \equiv c_8$ action equivalence | `tests/test_sensor_semantics.py`, honest-degradation anchors |
| Gate closure and $\kappa$ exact-fraction comparison | `engine/sensor_agent.py` (`evaluate_gate`), `scripts/kappa_sweep.py` |
| Ten pre-registered grading fields | `scripts/evaluate.py` (`EXPECT`) |
| All headline numbers | `python scripts/verify_numbers.py` |

The $\kappa$ gate compares exact fractions, not rounded decimals: $2/6 = 1/3$
must not be refused by a 3-decimal rounding to $0.333$. This defect was found by
the public Atlas campaign 231739937 and fixed; 29/29 semantics tests pass and
every archived batch re-judges identically.
