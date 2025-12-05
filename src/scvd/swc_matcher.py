"""
SWCMatcher
----------
Rule-based scorer that maps audit findings to SWC IDs.

Scoring is additive: higher is better.

For each SWC item:
    score = sum_over_fields(
                field_boost[field] * (
                    + keyword_weight       * 1  for each keyword phrase present
                    + signal_weight        * 1  for each solidity_signals phrase present
                    + regex_weight         * 1  for each positive regex that matches
                    + type_prior (once; from 'Type' metadata matching aliases/fuzzy)
                    - anti_keyword_weight  * 1  for each anti_keywords phrase present
                    - regex_negative_weight* 1  for each negative regex that matches
                )
           )

Defaults (overridable via swc.json → matching_defaults):
    regex_flags: "im"
    field_boosts: title=1.5, description=1.0, poc=1.0, impact=0.8, other=0.5
    weights: keyword=1.0, signal=1.5, regex=2.0, anti_keyword=-1.0, regex_negative=-2.0

Caller keeps the top-N SWC whose scores are within Δ of the best (see normalize_report.py).
"""



import json, re, pathlib
from typing import Dict, List, Tuple, Any, Iterable, Optional

class SWCMatcher:
    def __init__(self, swc_json_path: str | pathlib.Path):
        db = json.loads(pathlib.Path(swc_json_path).read_text(encoding="utf-8"))
        self.defaults = db.get("matching_defaults", {})
        self.items = db["items"]

        # compile flags from defaults
        flags = 0
        for ch in (self.defaults.get("regex_flags") or "").lower():
            flags |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(ch, 0)
        self._flags = flags

        # compile regexes once (fault-tolerant)
        def _compile_many(patterns: Iterable[str] | None, flags: int) -> List[re.Pattern]:
            out = []
            for p in (patterns or []):
                if not p:
                    continue
                try:
                    out.append(re.compile(p, flags))
                except re.error:
                    # you can log the bad pattern here if you like
                    continue
            return out

        for it in self.items:
            it["_regex"]     = _compile_many(it.get("regex"), self._flags)
            it["_regex_neg"] = _compile_many(it.get("regex_negative"), self._flags)

        # alias index for Type→prior
        self._alias_index: Dict[str, List[int]] = {}
        for idx, it in enumerate(self.items):
            for a in (it.get("aliases") or []):
                self._alias_index.setdefault(a.lower(), []).append(idx)

        w = self.defaults.get("weights", {})
        self.w_keyword   = float(w.get("keyword", 1.0))
        self.w_signal    = float(w.get("signal", 1.5))
        self.w_regex     = float(w.get("regex", 2.0))
        self.w_anti      = float(w.get("anti_keyword", -1.0))
        self.w_regex_neg = float(w.get("regex_negative", -2.0))

        self.field_boosts = {**{"title":1.5,"description":1.0,"poc":1.0,"impact":0.8,"other":0.5},
                             **(self.defaults.get("field_boosts") or {})}

    # --- public API ----------------------------------------------------------

    def score(
        self,
        title: str,
        description: str,
        impact: str,
        poc: str,
        other: str,
        type_label: str | None = None,
        shortlist: Optional[Iterable[str]] = None,
    ) -> List[Tuple[str, float, List[str], List[str]]]:
        """
        Compute scores for all SWC items. Higher is better.

        Inputs are raw text per section; 'type_label' is the auditor provided "Type"
        which seeds a strong prior using SWC aliases (exact match) and a weaker fuzzy prior.

        Returns:
            List of tuples sorted by score desc:
                [(swc_id: str, score: float, reasons: List[str], cwes: List[str])]

        'reasons' enumerates which signals fired, e.g.:
            ["type_prior:+3.5", "kw[title]:reentrancy", "re[description]"]

        Caller is expected to keep the top K within a delta of the best score.
        
        If `shortlist` is provided, only those SWC IDs are considered.
        """
        text_by_field = {
            "title": (title or ""),
            "description": (description or ""),
            "impact": (impact or ""),
            "poc": (poc or ""),
            "other": (other or ""),
        }
        low_by_field = {k: v.lower() for k, v in text_by_field.items()}

        # seed priors from Type
        type_prior = self._type_prior(type_label)

        allow: Optional[set] = set(map(str, shortlist)) if shortlist else None

        results = []
        for it in self.items:
            swc_id = it["id"]
            if allow is not None and swc_id not in allow:
                continue

            s = 0.0
            reasons: List[str] = []

            prior = type_prior.get(swc_id, 0.0)
            if prior:
                s += prior
                reasons.append(f"type_prior:+{prior:g}")

            kws  = it.get("keywords") or []
            anti = it.get("anti_keywords") or []
            sigs = it.get("solidity_signals") or []

            for field in ("title", "description", "impact", "poc", "other"):
                B   = float(self.field_boosts.get(field, 1.0))
                txt = text_by_field[field]
                low = low_by_field[field]

                # keywords / anti
                for k in kws:
                    if k and k.lower() in low:
                        s += self.w_keyword * B; reasons.append(f"kw[{field}]:{k}")
                for a in anti:
                    if a and a.lower() in low:
                        s += self.w_anti * B; reasons.append(f"anti[{field}]:{a}")

                # solidity signals
                for sig in sigs:
                    if sig and sig.lower() in low:
                        s += self.w_signal * B; reasons.append(f"sig[{field}]:{sig}")

                # regex pos/neg
                for rgx in it["_regex"]:
                    if rgx.search(txt):
                        s += self.w_regex * B; reasons.append(f"re[{field}]")
                for rgx in it["_regex_neg"]:
                    if rgx.search(txt):
                        s += self.w_regex_neg * B; reasons.append(f"re-NEG[{field}]")

            # dedupe reasons (optional)
            if reasons:
                seen = set(); reasons = [r for r in reasons if not (r in seen or seen.add(r))]

            cwes = [cwe["id"] for cwe in (it.get("relationships", {}).get("cwe") or [])]
            results.append((swc_id, s, reasons, cwes))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def topk_within_delta(self, scored, k: int = 2, delta: float = 1.0):
        if not scored:
            return []
        top = scored[0][1]
        out = []
        for swc_id, score, reasons, cwes in scored[:k]:
            if score >= top - delta and score > 0:
                out.append((swc_id, score, reasons, cwes))
        return out

    # --- internals -----------------------------------------------------------

    def _type_prior(self, type_label: str | None) -> Dict[str, float]:
        """Map 'Type: ...' to SWC priors. Exact alias hit is strong; fuzzy is weaker."""
        priors: Dict[str, float] = {}
        if not type_label:
            return priors
        t = type_label.strip().lower()

        # exact alias hit(s)
        for idx in self._alias_index.get(t, []):
            swc_id = self.items[idx]["id"]
            priors[swc_id] = priors.get(swc_id, 0.0) + 3.5

        # simple fuzzy: token overlap with aliases (cheap & deterministic)
        t_set = set(w for w in re.split(r"[^a-z0-9]+", t) if w)
        if not t_set:
            return priors
        for it in self.items:
            best = 0.0
            for a in (it.get("aliases") or []):
                a_set = set(w for w in re.split(r"[^a-z0-9]+", a.lower()) if w)
                if not a_set:
                    continue
                j = len(t_set & a_set) / max(1, len(t_set | a_set))
                best = max(best, j)
            if best >= 0.5:
                swc_id = it["id"]
                priors[swc_id] = max(priors.get(swc_id, 0.0), 2.0 * best)
        return priors
