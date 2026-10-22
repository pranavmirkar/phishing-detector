"""
Learned scoring layer: a small gradient-boosted-tree model that combines the detector's signals.

The rule engine (detector.py) still finds and explains every signal. This module only decides
how much each *combination* of signals is worth, which hand-set weights do poorly: it is what moves
recall at a strict false-alarm budget (see README, "Accuracy").

  * Inputs are the per-signal points the rules produced plus a few era-neutral lexical features
    (how random the sender domain / mailbox name looks, subject shape, number of link domains).
    Features that merely identify an era or are trivially spoofable (display name present,
    List-Id, attachment presence, HTML) are deliberately NOT used.
  * The trees are exported to JSON (benchmark/train_model.py) and evaluated here in pure Python:
    no scikit-learn or numpy at runtime.
  * Support-aware floor: for a signal type with fewer than `min_support` phishing examples in the
    training data (or none), the model has no evidence either way, so it abstains: the rule engine's
    points for those signals are kept as a floor under the model's score. This is what keeps
    attack styles that credential-phishing corpora barely contain (advance-fee scams, delivery-fee
    lures, text-only fraud, punycode, return-path forgery) from being scored as harmless.
  * The raw score is mapped to the familiar 0-100 scale so that LOW < 25 <= MEDIUM < 55 <= HIGH:
    25 is the raw score at which ~1% of legitimate validation mail would be flagged, 55 ~0.1%.

Set PG_MODEL=off to use the rule score alone, or PG_MODEL=/path/to/model.json for another model.
"""
import json
import math
import os
import re

DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_v1.json")
_state = {"loaded": False, "model": None}

LEXICAL_FEATURES = [
    "dom_len", "dom_digit", "dom_hyph", "dom_ent", "cctld",
    "loc_len", "loc_digit", "loc_ent",
    "subj_len", "subj_caps", "subj_re",
    "n_link_dom", "n_urls",
    "n_untrusted_dom", "untrusted_ratio", "http_ratio", "url_maxlen", "url_depth", "url_email",
]
EXTRA_FEATURES = ["spam", "trusted", "free"]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(v / len(s) * math.log2(v / len(s)) for v in counts.values())


def featurize(signal_points: dict, spam_score: float, trusted: bool, freemail: bool,
              local_part: str, registered: str, subject: str, n_urls: int, n_link_domains: int, link_stats: dict = None) -> dict:
    """Name -> value for everything the model may read. Used identically when training and serving."""
    label = registered.split(".")[0]
    letters = [c for c in subject if c.isalpha()]
    f = {f"sig:{t}": p / 50.0 for t, p in signal_points.items()}
    f.update({
        "spam": spam_score / 100.0, "trusted": float(trusted), "free": float(freemail),
        "dom_len": float(len(label)), "dom_digit": sum(c.isdigit() for c in label) / max(len(label), 1),
        "dom_hyph": float(label.count("-")), "dom_ent": _entropy(label),
        "cctld": float(len(registered.rsplit(".", 1)[-1]) == 2),
        "loc_len": float(len(local_part)), "loc_digit": sum(c.isdigit() for c in local_part) / max(len(local_part), 1),
        "loc_ent": _entropy(local_part),
        "subj_len": float(len(subject)), "subj_caps": sum(c.isupper() for c in letters) / max(len(letters), 1),
        "subj_re": float(subject.lower().startswith(("re:", "fw:", "fwd:"))),
        "n_link_dom": float(n_link_domains), "n_urls": float(min(n_urls, 30)),
    })
    ls = link_stats or {}
    f.update({k: float(ls.get(k, 0.0)) for k in ("n_untrusted_dom", "untrusted_ratio", "http_ratio", "url_maxlen", "url_depth", "url_email")})
    return f


class Model:
    def __init__(self, d: dict):
        self.version = d.get("version", "?")
        self.features = d["features"]                   # ordered feature names
        self.baseline = float(d["baseline"])
        self.trees = d["trees"]                          # each: {"f": [...], "t": [...], "l": [...], "r": [...], "v": [...]}
        self.anchors = d["anchors"]                      # raw score -> 0..100 (monotone, piecewise linear)
        self.meta = d.get("meta", {})
        self.support = d.get("support", {})              # signal type -> number of phishing training emails showing it
        self.min_support = int(d.get("min_support", 20))
        self.floor_always = set(d.get("floor_always", []))   # impersonation signals whose rule points are always a floor
        self._index = {n: i for i, n in enumerate(self.features)}

    def vector(self, feats: dict) -> list:
        x = [0.0] * len(self.features)
        for name, v in feats.items():
            i = self._index.get(name)
            if i is not None:
                x[i] = v
        return x

    def raw(self, feats: dict) -> float:
        x = self.vector(feats)
        total = self.baseline
        for t in self.trees:
            n = 0
            while t["f"][n] >= 0:
                n = t["l"][n] if x[t["f"][n]] <= t["t"][n] else t["r"][n]
            total += t["v"][n]
        return total

    def unsupported_points(self, signal_points: dict) -> int:
        """Rule points for signals the training data cannot judge (kept as a floor under the model's score)."""
        return sum(p for t, p in signal_points.items()
                   if self.support.get(t, 0) < self.min_support or t in self.floor_always)

    def risk(self, raw: float) -> int:
        xs, ys = self.anchors["raw"], self.anchors["risk"]
        if raw <= xs[0]:
            return int(ys[0])
        for i in range(1, len(xs)):
            if raw <= xs[i]:
                f = (raw - xs[i - 1]) / (xs[i] - xs[i - 1]) if xs[i] > xs[i - 1] else 1.0
                return int(round(ys[i - 1] + f * (ys[i] - ys[i - 1])))
        return int(ys[-1])


def load(path: str):
    with open(path, encoding="utf-8") as f:
        return Model(json.load(f))


def get_model():
    """The configured model, or None (rules only). Loaded once; a broken file disables the model, never the API."""
    if _state["loaded"]:
        return _state["model"]
    _state["loaded"] = True
    setting = os.environ.get("PG_MODEL")
    if setting is not None and setting.strip().lower() in ("off", "0", "none", "false"):
        return None
    path = setting or DEFAULT_PATH
    try:
        _state["model"] = load(path)
    except (OSError, ValueError, KeyError):
        _state["model"] = None
    return _state["model"]


def reset():
    """Forget the cached model (tests / hot reload)."""
    _state.update(loaded=False, model=None)
