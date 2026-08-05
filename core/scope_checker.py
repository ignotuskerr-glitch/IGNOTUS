"""
ingotus/core/scope_checker.py

Bug Bounty Scope Evaluator.
Filters discovered hosts against in-scope wildcards/domains and out-of-scope lists.
"""

import fnmatch
from typing import List, Tuple


class ScopeChecker:
    def __init__(self, in_scope_rules: List[str] = None, out_scope_rules: List[str] = None):
        self.in_scope = [r.strip().lower() for r in (in_scope_rules or []) if r.strip()]
        self.out_scope = [r.strip().lower() for r in (out_scope_rules or []) if r.strip()]

    def is_in_scope(self, host: str) -> bool:
        clean_host = host.lower().strip()

        # Check out-of-scope rules first (blacklist takes priority)
        for rule in self.out_scope:
            if self._match_rule(clean_host, rule):
                return False

        # Fail closed: active tooling must never treat a missing/empty scope
        # as permission to scan arbitrary hosts.
        if not self.in_scope:
            return False

        # Check in-scope rules
        for rule in self.in_scope:
            if self._match_rule(clean_host, rule):
                return True

        return False

    def _match_rule(self, host: str, rule: str) -> bool:
        if rule.startswith("*."):
            domain = rule[2:]
            return host == domain or host.endswith("." + domain)
        return fnmatch.fnmatch(host, rule)


def load_scope_file(filepath: str) -> Tuple[List[str], List[str]]:
    """
    Loads scope rules from a file containing:
    in-scope: *.target.com
    out-of-scope: dev.target.com
    """
    in_scope = []
    out_scope = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                lowered = line.lower()
                if line.startswith("!"):
                    out_scope.append(line[1:].strip())
                elif lowered.startswith("out:"):
                    out_scope.append(line[4:].strip())
                elif lowered.startswith("in:"):
                    in_scope.append(line[3:].strip())
                else:
                    in_scope.append(line)
    except (OSError, UnicodeError):
        return [], []

    return in_scope, out_scope
