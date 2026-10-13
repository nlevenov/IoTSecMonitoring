"""MAC vendor (OUI) lookup."""

from __future__ import annotations

import csv
from importlib import resources
from pathlib import Path

from ..sanitize import clean_text, is_randomized_mac


class OuiDatabase:
    def __init__(self) -> None:
        self.vendors: dict[str, str] = {}
        self.hints: dict[str, str] = {}

    @classmethod
    def load(cls, extra_file: str | Path | None = None) -> OuiDatabase:
        db = cls()
        bundled = resources.files("iotsec").joinpath("data/oui_iot.csv")
        db._load_curated(bundled.read_text(encoding="utf-8").splitlines())
        if extra_file and Path(extra_file).exists():
            db.load_ieee(extra_file)
        return db

    def _load_curated(self, lines: list[str]) -> None:
        rows = csv.DictReader(line for line in lines if not line.startswith("#"))
        for row in rows:
            prefix = row["prefix"].replace(":", "").lower()
            self.vendors[prefix] = row["vendor"]
            if row.get("hint"):
                self.hints[prefix] = row["hint"]

    def load_ieee(self, path: str | Path) -> int:
        """Load the IEEE MA-L registry CSV (Registry,Assignment,Organization Name,...)."""
        added = 0
        with Path(path).open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                assignment = (row.get("Assignment") or "").strip().lower()
                name = clean_text(row.get("Organization Name"), 64)
                if len(assignment) == 6 and name:
                    # the curated names are shorter and nicer - keep them
                    self.vendors.setdefault(assignment, name)
                    added += 1
        return added

    def vendor(self, mac: str) -> str | None:
        if is_randomized_mac(mac):
            return "Private (randomized) address"
        return self.vendors.get(mac.replace(":", "")[:6])

    def hint(self, mac: str) -> str | None:
        return self.hints.get(mac.replace(":", "")[:6])
