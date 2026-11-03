"""FMC snapshot (fwsync fmc-read, JSON) -> Config: the snapshot is rendered as the LINA CLI the FTD compiles from FMC
and read by the LINA adapter, so rule names, rule-ids, inline groups and NAT order behave as for a LINA backup."""
import json

from .base import Adapter
from .lina import LinaAdapter


class FmcJsonAdapter(Adapter):
    vendor = 'fmc'

    @staticmethod
    def detect(text):
        head = text[:4000].lstrip()
        return head.startswith('{') and '"fwsync_fmc_snapshot"' in head

    def parse(self, text, name):
        from ..fmc import render
        snap = json.loads(text)
        lina, warns = render(snap)
        cfg = LinaAdapter().parse(lina, name)
        cfg.vendor = self.vendor
        cfg.warnings = ['FMC: %s' % w for w in warns] + cfg.warnings
        cfg.source_text = lina
        return cfg
