"""Adapters turn a vendor config into fwsync.model.Config.
Add a vendor: subclass Adapter, set `vendor`, implement detect() and parse(), add it to ADAPTERS."""
from .base import Adapter
from .fmc_json import FmcJsonAdapter
from .lina import LinaAdapter

ADAPTERS = [FmcJsonAdapter, LinaAdapter]


def load(text, name='config', vendor=None):
    for a in ADAPTERS:
        if (vendor and a.vendor == vendor) or (not vendor and a.detect(text)):
            return a().parse(text, name)
    raise ValueError('no adapter recognises %s (available: %s)' % (name, ', '.join(a.vendor for a in ADAPTERS)))
