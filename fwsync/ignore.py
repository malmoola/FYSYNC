"""Interface map value "ignore": drop everything on that A interface. Rules naming the interface and NATs on it are
removed; rules without an interface lose the addresses routed out of it."""
from .netset import IPSet

IGNORE = 'ignore'


def ignored_names(prof):
    return {k for k, v in (prof.interface_map or {}).items() if str(v).lower() == IGNORE}


def apply(cfg, names):
    """names: nameifs of cfg to ignore (unknown names are skipped). Returns the addresses routed out of them."""
    from .detect import route_split
    names = {n for n in names if n in cfg.interfaces}
    if not names:
        return IPSet()
    cfg.ignored |= names
    X = IPSet()
    for ifc, s in route_split(cfg, IPSet.any()):
        if ifc in names:
            X = X | s
    keep = []
    for r in cfg.rules:
        if r.src_ifc in names or r.dst_ifc in names:
            continue
        default = r.src.is_any() and r.dst.is_any() and r.src_ifc is None and r.dst_ifc is None
        if not default and X:
            if r.dst.is_any():
                r.wide = True
            r.src, r.dst = r.src - X, r.dst - X
            if not r.src or not r.dst:
                continue
        keep.append(r)
    dropped = len(cfg.rules) - len(keep)
    cfg.rules = keep
    nats = [n for n in cfg.nats if n.real_ifc not in names and n.mapped_ifc not in names]
    cfg.warnings.append('ignored interfaces %s: %d rule lines and %d NATs dropped' % (
        ', '.join(sorted(names)), dropped, len(cfg.nats) - len(nats)))
    cfg.nats = nats
    cfg._ignored_set = (getattr(cfg, '_ignored_set', None) or IPSet()) | X
    return X
