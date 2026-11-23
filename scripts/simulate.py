"""Génère 12 semaines d'exports DSPM fictifs (3 sources) + journal d'actions analystes.

Usage : python -m scripts.simulate [--seed 42] [--out data/raw]
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from datarisk.config import RAW_DIR, load_config
from datarisk.simulator.exports import Exporter
from datarisk.simulator.world import World


def main() -> None:
    cfg = load_config()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=cfg["simulation"]["seed"])
    parser.add_argument("--out", type=Path, default=RAW_DIR)
    args = parser.parse_args()

    world = World(cfg, args.seed)
    world.build()
    counts = Exporter(world).write(args.out)

    fp = sum(i.is_fp for i in world.issues)
    print(f"Simulation seed={args.seed} : {world.start.date()} -> {world.end.date()} ({world.weeks} semaines)")
    print(f"  actifs de données      : {len(world.assets)}")
    print(f"  problèmes simulés      : {len(world.issues)} (dont {fp} faux positifs d'outil)")
    print(f"  actions analystes      : {len(world.events)} {dict(Counter(e['action'] for e in world.events))}")
    for source, n in counts.items():
        print(f"  lignes exportées {source:<14}: {n}")
    print(f"Exports écrits dans {args.out}")


if __name__ == "__main__":
    main()
