"""Bitcoin address activity via the Blockstream Esplora API (no key, no account).

It records transaction count, total received/sent and the balance as of capture time.
Other chains need keyed APIs and are left to future plugins.
"""

from __future__ import annotations

import json
import re
from typing import ClassVar

from osint.core.context import PluginContext
from osint.core.plugins import Enricher
from osint.enrichment.base import EnrichmentResult, EntityView
from osint.evidence.capture import capture_url

BTC = re.compile(r"^(bc1[0-9a-z]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
SAT = 100_000_000


class BtcEnricher(Enricher):
    name = "btc"
    version = "0.1.0"
    description = "Bitcoin address activity (Blockstream Esplora)."
    entity_types: ClassVar[set[str]] = {"crypto_wallet"}

    async def enrich(self, entity: EntityView, ctx: PluginContext) -> EnrichmentResult:
        addr = (entity.strong_key or entity.name).strip()
        if not BTC.match(addr):
            return EnrichmentResult(skipped="not a Bitcoin address")
        item = await capture_url(ctx, f"https://blockstream.info/api/address/{addr}", self.ident,
                                 screenshot=False, platform="blockstream")
        item.parse = False
        res = EnrichmentResult(captures=[item])
        if item.meta.http_status != 200:
            res.facts_text = f"Bitcoin address: {addr}\nLookup returned HTTP {item.meta.http_status}"
            return res
        d = json.loads(item.data)
        c, m = d.get("chain_stats", {}), d.get("mempool_stats", {})
        received = c.get("funded_txo_sum", 0) / SAT
        sent = c.get("spent_txo_sum", 0) / SAT
        res.facts_text = "\n".join([
            f"Bitcoin address: {addr}",
            f"Confirmed transactions: {c.get('tx_count', 0)}",
            f"Total received: {received:.8f} BTC",
            f"Total sent: {sent:.8f} BTC",
            f"Balance at capture: {received - sent:.8f} BTC",
            f"Unconfirmed transactions: {m.get('tx_count', 0)}",
        ])
        res.attributes = {"chain": "bitcoin", "tx_count": c.get("tx_count", 0),
                          "received_btc": received, "sent_btc": sent,
                          "balance_btc": received - sent}
        return res
