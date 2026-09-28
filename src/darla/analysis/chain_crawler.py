"""Chain crawler — submits child kits for scored links within an investigation."""

import logging
import uuid
from urllib.parse import urlparse, urlunparse

from sqlalchemy.orm import Session

from darla.models.kit import Kit, KitStatus

logger = logging.getLogger(__name__)


def _normalize_url(url: str) -> str:
    """Normalize a URL for dedup comparison.

    Strips fragments, trailing slashes, and lowercases scheme+host so that
    ``https://foo.com/path#anchor`` and ``https://foo.com/path`` match.
    """
    try:
        p = urlparse(url)
        # Drop fragment, normalise scheme + host to lowercase
        path = p.path.rstrip("/") or "/"
        return urlunparse((p.scheme.lower(), p.netloc.lower(), path, p.params, p.query, ""))
    except Exception:
        return url


class ChainCrawler:
    """Submit child kits for links that scored above threshold."""

    def __init__(self, db: Session):
        self.db = db

    def submit_child_kits(
        self,
        parent_kit_id: uuid.UUID,
        investigation_id: uuid.UUID,
        scored_links: list,  # list[ScoredLink]
        current_depth: int,
    ) -> list[uuid.UUID]:
        """Create child Kit records and dispatch analysis chains.

        Returns list of created kit IDs.
        """
        from darla.tasks.analysis import build_analysis_chain

        # Build a set of normalized URLs already in this investigation
        existing_urls = {
            _normalize_url(row[0])
            for row in self.db.query(Kit.source_url).filter(
                Kit.investigation_id == investigation_id,
            ).all()
        }

        child_ids = []

        for link in scored_links:
            # Dedup: skip if a normalized match already exists in investigation
            norm = _normalize_url(link.url)
            if norm in existing_urls:
                logger.debug("Skipping duplicate URL in investigation: %s", link.url)
                continue
            existing_urls.add(norm)

            kit = Kit(
                source_url=link.url,
                source_feed="investigation",
                status=KitStatus.PENDING,
                parent_kit_id=parent_kit_id,
                investigation_id=investigation_id,
                chain_depth=current_depth + 1,
                discovery_method=link.source,
            )
            self.db.add(kit)
            self.db.flush()  # Get the ID

            child_ids.append(kit.id)

            logger.info(
                "Spawned child kit %s (depth=%d, method=%s, score=%.2f): %s",
                kit.id, current_depth + 1, link.source, link.score, link.url,
            )

        # Commit before dispatching: a worker that dequeues a chain before
        # the row is visible fails with "Kit ... not found" and burns its
        # only retry.
        self.db.commit()
        for child_id in child_ids:
            build_analysis_chain(str(child_id)).apply_async()
        return child_ids
