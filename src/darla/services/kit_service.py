"""Kit business logic."""

import base64
import contextlib
import json
import logging
import mimetypes
import shutil
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from darla.config import get_settings
from darla.models.analysis_result import AnalysisResult, AnalysisType
from darla.models.associations import campaign_kits
from darla.models.indicator import Indicator
from darla.models.investigation import Investigation
from darla.models.kit import Kit, KitStatus
from darla.services.dispatch import commit_then_dispatch

logger = logging.getLogger(__name__)

# Runs after a new kit is flushed but before the commit that precedes the
# chain dispatch.  Anything the chain must see on its first read — the
# investigation link above all — has to be written here: a worker can
# dequeue the chain the instant it is published, so rows written after
# dispatch race it (a root kit whose investigation was linked a few ms
# late spawned its browser_render child with no investigation, dropping
# it from the tree and letting the investigation complete while the
# render was still running).
PrepareKit = Callable[[Kit], Awaitable[None]]


class KitService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_kits(
        self,
        offset: int = 0,
        limit: int = 50,
        status_filter: str | None = None,
        source_feed: str | None = None,
    ) -> tuple[list[Kit], int]:
        query = select(Kit).order_by(Kit.created_at.desc())
        count_query = select(func.count(Kit.id))

        if status_filter:
            query = query.where(Kit.status == status_filter)
            count_query = count_query.where(Kit.status == status_filter)
        if source_feed:
            query = query.where(Kit.source_feed == source_feed)
            count_query = count_query.where(Kit.source_feed == source_feed)

        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_kit(self, kit_id: uuid.UUID) -> Kit | None:
        query = (
            select(Kit)
            .where(Kit.id == kit_id)
            .options(
                selectinload(Kit.indicators),
                selectinload(Kit.analysis_results),
                selectinload(Kit.campaigns),
                selectinload(Kit.families),
                selectinload(Kit.actors),
                selectinload(Kit.child_kits),
            )
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def _find_existing_kit(self, url: str) -> Kit | None:
        """Find an existing non-FAILED root kit with the same source URL."""
        query = (
            select(Kit)
            .where(
                Kit.source_url == url,
                Kit.status != KitStatus.FAILED,
                Kit.parent_kit_id.is_(None),
            )
            .order_by(Kit.created_at.desc())
            .limit(1)
        )
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def submit_kit(
        self, url: str, source_feed: str | None = None, force: bool = False,
        prepare: PrepareKit | None = None,
    ) -> tuple[Kit, str, bool]:
        # URL dedup: return existing kit if already tracked
        if not force:
            existing = await self._find_existing_kit(url)
            if existing:
                return existing, "", True

        kit = Kit(
            id=uuid.uuid4(),
            source_url=str(url),
            source_feed=source_feed or "manual",
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()
        if prepare:
            await prepare(kit)

        # Dispatch Celery task
        from darla.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id), force=force)
        result = await commit_then_dispatch(self.db, chain)
        task_id = result.id

        return kit, task_id, False

    async def submit_file(
        self,
        filename: str,
        local_path: str,
        source_feed: str | None = None,
        kit_id: uuid.UUID | None = None,
        prepare: PrepareKit | None = None,
    ) -> tuple[Kit, str]:
        """Submit a locally-stored file for analysis (skip download)."""
        kit = Kit(
            id=kit_id or uuid.uuid4(),
            source_url=f"file://{filename}",
            source_feed=source_feed or "manual",
            local_path=local_path,
            filename=filename,
            status=KitStatus.PENDING,
        )
        self.db.add(kit)
        await self.db.flush()
        if prepare:
            await prepare(kit)

        from darla.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = await commit_then_dispatch(self.db, chain)
        return kit, result.id

    async def submit_bulk(
        self, urls: list[str], source_feed: str | None = None,
        prepare: PrepareKit | None = None,
    ) -> tuple[list[dict], int, int]:
        """Submit multiple URLs. Returns (results, submitted, skipped)."""
        from darla.tasks.analysis import build_analysis_chain

        results = []
        submitted = 0
        skipped = 0

        for url in urls:
            existing = await self._find_existing_kit(url)
            if existing:
                results.append({
                    "url": url,
                    "kit_id": existing.id,
                    "task_id": None,
                    "duplicate": True,
                })
                skipped += 1
                continue

            kit = Kit(
                id=uuid.uuid4(),
                source_url=url,
                source_feed=source_feed or "manual",
                status=KitStatus.PENDING,
            )
            self.db.add(kit)
            await self.db.flush()
            if prepare:
                await prepare(kit)

            chain = build_analysis_chain(str(kit.id))
            task_result = await commit_then_dispatch(self.db, chain)
            results.append({
                "url": url,
                "kit_id": kit.id,
                "task_id": task_result.id,
                "duplicate": False,
            })
            submitted += 1

        return results, submitted, skipped

    async def submit_bulk_files(
        self, files: list[dict], prepare: PrepareKit | None = None,
    ) -> list[dict]:
        """Submit multiple locally-stored files for analysis.

        Each entry in *files* must have: filename, local_path, kit_id.
        Returns a list of result dicts with kit_id and task_id.
        """
        from darla.tasks.analysis import build_analysis_chain

        results: list[dict] = []
        for f in files:
            kit = Kit(
                id=f["kit_id"],
                source_url=f"file://{f['filename']}",
                source_feed="manual",
                local_path=f["local_path"],
                filename=f["filename"],
                status=KitStatus.PENDING,
            )
            self.db.add(kit)
            await self.db.flush()
            if prepare:
                await prepare(kit)

            chain = build_analysis_chain(str(kit.id))
            task_result = await commit_then_dispatch(self.db, chain)
            results.append({
                "filename": f["filename"],
                "kit_id": kit.id,
                "task_id": task_result.id,
            })

        return results

    async def find_similar(
        self, kit_id: uuid.UUID, threshold: int = 100
    ) -> list[dict]:
        kit = await self.get_kit(kit_id)
        if not kit or not kit.tlsh:
            return []

        # Load all kits with TLSH hashes
        query = select(Kit).where(
            Kit.tlsh.isnot(None),
            Kit.id != kit_id,
        )
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        similar = []
        try:
            import tlsh

            for candidate in candidates:
                try:
                    distance = tlsh.diff(kit.tlsh, candidate.tlsh)
                except Exception:
                    continue
                if distance <= threshold:
                    similar.append({
                        "id": str(candidate.id),
                        "sha256": candidate.sha256,
                        "tlsh": candidate.tlsh,
                        "source_url": candidate.source_url,
                        "distance": distance,
                    })
            similar.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        return similar

    async def reanalyze(self, kit_id: uuid.UUID) -> str:
        kit = await self.get_kit(kit_id)
        if not kit:
            raise ValueError("Kit not found")

        kit.status = KitStatus.PENDING
        await self.db.flush()

        from darla.tasks.analysis import build_analysis_chain

        chain = build_analysis_chain(str(kit.id))
        result = await commit_then_dispatch(self.db, chain)
        return result.id

    async def _collect_descendant_ids(self, kit_id: uuid.UUID) -> list[uuid.UUID]:
        """Recursively collect all descendant kit IDs (depth-first)."""
        all_ids: list[uuid.UUID] = []

        async def _recurse(parent_id: uuid.UUID) -> None:
            result = await self.db.execute(
                select(Kit.id).where(Kit.parent_kit_id == parent_id)
            )
            child_ids = [row[0] for row in result.all()]
            for cid in child_ids:
                all_ids.append(cid)
                await _recurse(cid)

        await _recurse(kit_id)
        return all_ids

    async def get_deletion_preview(self, kit_id: uuid.UUID) -> dict | None:
        """Return a summary of everything that will be cascade-deleted."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        descendant_ids = await self._collect_descendant_ids(kit_id)
        all_kit_ids = [kit_id] + descendant_ids

        indicator_count = (await self.db.execute(
            select(func.count()).select_from(Indicator).where(
                Indicator.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        analysis_count = (await self.db.execute(
            select(func.count()).select_from(AnalysisResult).where(
                AnalysisResult.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        campaign_link_count = (await self.db.execute(
            select(func.count()).select_from(campaign_kits).where(
                campaign_kits.c.kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        investigation_count = (await self.db.execute(
            select(func.count()).select_from(Investigation).where(
                Investigation.root_kit_id.in_(all_kit_ids)
            )
        )).scalar_one()

        return {
            "kit_id": str(kit_id),
            "total_kits": len(all_kit_ids),
            "child_kits": len(descendant_ids),
            "indicators": indicator_count,
            "analysis_results": analysis_count,
            "campaign_links": campaign_link_count,
            "investigations": investigation_count,
        }

    async def get_kit_content(
        self, kit_id: uuid.UUID, max_file_size: int = 1_048_576
    ) -> list[dict] | None:
        """Read text content from the kit's extracted files (or raw download)."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        settings = get_settings()
        files: list[dict] = []

        # Scannable text extensions
        text_exts = {
            ".html", ".htm", ".php", ".js", ".css", ".json", ".xml",
            ".txt", ".eml", ".py", ".sh", ".bat", ".ps1", ".vbs",
            ".svg", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".htaccess",
        }

        # MIME types that indicate readable text content
        text_mimes = {
            "text/html", "text/plain", "text/css", "text/xml",
            "application/json", "application/xml", "application/javascript",
            "application/x-php", "message/rfc822",
        }

        def _is_text_file(fp: Path, kit_mime: str | None = None) -> bool:
            """Check if a file is likely text content."""
            if fp.suffix.lower() in text_exts:
                return True
            # No extension, generic placeholder, or unrecognised extension —
            # check MIME or sniff content.  URL-derived filenames can have
            # misleading suffixes (e.g. ".com" from $user@domain.com).
            known_binary = {
                ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2",
                ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                ".exe", ".dll", ".so", ".wasm",
            }
            if fp.suffix.lower() in known_binary:
                return False
            if not fp.suffix or fp.suffix.lower() not in text_exts:
                if kit_mime and kit_mime in text_mimes:
                    return True
                # Sniff first 512 bytes for text content
                try:
                    head = fp.read_bytes()[:512]
                    head.decode("utf-8")
                    return True
                except (OSError, UnicodeDecodeError):
                    return False
            return False

        def _read_file(fp: Path, relative_to: Path | None = None) -> dict | None:
            try:
                size = fp.stat().st_size
                truncated = size > max_file_size
                content = fp.read_text(errors="replace")[:max_file_size]
                mime, _ = mimetypes.guess_type(fp.name)
                # Fall back to the kit's stored MIME type for extension-less files
                if not mime and not fp.suffix and kit.mime_type:
                    mime = kit.mime_type
                filename = str(fp.relative_to(relative_to)) if relative_to else fp.name
                return {
                    "filename": filename,
                    "content": content,
                    "size": size,
                    "mime_type": mime,
                    "truncated": truncated,
                }
            except (OSError, UnicodeDecodeError):
                return None

        # Check extracted directory first
        extract_dir = Path(settings.kit_extract_dir) / str(kit_id)
        if extract_dir.is_dir():
            for fp in sorted(extract_dir.rglob("*")):
                if not fp.is_file():
                    continue
                if not _is_text_file(fp):
                    continue
                if len(files) >= 50:
                    break
                entry = _read_file(fp, relative_to=extract_dir)
                if entry:
                    files.append(entry)

        # Fallback: raw downloaded file
        if not files and kit.local_path:
            raw = Path(kit.local_path)
            if raw.is_file() and _is_text_file(raw, kit.mime_type):
                entry = _read_file(raw)
                if entry:
                    files.append(entry)

        return files

    def _resolve_download_dir(self, kit: Kit) -> Path | None:
        """Resolve the download directory for a kit from its local_path.

        Falls back to the kit ID directory under kit_download_dir when
        local_path is not set (e.g. browser download failed mid-process
        but partial artifacts like screenshots were already saved).
        """
        if kit.local_path:
            download_dir = Path(kit.local_path).parent
            if download_dir.is_dir():
                return download_dir

        # Fallback: check if a directory named after the kit ID exists
        settings = get_settings()
        fallback_dir = Path(settings.kit_download_dir) / str(kit.id)
        if fallback_dir.is_dir():
            return fallback_dir

        return None

    async def get_kit_screenshots(self, kit_id: uuid.UUID) -> list[dict] | None:
        """Read base64-encoded screenshots from the kit's download directory."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        download_dir = self._resolve_download_dir(kit)
        if not download_dir:
            return []

        screenshots_dir = download_dir / "_screenshots"
        if not screenshots_dir.is_dir():
            return []

        results: list[dict] = []
        for fp in sorted(screenshots_dir.iterdir()):
            if not fp.is_file() or fp.suffix.lower() not in (".png", ".jpg", ".jpeg"):
                continue
            if fp.stat().st_size > 10 * 1024 * 1024:  # 10MB cap
                continue
            if len(results) >= 20:
                break
            try:
                data = fp.read_bytes()
                ext = fp.suffix.lower().lstrip(".")
                mime = "image/jpeg" if ext in ("jpg", "jpeg") else "image/png"
                data_uri = f"data:{mime};base64,{base64.b64encode(data).decode()}"
                # Parse stage from filename: "01_landing.png" → "landing"
                stage = fp.stem
                parts = stage.split("_", 1)
                if len(parts) == 2 and parts[0].isdigit():
                    stage = parts[1]
                results.append({
                    "filename": fp.name,
                    "stage": stage.replace("_", " ").title(),
                    "data_uri": data_uri,
                })
            except OSError:
                continue
        return results

    async def get_kit_network_log(self, kit_id: uuid.UUID) -> dict | None:
        """Read requests.json network log from the kit's download directory."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        download_dir = self._resolve_download_dir(kit)
        if not download_dir:
            return {"events": [], "total": 0}

        requests_file = download_dir / "requests.json"
        if not requests_file.is_file():
            return {"events": [], "total": 0}

        try:
            data = json.loads(requests_file.read_text(errors="replace"))
            if not isinstance(data, list):
                return {"events": [], "total": 0}
            events = data[:5000]
            return {"events": events, "total": len(data)}
        except (OSError, json.JSONDecodeError):
            return {"events": [], "total": 0}

    async def get_kit_browser_resources(self, kit_id: uuid.UUID) -> list[dict] | None:
        """Read captured browser sub-resources from the kit's download directory."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        download_dir = self._resolve_download_dir(kit)
        if not download_dir:
            return []

        resources_dir = download_dir / "_browser_resources"
        if not resources_dir.is_dir():
            return []

        # Text extensions for content preview
        text_exts = {
            ".html", ".htm", ".php", ".js", ".css", ".json", ".xml",
            ".txt", ".svg", ".yml", ".yaml",
        }
        text_mimes = {
            "text/html", "text/plain", "text/css", "text/xml", "text/javascript",
            "application/json", "application/xml", "application/javascript",
            "application/x-php",
        }

        # Fallback MIME map for extensions mimetypes may not know
        ext_mime_fallback = {
            ".js": "application/javascript",
            ".mjs": "application/javascript",
            ".cjs": "application/javascript",
            ".ts": "text/typescript",
            ".jsx": "text/jsx",
            ".tsx": "text/tsx",
            ".php": "application/x-php",
            ".svg": "image/svg+xml",
            ".woff2": "font/woff2",
            ".woff": "font/woff",
        }

        # The manifest says which URL / status / request each capture came
        # from.  Without it, repeat hits on one URL (a lure fetched, re-
        # fetched after its gate, then POSTed to) are indistinguishable.
        manifest: dict[str, dict] = {}
        with contextlib.suppress(OSError, ValueError, TypeError, AttributeError):
            entries = json.loads(
                (resources_dir / "_manifest.json").read_text(errors="replace")
            )
            for e in entries:
                name = str(e.get("filename") or "")
                if name.startswith("_browser_resources/"):
                    manifest[name.removeprefix("_browser_resources/")] = e

        results: list[dict] = []
        for fp in sorted(resources_dir.iterdir()):
            if not fp.is_file() or fp.name == "_manifest.json":
                continue
            if len(results) >= 50:
                break
            meta = manifest.get(fp.name, {})
            try:
                size = fp.stat().st_size
                mime = (meta.get("content_type") or "").split(";")[0].strip() or None
                if not mime:
                    mime, _ = mimetypes.guess_type(fp.name)
                if not mime:
                    mime = ext_mime_fallback.get(fp.suffix.lower())
                is_text = (
                    fp.suffix.lower() in text_exts
                    or (mime and mime in text_mimes)
                )
                content = None
                truncated = False
                max_size = 500 * 1024  # 500KB
                if is_text and size <= max_size:
                    with contextlib.suppress(OSError):
                        content = fp.read_text(errors="replace")
                elif is_text and size > max_size:
                    try:
                        content = fp.read_text(errors="replace")[:max_size]
                        truncated = True
                    except OSError:
                        pass
                results.append({
                    "filename": fp.name,
                    "size": size,
                    "mime_type": mime,
                    "content": content,
                    "truncated": truncated,
                    "url": meta.get("url"),
                    "status": meta.get("status"),
                    "method": meta.get("method"),
                    "timestamp": meta.get("timestamp"),
                    "request_id": meta.get("request_id"),
                })
            except OSError:
                continue
        return results

    async def get_kit_deobfuscation_preview(self, kit_id: uuid.UUID) -> list[dict] | None:
        """Read original and deobfuscated file pairs from the kit's download directory."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        download_dir = self._resolve_download_dir(kit)
        if not download_dir:
            return []

        # Get deobfuscation details from analysis results
        result = (
            await self.db.execute(
                select(AnalysisResult)
                .where(AnalysisResult.kit_id == kit_id)
                .where(AnalysisResult.analysis_type == AnalysisType.DEOBFUSCATION)
            )
        ).scalar_one_or_none()

        if not result or not result.result_data:
            return []

        details = result.result_data.get("details", [])
        if not details:
            return []

        max_content = 500 * 1024  # 500KB per file
        pairs: list[dict] = []
        for d in details[:20]:  # Cap at 20 pairs
            original_path = download_dir / d.get("file", "")
            deob_path = download_dir / d.get("deob_file", "")

            original_content = None
            deob_content = None
            original_truncated = False
            deob_truncated = False

            if original_path.is_file():
                try:
                    raw = original_path.read_text(errors="replace")
                    if len(raw) > max_content:
                        original_content = raw[:max_content]
                        original_truncated = True
                    else:
                        original_content = raw
                except OSError:
                    pass

            if deob_path.is_file():
                try:
                    raw = deob_path.read_text(errors="replace")
                    if len(raw) > max_content:
                        deob_content = raw[:max_content]
                        deob_truncated = True
                    else:
                        deob_content = raw
                except OSError:
                    pass

            pairs.append({
                "file": d.get("file", ""),
                "deob_file": d.get("deob_file", ""),
                "layers": d.get("layers", 0),
                "techniques": d.get("techniques", []),
                "original_content": original_content,
                "original_truncated": original_truncated,
                "deob_content": deob_content,
                "deob_truncated": deob_truncated,
            })

        return pairs

    async def search_kits(
        self,
        q: str | None = None,
        yara_rule: str | None = None,
        tlsh_hash: str | None = None,
        tlsh_threshold: int = 100,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[dict], int]:
        """Search kits by text, YARA rule name, or TLSH similarity."""

        # TLSH similarity search (different path — needs in-memory comparison)
        if tlsh_hash:
            return await self._search_by_tlsh(tlsh_hash, tlsh_threshold, offset, limit)

        # YARA rule search — JSONB query on analysis_results
        if yara_rule:
            return await self._search_by_yara(yara_rule, offset, limit)

        # General text search
        if q:
            return await self._search_by_text(q, offset, limit)

        return [], 0

    async def _search_by_text(
        self, q: str, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        pattern = f"%{q}%"
        where = or_(
            Kit.source_url.ilike(pattern),
            Kit.sha256.ilike(pattern),
            Kit.md5.ilike(pattern),
            Kit.sha1.ilike(pattern),
            Kit.tlsh.ilike(pattern),
            Kit.filename.ilike(pattern),
        )
        count_q = select(func.count(Kit.id)).where(where)
        total = (await self.db.execute(count_q)).scalar_one()

        query = select(Kit).where(where).order_by(Kit.created_at.desc()).offset(offset).limit(limit)
        result = await self.db.execute(query)
        kits = result.scalars().all()
        return [self._kit_to_summary(k) for k in kits], total

    async def _search_by_yara(
        self, rule_name: str, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        """Find kits where a YARA rule matched (JSONB query on analysis_results)."""
        # analysis_results.result_data->'matches' is an array of objects with 'rule' key
        from sqlalchemy import text

        # Count
        count_sql = text("""
            SELECT COUNT(DISTINCT k.id)
            FROM kits k
            JOIN analysis_results ar ON ar.kit_id = k.id
            WHERE ar.analysis_type = 'YARA_SCAN'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(ar.result_data->'matches') m
                WHERE m->>'rule' ILIKE :pattern
              )
        """)
        pattern = f"%{rule_name}%"
        total = (await self.db.execute(count_sql, {"pattern": pattern})).scalar_one()

        # Fetch
        fetch_sql = text("""
            SELECT DISTINCT k.id, k.source_url, k.sha256, k.tlsh, k.status,
                   k.file_size, k.source_feed, k.created_at
            FROM kits k
            JOIN analysis_results ar ON ar.kit_id = k.id
            WHERE ar.analysis_type = 'YARA_SCAN'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(ar.result_data->'matches') m
                WHERE m->>'rule' ILIKE :pattern
              )
            ORDER BY k.created_at DESC
            OFFSET :offset LIMIT :limit
        """)
        rows = (await self.db.execute(
            fetch_sql, {"pattern": pattern, "offset": offset, "limit": limit}
        )).mappings().all()

        items = [
            {
                "id": str(r["id"]),
                "source_url": r["source_url"],
                "sha256": r["sha256"],
                "tlsh": r["tlsh"],
                "status": r["status"],
                "file_size": r["file_size"],
                "source_feed": r["source_feed"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
        return items, total

    async def _search_by_tlsh(
        self, tlsh_hash: str, threshold: int, offset: int, limit: int
    ) -> tuple[list[dict], int]:
        """Find kits similar to the given TLSH hash."""
        query = select(Kit).where(Kit.tlsh.isnot(None))
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        similar: list[dict] = []
        try:
            import tlsh

            for kit in candidates:
                try:
                    distance = tlsh.diff(tlsh_hash, kit.tlsh)
                except Exception:
                    continue
                if distance <= threshold:
                    d = self._kit_to_summary(kit)
                    d["distance"] = distance
                    similar.append(d)
            similar.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        total = len(similar)
        return similar[offset : offset + limit], total

    @staticmethod
    def _kit_to_summary(kit: Kit) -> dict:
        return {
            "id": str(kit.id),
            "source_url": kit.source_url,
            "sha256": kit.sha256,
            "tlsh": kit.tlsh,
            "status": kit.status.value if hasattr(kit.status, "value") else str(kit.status),
            "file_size": kit.file_size,
            "source_feed": kit.source_feed,
            "created_at": kit.created_at.isoformat() if kit.created_at else None,
        }

    async def find_diffable_pairs(
        self,
        kit_id: uuid.UUID,
        max_distance: int = 30,
        max_size_ratio: float = 1.15,
    ) -> list[dict]:
        """Find kits diffable against *kit_id*: same eTLD+1, close TLSH, similar size."""
        from darla.utils.domain import extract_etld_plus_one

        kit = await self.get_kit(kit_id)
        if not kit or not kit.tlsh:
            return []

        domain = extract_etld_plus_one(kit.source_url)
        if not domain:
            return []

        query = select(Kit).where(
            Kit.tlsh.isnot(None),
            Kit.id != kit_id,
            Kit.status == KitStatus.ANALYZED,
        )
        result = await self.db.execute(query)
        candidates = result.scalars().all()

        pairs: list[dict] = []
        try:
            import tlsh as tlsh_mod

            for c in candidates:
                c_domain = extract_etld_plus_one(c.source_url)
                if c_domain != domain:
                    continue
                try:
                    distance = tlsh_mod.diff(kit.tlsh, c.tlsh)
                except Exception:
                    continue
                if distance > max_distance:
                    continue
                # Size ratio check
                if kit.file_size and c.file_size:
                    big, small = max(kit.file_size, c.file_size), min(kit.file_size, c.file_size)
                    if small > 0 and big / small > max_size_ratio:
                        continue
                pairs.append({
                    "id": c.id,
                    "source_url": c.source_url,
                    "tlsh": c.tlsh,
                    "file_size": c.file_size,
                    "distance": distance,
                    "size_ratio": (
                        round(big / small, 3)
                        if kit.file_size and c.file_size
                        and min(kit.file_size, c.file_size) > 0
                        else 1.0
                    ),
                    "created_at": c.created_at,
                })
            pairs.sort(key=lambda x: x["distance"])
        except ImportError:
            pass

        return pairs

    async def get_kit_primary_html(self, kit_id: uuid.UUID) -> str | None:
        """Return the content of the largest .html file for a kit."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return None

        settings = get_settings()

        # Browser-render kits: the authoritative page is the rendered DOM
        # saved as ``page.html`` (``local_path``).  Picking the *largest*
        # HTML in the render dir instead can surface a captured
        # sub-resource (an inlined template, an iframe doc) and make the
        # diff compare the wrong document — so trust local_path here.
        if kit.discovery_method == "browser_render" and kit.local_path:
            page_html = Path(kit.local_path)
            if page_html.is_file() and page_html.suffix.lower() in (".html", ".htm"):
                try:
                    return page_html.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass

        # Check extracted directory first, then raw download
        candidates: list[Path] = []
        extract_dir = Path(settings.kit_extract_dir) / str(kit_id)
        if extract_dir.is_dir():
            candidates.extend(
                fp for fp in extract_dir.rglob("*")
                if fp.is_file() and fp.suffix.lower() in (".html", ".htm")
            )

        if not candidates and kit.local_path:
            raw = Path(kit.local_path)
            if raw.is_file() and raw.suffix.lower() in (".html", ".htm"):
                candidates.append(raw)

        if not candidates:
            return None

        # Pick the largest HTML file
        best = max(candidates, key=lambda fp: fp.stat().st_size)
        try:
            return best.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    async def get_diffable_pair_groups(
        self,
        offset: int = 0,
        limit: int = 20,
        max_distance: int = 30,
        max_size_ratio: float = 1.15,
    ) -> tuple[list[dict], int]:
        """Return domain groups containing ≥2 diffable kits."""
        from darla.utils.domain import extract_etld_plus_one

        query = select(Kit).where(
            Kit.tlsh.isnot(None),
            Kit.status == KitStatus.ANALYZED,
        )
        result = await self.db.execute(query)
        kits = result.scalars().all()

        # Group by eTLD+1
        domain_map: dict[str, list[Kit]] = {}
        for k in kits:
            d = extract_etld_plus_one(k.source_url)
            if d:
                domain_map.setdefault(d, []).append(k)

        # Filter to domains with ≥2 kits that have at least one diffable pair
        groups: list[dict] = []
        try:
            import tlsh as tlsh_mod

            for domain, domain_kits in sorted(domain_map.items()):
                if len(domain_kits) < 2:
                    continue

                pair_count = 0
                for i, ka in enumerate(domain_kits):
                    for kb in domain_kits[i + 1:]:
                        try:
                            dist = tlsh_mod.diff(ka.tlsh, kb.tlsh)
                        except Exception:
                            continue
                        if dist > max_distance:
                            continue
                        if ka.file_size and kb.file_size:
                            big = max(ka.file_size, kb.file_size)
                            small = min(ka.file_size, kb.file_size)
                            if small > 0 and big / small > max_size_ratio:
                                continue
                        pair_count += 1

                if pair_count == 0:
                    continue

                groups.append({
                    "domain": domain,
                    "kits": [
                        {
                            "id": k.id,
                            "source_url": k.source_url,
                            "tlsh": k.tlsh,
                            "file_size": k.file_size,
                            "status": getattr(k.status, "value", str(k.status)),
                            "created_at": k.created_at,
                        }
                        for k in domain_kits
                    ],
                    "pair_count": pair_count,
                })
        except ImportError:
            pass

        total = len(groups)
        return groups[offset : offset + limit], total

    async def delete_kit(self, kit_id: uuid.UUID) -> bool:
        """Delete a kit and all its descendants (DB cascades handle FK cleanup)."""
        kit = await self.get_kit(kit_id)
        if not kit:
            return False

        # Collect local file paths for cleanup before the rows disappear
        local_paths: list[str] = []
        if kit.local_path:
            local_paths.append(kit.local_path)

        descendant_ids = await self._collect_descendant_ids(kit_id)
        if descendant_ids:
            result = await self.db.execute(
                select(Kit.local_path).where(
                    Kit.id.in_(descendant_ids),
                    Kit.local_path.isnot(None),
                )
            )
            local_paths.extend(row[0] for row in result.all())

        # DB cascades delete children, indicators, analysis_results,
        # campaign_kits rows, and investigations (if root_kit)
        await self.db.delete(kit)

        # Best-effort file cleanup (after ORM marks for deletion)
        for path in local_paths:
            try:
                kit_dir = Path(path).parent
                if kit_dir.exists():
                    shutil.rmtree(kit_dir)
            except OSError:
                logger.warning("Failed to clean up kit files at %s", path)

        return True
