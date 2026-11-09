"""Policy documents: hashing, the integrity gate, and retrieval (notebook Step 10.4).

Embeddings run locally (Chroma's bundled all-MiniLM-L6-v2 ONNX model), so retrieval
needs no second API key. The model downloads once (~80 MB) on first use.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

if TYPE_CHECKING:
    from langchain_chroma import Chroma

    from .audit import AuditLog


class CorpusIntegrityError(Exception):
    """Raised when a document's digest is not in the approved manifest."""


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def pdf_text(path: Path | str) -> str:
    """All pages of a PDF as one whitespace-normalised string."""
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    return re.sub(r"\s+", " ", " ".join(p.extract_text() or "" for p in reader.pages)).strip()


class LocalEmbeddings(Embeddings):
    """LangChain adapter over Chroma's default local embedding function."""

    def __init__(self) -> None:
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction

        self._fn = DefaultEmbeddingFunction()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [[float(x) for x in vec] for vec in self._fn(texts)]

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


_EMBEDDINGS: LocalEmbeddings | None = None


def default_embeddings() -> LocalEmbeddings:
    global _EMBEDDINGS
    if _EMBEDDINGS is None:
        _EMBEDDINGS = LocalEmbeddings()
    return _EMBEDDINGS


def build_vectorstore(pdf_path: Path | str, embeddings: Embeddings | None = None) -> Chroma:
    """Chunk and embed a policy PDF into a fresh in-memory collection.

    Note what this does NOT do: check where the document came from. That is the
    weakness attack 7.1 uses against the baseline agent.
    """
    from langchain_chroma import Chroma
    from langchain_text_splitters import RecursiveCharacterTextSplitter
    from pypdf import PdfReader

    path = Path(pdf_path)
    docs = [
        Document(page_content=re.sub(r"\s+", " ", page.extract_text() or "").strip(),
                 metadata={"source_file": path.name, "page": i})
        for i, page in enumerate(PdfReader(str(path)).pages)
    ]
    splits = RecursiveCharacterTextSplitter(chunk_size=520, chunk_overlap=90).split_documents(docs)
    return Chroma.from_documents(
        documents=splits,
        embedding=embeddings or default_embeddings(),
        collection_name=f"policy_{uuid.uuid4().hex[:12]}",
    )


def verify_document(pdf_path: Path | str, manifest: dict[str, str],
                    audit: AuditLog | None = None) -> str:
    """Return the digest if approved, otherwise raise CorpusIntegrityError. Reads no content."""
    path = Path(pdf_path)
    digest = sha256_file(path)
    if digest not in set(manifest.values()):
        if audit is not None:
            audit.append("corpus_integrity_failure", {"file": path.name, "sha256": digest},
                         actor="integrity")
        raise CorpusIntegrityError(
            f"REFUSED to index '{path.name}': sha256 {digest} is not in the approved manifest.")
    if audit is not None:
        audit.append("corpus_integrity_verified", {"file": path.name, "sha256": digest},
                     actor="integrity")
    return digest


def build_verified_vectorstore(pdf_path: Path | str, manifest: dict[str, str],
                               audit: AuditLog | None = None,
                               embeddings: Embeddings | None = None) -> Chroma:
    """Index a policy document only if its SHA-256 is in the approved manifest."""
    verify_document(pdf_path, manifest, audit)
    return build_vectorstore(pdf_path, embeddings)
