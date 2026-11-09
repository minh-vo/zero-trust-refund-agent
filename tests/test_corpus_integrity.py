"""Attacks 7.1 and 7.2: a swapped policy document is refused before anything reads it."""

import difflib

import pytest

from shopease_agent.audit import AuditLog
from shopease_agent.config import (
    APPROVED_CORPUS,
    DATA_DIR,
    POLICY_PDF_CLEAN,
    POLICY_PDF_RAG_POISONED,
    POLICY_PDF_SUBTLE_EDIT,
)
from shopease_agent.corpus import CorpusIntegrityError, pdf_text, sha256_file, verify_document
from shopease_agent.framing import legacy_input_filter


def test_approved_document_matches_pinned_digest():
    assert sha256_file(DATA_DIR / POLICY_PDF_CLEAN) == APPROVED_CORPUS[POLICY_PDF_CLEAN]


@pytest.mark.parametrize("pdf", [POLICY_PDF_RAG_POISONED, POLICY_PDF_SUBTLE_EDIT])
def test_tampered_documents_are_refused(pdf):
    audit = AuditLog()
    with pytest.raises(CorpusIntegrityError):
        verify_document(DATA_DIR / pdf, APPROVED_CORPUS, audit)
    assert audit.of_type("corpus_integrity_failure")


@pytest.mark.parametrize("pdf", [POLICY_PDF_RAG_POISONED, POLICY_PDF_SUBTLE_EDIT])
def test_content_filter_cannot_see_the_forgery(pdf):
    """The point of 7.x: the filter has nothing to match, the hash still catches it."""
    blocked, _ = legacy_input_filter(pdf_text(DATA_DIR / pdf))
    assert not blocked


def test_subtle_edit_is_nearly_identical():
    clean = pdf_text(DATA_DIR / POLICY_PDF_CLEAN)
    subtle = pdf_text(DATA_DIR / POLICY_PDF_SUBTLE_EDIT)
    assert difflib.SequenceMatcher(None, clean, subtle).ratio() > 0.99
