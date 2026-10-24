"""
Phase 3.5.3 — Section-Aware Cybersecurity Chunker Module.
"""

from dataclasses import dataclass
import re
from typing import List, Optional

from app.rag.document_loader import CybersecurityDocument


@dataclass
class DocumentChunk:
    chunk_index: int
    section_title: Optional[str]
    content: str
    technique_id: Optional[str] = None
    cve_id: Optional[str] = None


class CybersecurityChunker:
    """
    Section-Aware Cybersecurity Chunker.

    Preserves logical headings (e.g. Overview, Description, Detection, Mitigations)
    and splits long text cleanly at paragraph/sentence boundaries while keeping technical identifiers intact.
    """

    # Recognized section heading regex patterns
    SECTION_HEADING_REGEX = re.compile(
        r"^(?:#{1,6}\s+|===\s*|\b)(Overview|Description|Technical Details|Detection|Procedure Examples|Mitigations|References|Affected Products|CVSS|Summary)(?:\s*===|\:|\s*$)",
        re.IGNORECASE | re.MULTILINE,
    )

    def __init__(self, max_chunk_chars: int = 1500, overlap_chars: int = 100):
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = max(0, overlap_chars)

    def _split_text_by_boundary(self, text: str) -> List[str]:
        """Split long section text into sub-chunks using paragraph -> sentence boundaries."""
        if len(text) <= self.max_chunk_chars:
            return [text]

        paragraphs = text.split("\n\n")
        chunks = []
        current_chunk = []
        current_length = 0

        for para in paragraphs:
            para_len = len(para)
            if current_length + para_len + 2 <= self.max_chunk_chars:
                current_chunk.append(para)
                current_length += para_len + 2
            else:
                if current_chunk:
                    chunks.append("\n\n".join(current_chunk))
                    current_chunk = []
                    current_length = 0

                # If paragraph itself is longer than max_chunk_chars, split by sentences
                if para_len > self.max_chunk_chars:
                    sentences = re.split(r"(?<=[.!?])\s+", para)
                    sub_chunk = []
                    sub_len = 0
                    for sent in sentences:
                        sent_len = len(sent)
                        if sub_len + sent_len + 1 <= self.max_chunk_chars:
                            sub_chunk.append(sent)
                            sub_len += sent_len + 1
                        else:
                            if sub_chunk:
                                chunks.append(" ".join(sub_chunk))
                            sub_chunk = [sent]
                            sub_len = sent_len
                    if sub_chunk:
                        chunks.append(" ".join(sub_chunk))
                else:
                    current_chunk.append(para)
                    current_length = para_len

        if current_chunk:
            chunks.append("\n\n".join(current_chunk))

        return chunks if chunks else [text]

    def chunk_document(self, document: CybersecurityDocument) -> List[DocumentChunk]:
        """
        Chunk a CybersecurityDocument into section-aware DocumentChunk records.
        """
        if not document.content or not document.content.strip():
            return []

        text = document.content.strip()
        chunks: List[DocumentChunk] = []

        # Find section headers
        matches = list(self.SECTION_HEADING_REGEX.finditer(text))

        if not matches:
            # No formal section headings found -> chunk as default Description section
            sub_texts = self._split_text_by_boundary(text)
            for idx, sub in enumerate(sub_texts):
                chunks.append(DocumentChunk(
                    chunk_index=idx,
                    section_title="Description",
                    content=sub,
                    technique_id=document.technique_id,
                    cve_id=document.cve_id,
                ))
            return chunks

        # Parse sections based on header positions
        sections = []
        for i, match in enumerate(matches):
            sec_title = match.group(1).title()
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            sec_body = text[start_pos:end_pos].strip()
            if sec_body:
                sections.append((sec_title, sec_body))

        # Check prefix text before first header
        prefix_text = text[: matches[0].start()].strip()
        if prefix_text:
            sections.insert(0, ("Overview", prefix_text))

        # Build chunks from sections
        chunk_idx = 0
        for sec_title, sec_body in sections:
            sub_texts = self._split_text_by_boundary(sec_body)
            for sub in sub_texts:
                chunks.append(DocumentChunk(
                    chunk_index=chunk_idx,
                    section_title=sec_title,
                    content=sub,
                    technique_id=document.technique_id,
                    cve_id=document.cve_id,
                ))
                chunk_idx += 1

        return chunks
