"""
Phase 3.5.2 — Embedding Abstraction, TF-IDF Lexical Fallback, and SentenceTransformer Semantic Provider.
"""

from abc import ABC, abstractmethod
import math
import re
from typing import List, Optional, Union, Dict, Any
import numpy as np


class BaseEmbeddingProvider(ABC):
    """Abstract Base Class for Embedding Providers."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return human-readable provider identifier."""
        pass

    @property
    @abstractmethod
    def embedding_dimension(self) -> int:
        """Return the dimension of generated embedding vectors."""
        pass

    @abstractmethod
    def embed_text(self, text: str) -> np.ndarray:
        """Embed a single text string into a 1D float32 numpy array."""
        pass

    @abstractmethod
    def embed_texts(self, texts: List[str]) -> np.ndarray:
        """Embed a list of text strings into a 2D float32 numpy array (N x D)."""
        pass

    def fit(self, texts: List[str]) -> None:
        """Optional fitting step for vocabulary-based embedding providers (e.g. TF-IDF)."""
        pass


class TFIDFEmbeddingProvider(BaseEmbeddingProvider):
    """
    Lexical Keyword Vector Representation via TF-IDF.

    IMPORTANT: This provider is a LEXICAL (keyword) fallback, NOT a semantic model.
    It builds a term frequency - inverse document frequency vocabulary over ingested text.
    It operates 100% offline using numpy and standard Python libraries without external network dependencies.
    """

    def __init__(self, max_features: int = 256):
        self._max_features = max_features
        self._vocab: Dict[str, int] = {}
        self._idf: np.ndarray = np.array([], dtype=np.float32)
        self._is_fitted: bool = False

    @property
    def provider_name(self) -> str:
        return "tfidf_lexical_fallback"

    @property
    def embedding_dimension(self) -> int:
        if not self._is_fitted:
            return self._max_features
        return len(self._vocab) if len(self._vocab) > 0 else self._max_features

    def _tokenize(self, text: str) -> List[str]:
        if not text or not text.strip():
            return []
        # Lowercase and split on non-alphanumeric characters
        tokens = re.findall(r"\b[a-zA-Z0-9_]+\b", text.lower())
        return [t for t in tokens if len(t) > 1]

    def fit(self, texts: List[str]) -> None:
        """Fit vocabulary and compute inverse document frequency (IDF) over corpus."""
        if not texts:
            self._vocab = {}
            self._idf = np.zeros(self._max_features, dtype=np.float32)
            self._is_fitted = True
            return

        doc_count = len(texts)
        term_doc_freq: Dict[str, int] = {}

        all_doc_tokens = []
        for text in texts:
            tokens = set(self._tokenize(text))
            all_doc_tokens.append(tokens)
            for token in tokens:
                term_doc_freq[token] = term_doc_freq.get(token, 0) + 1

        if not term_doc_freq:
            self._vocab = {}
            self._idf = np.zeros(self._max_features, dtype=np.float32)
            self._is_fitted = True
            return

        # Sort terms by frequency descending, take top max_features
        sorted_terms = sorted(term_doc_freq.items(), key=lambda x: x[1], reverse=True)[: self._max_features]
        self._vocab = {term: idx for idx, (term, _) in enumerate(sorted_terms)}

        # Smooth IDF calculation: log((N + 1) / (df + 1)) + 1
        num_terms = len(self._vocab)
        idf_arr = np.zeros(num_terms, dtype=np.float32)
        for term, idx in self._vocab.items():
            df = term_doc_freq[term]
            idf_arr[idx] = math.log((doc_count + 1.0) / (df + 1.0)) + 1.0

        self._idf = idf_arr
        self._is_fitted = True

    def embed_text(self, text: str) -> np.ndarray:
        dim = self.embedding_dimension
        if not self._is_fitted or dim == 0:
            return np.zeros(dim, dtype=np.float32)

        tokens = self._tokenize(text)
        if not tokens:
            return np.zeros(dim, dtype=np.float32)

        # Calculate Term Frequency (TF)
        tf = np.zeros(dim, dtype=np.float32)
        for t in tokens:
            if t in self._vocab:
                tf[self._vocab[t]] += 1.0

        # Normalize TF by total token count
        if len(tokens) > 0:
            tf = tf / float(len(tokens))

        # TF-IDF product
        tfidf = tf * self._idf

        # L2 Normalization
        norm = np.linalg.norm(tfidf)
        if norm > 0:
            tfidf = tfidf / norm

        return tfidf.astype(np.float32)

    def embed_texts(self, texts: List[str]) -> np.ndarray:
        if not texts:
            dim = self.embedding_dimension
            return np.zeros((0, dim), dtype=np.float32)
        
        # Auto-fit if not fitted yet
        if not self._is_fitted:
            self.fit(texts)

        vecs = [self.embed_text(t) for t in texts]
        return np.vstack(vecs).astype(np.float32)


class SentenceTransformerEmbeddingProvider(BaseEmbeddingProvider):
    """
    Semantic Vector Embedding Provider using sentence-transformers.

    Provides true semantic embeddings (e.g. all-MiniLM-L6-v2, 384 dimensions).
    Uses lazy loading to avoid downloading models on application startup or during testing.
    Fails gracefully if sentence-transformers is not installed or model loading fails.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model_name = model_name
        self._model = None
        self._load_attempted = False
        self._dimension = 384  # Default dimension for all-MiniLM-L6-v2

    @property
    def provider_name(self) -> str:
        return f"sentence_transformer:{self._model_name}"

    @property
    def embedding_dimension(self) -> int:
        return self._dimension

    def _load_model(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self._model_name)
            self._dimension = self._model.get_sentence_embedding_dimension()
        except Exception:
            # Lazy load fallback if model or package unavailable
            self._model = None

    @property
    def is_available(self) -> bool:
        self._load_model()
        return self._model is not None

    def embed_text(self, text: str) -> np.ndarray:
        self._load_model()
        if self._model is None:
            # Fallback zero-vector if package/model unavailable
            return np.zeros(self._dimension, dtype=np.float32)

        if not text or not text.strip():
            return np.zeros(self._dimension, dtype=np.float32)

        vector = self._model.encode(text, convert_to_numpy=True)
        return vector.astype(np.float32)

    def embed_texts(self, texts: List[str]) -> np.ndarray:
        self._load_model()
        if self._model is None or not texts:
            dim = self._dimension
            return np.zeros((len(texts), dim), dtype=np.float32)

        vectors = self._model.encode(texts, convert_to_numpy=True)
        return vectors.astype(np.float32)


def get_embedding_provider(
    provider_type: str = "tfidf",
    model_name: Optional[str] = None
) -> BaseEmbeddingProvider:
    """Factory function for instantiating embedding providers."""
    provider_clean = (provider_type or "tfidf").lower().strip()
    if provider_clean in ("tfidf", "tfidf_lexical", "lexical"):
        return TFIDFEmbeddingProvider()
    elif provider_clean in ("sentence_transformer", "sentence_transformers", "semantic"):
        return SentenceTransformerEmbeddingProvider(model_name=model_name or "all-MiniLM-L6-v2")
    else:
        raise ValueError(f"Unknown embedding provider: '{provider_type}'. Supported: 'tfidf', 'sentence_transformer'.")
