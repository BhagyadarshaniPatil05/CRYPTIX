import pytest
import numpy as np
from app.rag.embeddings import (
    BaseEmbeddingProvider,
    TFIDFEmbeddingProvider,
    SentenceTransformerEmbeddingProvider,
    get_embedding_provider,
)


def test_tfidf_initialization_and_provider_name():
    """1. Test TFIDFEmbeddingProvider initialization and properties."""
    provider = TFIDFEmbeddingProvider(max_features=64)
    assert provider.provider_name == "tfidf_lexical_fallback"
    assert provider.embedding_dimension == 64


def test_tfidf_corpus_fit_and_dimensions():
    """2 & 5. Test fitting corpus and verifying dimension consistency."""
    provider = TFIDFEmbeddingProvider(max_features=10)
    corpus = [
        "Android malware dynamic code loading T1407",
        "SMS Trojan privilege escalation intent filter",
        "Network socket connection command execution",
    ]
    provider.fit(corpus)
    assert provider.embedding_dimension > 0
    assert provider.embedding_dimension <= 10


def test_tfidf_embed_single_text():
    """3. Test embedding a single text string into a 1D float32 array."""
    provider = TFIDFEmbeddingProvider(max_features=16)
    corpus = ["Android malware T1407", "Dynamic code loading"]
    provider.fit(corpus)

    vec = provider.embed_text("Android malware T1407")
    assert isinstance(vec, np.ndarray)
    assert vec.dtype == np.float32
    assert vec.ndim == 1
    assert vec.shape[0] == provider.embedding_dimension


def test_tfidf_embed_multiple_texts():
    """4. Test embedding multiple texts into a 2D float32 array."""
    provider = TFIDFEmbeddingProvider(max_features=16)
    corpus = ["Android malware T1407", "Dynamic code loading", "SMS intent"]
    provider.fit(corpus)

    texts = ["Android malware", "Dynamic code"]
    matrix = provider.embed_texts(texts)
    assert isinstance(matrix, np.ndarray)
    assert matrix.dtype == np.float32
    assert matrix.ndim == 2
    assert matrix.shape[0] == 2
    assert matrix.shape[1] == provider.embedding_dimension


def test_tfidf_deterministic_output():
    """6. Test that same text produces identical embedding vectors."""
    provider = TFIDFEmbeddingProvider(max_features=16)
    provider.fit(["Android malware T1407", "Dynamic code loading"])

    vec1 = provider.embed_text("Android malware T1407")
    vec2 = provider.embed_text("Android malware T1407")
    np.testing.assert_array_almost_equal(vec1, vec2)


def test_tfidf_empty_text_handled_safely():
    """7. Test that empty text returns a zero vector without crashing."""
    provider = TFIDFEmbeddingProvider(max_features=16)
    provider.fit(["Android malware T1407"])

    vec_empty = provider.embed_text("")
    assert isinstance(vec_empty, np.ndarray)
    assert np.all(vec_empty == 0.0)

    vec_whitespace = provider.embed_text("   ")
    assert np.all(vec_whitespace == 0.0)


def test_tfidf_unknown_terms_handled_safely():
    """8. Test that text containing only unknown out-of-vocabulary terms returns zero vector."""
    provider = TFIDFEmbeddingProvider(max_features=16)
    provider.fit(["Android malware T1407"])

    vec_unknown = provider.embed_text("xyz_unknown_term_99999")
    assert isinstance(vec_unknown, np.ndarray)
    assert np.all(vec_unknown == 0.0)


def test_sentence_transformer_optional_dependency():
    """9 & 10. Test SentenceTransformer optional dependency and graceful fallback."""
    provider = SentenceTransformerEmbeddingProvider(model_name="all-MiniLM-L6-v2")
    assert "sentence_transformer" in provider.provider_name

    # Check lazy loading: model should not load on instantiation
    assert provider._load_attempted is False

    # Calling embed_text must not crash even if sentence_transformers is not installed
    vec = provider.embed_text("Android malware T1407")
    assert isinstance(vec, np.ndarray)
    assert vec.ndim == 1
    assert vec.shape[0] == provider.embedding_dimension


def test_sentence_transformer_lazy_loading():
    """11. Test lazy model loading behavior."""
    provider = SentenceTransformerEmbeddingProvider(model_name="all-MiniLM-L6-v2")
    assert provider._model is None
    assert provider._load_attempted is False

    # First embed trigger attempts load
    _ = provider.embed_text("Test query")
    assert provider._load_attempted is True


def test_factory_function():
    """12. Test get_embedding_provider factory creation and validation."""
    tfidf_provider = get_embedding_provider("tfidf")
    assert isinstance(tfidf_provider, TFIDFEmbeddingProvider)

    st_provider = get_embedding_provider("sentence_transformer")
    assert isinstance(st_provider, SentenceTransformerEmbeddingProvider)

    with pytest.raises(ValueError, match="Unknown embedding provider"):
        get_embedding_provider("non_existent_provider")
