import logging
from typing import List

logger = logging.getLogger(__name__)

_model = None


def get_embedding_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer("BAAI/bge-small-en-v1.5")
            logger.info("Embedding model loaded: bge-small-en-v1.5")
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
    return _model


def embed_texts(texts: List[str]) -> List[List[float]]:
    model = get_embedding_model()
    if model is None:
        return [[] for _ in texts]
    return model.encode(texts, normalize_embeddings=True).tolist()


def embed_text(text: str) -> List[float]:
    result = embed_texts([text])
    return result[0] if result else []
