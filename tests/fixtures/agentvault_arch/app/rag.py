"""Vector store construction and retrieval — construction is not invocation."""
from __future__ import annotations

from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores import Chroma


def setup_retriever(docs, q: str):
    emb = OpenAIEmbeddings()
    vs = Chroma.from_documents(docs, emb)
    retriever = vs.as_retriever()
    return retriever.get_relevant_documents(q)
