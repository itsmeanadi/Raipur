import os
import re
from pathlib import Path
from collections import Counter
import math

class Corpus:
    def __init__(self, docs_dir: str):
        self.chunks = []
        self.load_documents(docs_dir)
        
    def load_documents(self, docs_dir: str):
        p = Path(docs_dir)
        if not p.exists():
            return
            
        for file_path in p.glob("*.txt"):
            text = file_path.read_text(encoding="utf-8")
            # Split by 500 chars roughly, preferring paragraph breaks if any
            # To keep it simple, just chunk by paragraphs or max length
            paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
            
            for para in paragraphs:
                if len(para) > 500:
                    # split further if too long
                    for i in range(0, len(para), 500):
                        self.chunks.append({
                            "source_file": file_path.name,
                            "text": para[i:i+500]
                        })
                else:
                    self.chunks.append({
                        "source_file": file_path.name,
                        "text": para
                    })

    def retrieve(self, query: str, k: int = 4):
        if not self.chunks:
            return []
            
        # Very simple TF-IDF / term overlap matching
        def tokenize(text):
            return re.findall(r'\w+', text.lower())
            
        query_terms = tokenize(query)
        if not query_terms:
            return self.chunks[:k]
            
        # Calculate DF
        df = Counter()
        chunk_tokens_list = []
        for c in self.chunks:
            tokens = set(tokenize(c["text"]))
            chunk_tokens_list.append(list(tokenize(c["text"])))
            for t in tokens:
                df[t] += 1
                
        N = len(self.chunks)
        idf = {t: math.log(N / (df[t] + 1)) for t in df}
        
        scores = []
        for i, c in enumerate(self.chunks):
            tokens = chunk_tokens_list[i]
            tf = Counter(tokens)
            score = sum(tf[t] * idf.get(t, 0) for t in query_terms)
            scores.append((score, c))
            
        scores.sort(key=lambda x: x[0], reverse=True)
        return [c for score, c in scores[:k]]

def retrieve(query: str, k: int = 4, docs_dir: str = None):
    if docs_dir is None:
        docs_dir = str(Path(__file__).parent / "documents")
    corpus = Corpus(docs_dir)
    return corpus.retrieve(query, k)
