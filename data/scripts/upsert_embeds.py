import pinecone
import json
import os
from pathlib import Path
from dotenv import load_dotenv
import numpy as np
import pandas as pd
import ast

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

PINECONE_KEY = os.environ.get("PINECONE_KEY")
PINECONE_ENV = os.environ.get("PINECONE_ENV")

pinecone.init(api_key=PINECONE_KEY, environment=PINECONE_ENV)
#pinecone.create_index('enabled-commands-index', metric='cosine', dimension=1536)

command_index = pinecone.Index(index_name='enabled-commands-index')
df = pd.read_csv("data/processed/embedding/commands/ada-enabled-command-embedding.csv")

# Initialize lists for command ids and vectors
# Function to parse the stringified embedding


def parse_embedding(embedding_str):
    return np.array(json.loads(embedding_str))


# Load command embeddings
df['embedding'] = df['embedding'].apply(parse_embedding)

"""
# Parse to the necessary format for Pinecone
command_vectors_dicts = [
    {"id": name, "values": embedding.tolist()}
    for name, embedding in zip(df['name'], df['embedding'])
]

command_index.upsert(vectors=command_vectors_dicts)
"""
batch_size = 100

# Batch the data and upsert vectors
for i in range(0, len(df), batch_size):
    batch_df = df[i: i + batch_size]
    command_vectors_dicts = [
        {"id": name, "values": embedding.tolist()}
        for name, embedding in zip(batch_df['name'], batch_df['embedding'])
    ]
    command_index.upsert(vectors=command_vectors_dicts)
    print (f"Processed batch : {i}")
