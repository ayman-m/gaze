import os
import ast
from pathlib import Path
from dotenv import load_dotenv
import numpy as np
from nomic import atlas
import nomic
import pandas as pd
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

ATLAS_KEY = os.environ.get("ATLAS_KEY")
nomic.login(ATLAS_KEY)

df = pd.read_csv("data/processed/embedding/intents/ada-advanced-intent-embedding.csv")
print(df.head())

embeddings_dict = {}

for index, row in df.iterrows():
    embedding_id = row['name'][:35]
    embedding = ast.literal_eval(row['embedding'])

    # this will overwrite the embedding if the id is already present in the dictionary
    embeddings_dict[embedding_id] = embedding

ids = list(embeddings_dict.keys())
embeddings = list(embeddings_dict.values())


embeddings = np.array(embeddings)

atlas.map_embeddings(embeddings=embeddings, data=[{'id': embedding_id} for embedding_id in ids], id_field='id')
#atlas.map_embeddings(embeddings=embeddings, data=[{'id': embedding_id} for embedding_id in (print(f'ID: {id}') or id for id in ids)], id_field='id')