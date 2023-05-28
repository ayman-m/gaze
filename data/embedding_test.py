import pandas as pd
import os
import openai
import ast
import time
import numpy as np

from pathlib import Path
from dotenv import load_dotenv
from openai.embeddings_utils import get_embedding
from openai.embeddings_utils import cosine_similarity

start_time = time.time()

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

# Retrieve environment variables
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

openai.api_key = OPENAI_API_KEY


class CommandEmbedding:
    def __init__(self, file_path):
        self.file_path = file_path
        self.df = pd.read_csv(file_path, usecols=['embedding', 'name'])

    @classmethod
    def get_embedding_vectors(cls, question):
        question_vector = get_embedding(question, engine='text-embedding-ada-002')
        return question_vector

    def get_similarities(self, question_vector):
        self.df["similarities"] = self.df['embedding'].apply(lambda x: cosine_similarity(np.array(ast.literal_eval(x)),
                                                                                         question_vector))

    def get_top_similar_rows(self, num_rows=4):
        similar_rows = self.df.sort_values(by='similarities', ascending=False).head(num_rows)
        return similar_rows


# Initialize the class and load the data
command_embedding = CommandEmbedding('data/all-command_embedding.csv')

# Calculate the embedding for a question
question = "I need to get user information from active directory?"
question_vector = command_embedding.get_embedding_vectors(question)

# Get similarities
command_embedding.get_similarities(question_vector)

# Get top similar rows
top_similar_rows = command_embedding.get_top_similar_rows(5)
print(top_similar_rows)


end_time = time.time()

print(f'Time taken: {end_time - start_time} seconds')