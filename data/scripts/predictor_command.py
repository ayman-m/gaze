import ast
import os
import pandas as pd
import numpy as np
import openai

from pathlib import Path
from dotenv import load_dotenv
from openai.embeddings_utils import get_embedding
from openai.embeddings_utils import cosine_similarity

# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
openai.api_key = OPENAI_API_KEY

# Get user inputs
model_choice = input("Choose a command list (All or Some): ")
prompt = input("Enter a prompt to test: ")
df = None
# Check if the chosen model is valid
if model_choice not in ["All", "Some"]:
    print("Invalid list choice. Please choose a valid command list.")
    exit()

if model_choice == "All":
    df = pd.read_csv("data/processed/embedding/commands/ada-all-command-embedding.csv", usecols=['embedding', 'name'])

if model_choice == "Some":
    df = pd.read_csv("data/processed/embedding/commands/ada-some-command-embedding.csv", usecols=['embedding', 'name'])

question_vector = get_embedding(prompt, engine="text-embedding-ada-002")
df["similarities"] = df['embedding'].apply(lambda x: cosine_similarity(np.array(ast.literal_eval(x)),
                                                                       question_vector))
similar_rows = df.sort_values(by='similarities', ascending=False).head(3)

# Print the similar intent names and their similarities
for index, row in similar_rows.iterrows():
    print("Command Name:", row['name'])
    print("Similarity:", row['similarities'])
    print()
