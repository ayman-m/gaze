import json
import csv
import pandas as pd


# Load your original dataframe
df = pd.read_csv('data/command_embedding.csv')

# Select the columns you want to keep
df = df[['name', 'embedding']]

# Write the dataframe to a new csv file
df.to_csv('data/command_embedding_no_description.csv', index=False)


"""
# Load your JSON file
with open('output.json') as f:
    data = json.load(f)

# Open (or create) your CSV file
with open('output.csv', 'w') as f:
    # Create a CSV writer
    writer = csv.DictWriter(f, fieldnames=['name', 'description'])

    # Write the CSV header
    writer.writeheader()

    # Write the JSON data to the CSV file
    for row in data:
        writer.writerow(row)


total_tokens = 0
token_cost = 0.000240881872618
# Read the data from the JSON file.
with open('output.json', 'r') as f:
    data = json.load(f)

# Transform the data.
transformed_data = [{'prompt': item['description']+" END", 'completion': " "+item['name']+" END"} for item in data]

# Write the transformed data to a JSONL file.
with open('output.jsonl', 'w') as f:
    for item in transformed_data:
        f.write(json.dumps(item) + '\n')

with open('output.jsonl', 'r') as f:
    for line in f:
        item = json.loads(line)
        for value in item.values():
            if isinstance(value, str):
                total_tokens += len(value.split())
    tuning_cost = total_tokens * token_cost
"""
