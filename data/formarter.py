import json

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
print(f"Total tokens: {total_tokens} with cost: {tuning_cost}")