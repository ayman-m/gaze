import requests
import os
import json
import csv
from pathlib import Path
from dotenv import load_dotenv

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

SOAR_URL = os.environ.get("SOAR_URL")
SOAR_API_KEY = os.environ.get("SOAR_API_KEY")

payload = ""
headers = {
  'Content-Type': 'application/json',
  'Authorization': SOAR_API_KEY
}

response = requests.request("GET", SOAR_URL+"/settings/integration-commands", headers=headers, data=payload,
                            verify=False)

# Parse the JSON response
data = json.loads(response.text)

# Extract the desired fields from the data
extracted_data = []
for item in data:
    integration_name = item['name']
    category = item['category']
    description = item['description']
    for command in item.get('commands', []):
        command_name = command['name']
        command_description = command['description']
        command_arguments = command['arguments']
        command_outputs = command['outputs']
        extracted_data.append({
            'category': category,
            'integration_name': integration_name,
            'integration_description': description,
            'name': command_name,
            'description': command_description,
            'arguments': command_arguments,
            'outputs': command_outputs
        })

# Save the extracted data to a CSV file
output_file = 'data/source/commands/enabled_commands.csv'
fieldnames = ['category', 'integration_name', 'integration_description', 'name', 'description', 'arguments', 'outputs']

with open(output_file, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(extracted_data)

print(f"Wrote {len(extracted_data)} rows to {output_file}.")

