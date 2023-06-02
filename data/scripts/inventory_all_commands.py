import requests
from github import Github
import yaml
import csv
import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

g = Github(GITHUB_TOKEN)
repo = g.get_repo("demisto/content")
commands_list = []
packs = repo.get_contents("Packs")

for pack in packs:
    if pack.type == "dir":
        try:
            # Get the list of integrations in the pack.
            integrations = repo.get_contents(pack.path + "/Integrations")
            print(f"Found {len(integrations)} integrations in pack {pack.path}.")
            for integration in integrations:
                if integration.type == "dir":
                    # Get the list of files in the integration.
                    files = repo.get_contents(integration.path)
                    print(f"Found {len(files)} files in integration {integration.path}.")
                    for file in files:
                        if file.path.endswith('.yml'):
                            response = requests.get(file.download_url)
                            response.raise_for_status()
                            data = yaml.safe_load(response.text)
                            category = data.get('category', "NA")
                            integration_description = data.get('description', "NA")
                            integration_name = data.get('name', "NA")
                            commands = data.get('script', {}).get('commands', [])
                            for command in commands:
                                name = command.get('name')
                                description = command.get('description')
                                argument = command.get('arguments', {})
                                command_outputs = command.get('outputs', {})
                                extracted_data = {
                                    "category": category,
                                    'integration_name': integration_name,
                                    "integration_description": integration_description,
                                    "name": name,
                                    "description": description,
                                    "arguments": argument,
                                    "outputs": command_outputs,
                                }
                                commands_list.append(extracted_data)
                            print(f"Extracted {len(commands_list)} commands from file {file.path}.")
        except Exception as e:
            print(f"Skipping {pack.path} due to error: {str(e)}")

# Write the information into a CSV file.
output_file = 'data/source/commands/all_commands.csv'
with open(output_file, 'a', newline='') as f:
    fieldnames = ['category', 'integration_name', 'integration_description', 'name', 'description', 'arguments',
                  'outputs']
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if os.stat(output_file).st_size == 0:
        writer.writeheader()
    writer.writerows(commands_list)

print(f"Wrote {len(commands_list)} commands to {output_file}.")
