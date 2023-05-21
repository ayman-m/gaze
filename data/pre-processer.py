import requests
from github import Github
import yaml
import json
import os
from pathlib import Path
from dotenv import load_dotenv

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

SLACK_BOT_TOKEN = os.environ.get("GITHUB_TOKEN")

g = Github(SLACK_BOT_TOKEN)

# Then get your specific repo
repo = g.get_repo("demisto/content")

all_data = []

# Get the list of packs.
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
                            # Download the YAML file.
                            response = requests.get(file.download_url)
                            response.raise_for_status()

                            # Parse the YAML file into a Python dictionary.
                            data = yaml.safe_load(response.text)

                            # Extract the commands and their descriptions.
                            commands = data.get('script', {}).get('commands', [])
                            extracted_data = [{'name': cmd.get('name'), 'description': cmd.get('description')} for cmd in commands]

                            all_data.extend(extracted_data)
                            print(f"Extracted {len(extracted_data)} commands from file {file.path}.")
        except Exception as e:
            print(f"Skipping {pack.path} due to error: {str(e)}")

# Write the information into a JSON file.
with open('output.json', 'w') as f:
    json.dump(all_data, f)
print(f"Wrote {len(all_data)} commands to output.json.")