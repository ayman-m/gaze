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

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")


class Downloader:
    """
    The Downloader is a utility class that provides methods to interact with the GitHub API, specifically to download
    data related to commands from the demisto/content repository.

    The class requires a GitHub token (GITHUB_TOKEN) which should be supplied as an environment variable.

    Class Methods:
    - get_command_arguments_outputs: Downloads YAML files for each integration in the repository, and extracts
                                     information about commands, their arguments, and outputs.

    Attributes:
    g (github.Github): An authenticated Github Python API client instance.
    repo (github.Repository.Repository): The demisto/content repository.
    """
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo("demisto/content")

    @classmethod
    def get_command_arguments_outputs(cls):
        """
        Downloads YAML files for each integration in the repository, and extracts information about commands, their
        arguments, and outputs.

        Returns:
        list: A list of dictionaries, each containing information about a command.

        Each dictionary contains the following keys:
        - "name": The name of the command.
        - "argument": A dictionary containing information about the command's arguments.
        - "outputs": A dictionary containing information about the command's outputs.
        """
        commands_list = []

        packs = cls.repo.get_contents("Packs")
        for pack in packs:
            if pack.type == "dir":
                try:
                    # Get the list of integrations in the pack.
                    integrations = cls.repo.get_contents(pack.path + "/Integrations")
                    print(f"Found {len(integrations)} integrations in pack {pack.path}.")
                    for integration in integrations:
                        if integration.type == "dir":
                            # Get the list of files in the integration.
                            files = cls.repo.get_contents(integration.path)
                            print(f"Found {len(files)} files in integration {integration.path}.")
                            for file in files:
                                if file.path.endswith('.yml'):
                                    response = requests.get(file.download_url)
                                    response.raise_for_status()
                                    data = yaml.safe_load(response.text)
                                    commands = data.get('script', {}).get('commands', [])
                                    for command in commands:
                                        name = command.get('name')
                                        argument = command.get('arguments', {})
                                        command_outputs = command.get('outputs', {})
                                        extracted_data = {
                                            "name": name,
                                            "argument": argument,
                                            "outputs": command_outputs
                                        }
                                        commands_list.append(extracted_data)
                                        break
                                    print(f"Extracted {len(commands_list)} commands from file {file.path}.")
                except Exception as e:
                    print(f"Skipping {pack.path} due to error: {str(e)}")
        return commands_list


all_data = Downloader.get_command_arguments_outputs()
# Write the information into a JSON file.
with open('output.json', 'w') as f:
    json.dump(all_data, f)
print(f"Wrote {len(all_data)} commands to output.json.")