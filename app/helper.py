import json
import ast


class Decorator:
    """
    Decorator is a utility class that provides methods for cleaning dictionaries and generating enrichment blocks for Slack messages.

    Class Methods:
    - clean_dict: Cleans a dictionary by removing keys with None values and flattening nested dictionaries.
    - enrichment_blocks: Generates a list of Slack block kit components to display the information from a list of dictionaries.
    """

    @classmethod
    def clean_dict(cls, dictionary):
        """
        Cleans a dictionary by removing keys with None values and flattening nested dictionaries.

        Parameters:
        dictionary (dict): The dictionary to clean.

        Returns:
        dict: The cleaned dictionary.
        """
        cleaned_dict = {}
        for key, value in dictionary.items():
            if isinstance(value, dict):
                nested_dict = cls.clean_dict(value)
                cleaned_dict.update(nested_dict)
            elif value is not None:
                cleaned_dict[key] = value
        return cleaned_dict

    @classmethod
    def enrichment_blocks(cls, dict_list, header=None):
        """
        Generates a list of Slack block kit components to display the information from a list of dictionaries.

        Parameters:
        dict_list (list): A list of dictionaries containing the information to display.
        header (str, optional): The header text to display above the blocks.

        Returns:
        list: A list of Slack block kit components.
        """
        blocks = []
        if header:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*{}*\n".format(header)
                }
            })
        for item_dict in dict_list:
            table_text = ""
            for key, value in item_dict.items():
                if isinstance(value, list):
                    value = ', '.join(map(str, value))
                table_text += "*{}*: {}\n".format(key, value)
            block = {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": table_text
                }
            }
            blocks.append(block)
            blocks.append({"type": "divider"})  # Add divider after each section
        return blocks

    @classmethod
    def generate_choices(cls, similar_rows):
        choices = []
        if similar_rows.to_dict().get('matches'):
            for row in similar_rows.get('matches'):
                choices.append({
                    "text": {
                        "type": "plain_text",
                        "text": row['id'],
                    },
                    "value": row['id']
                })
        else:
            for index, row in similar_rows.iterrows():
                choices.append({
                    "text": {
                        "type": "plain_text",
                        "text": row['name'],
                    },
                    "value": row['name']
                })
        return choices

    @classmethod
    def check_key(cls, dict_obj, key):
        if key in dict_obj.keys():
            return True
        else:
            return False

    @classmethod
    def command_outputs_blocks(cls, command_reader, command_name):
        blocks = [{"type": "divider"}]
        command_row = command_reader[command_reader['name'] == command_name]
        if command_row.empty:
            return False, None
        choices = [{
                "text": {
                    "type": "plain_text",
                    "text": "WarRoomOutput"
                },
                "value": "WarRoomOutput"
        }]
        if command_row['outputs'].notnull().any():
            outputs = command_row['outputs'].values[0]
            outputs = ast.literal_eval(outputs)
            unique_paths_set = set()
            for output in outputs:
                output_path = output.get('contextPath', None)
                path_to_third_level = '.'.join(output_path.split('.')[:3])
                unique_paths_set.add(path_to_third_level)
            unique_paths_list = list(unique_paths_set)
            for path in unique_paths_list:
                choices.append({
                    "text": {
                        "type": "plain_text",
                        "text": path
                    },
                    "value": path
                })
        output_blocks = [
            {
                "type": "section",
                "block_id": f"{command_name}_outputs",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Select the outputs that you want me to return for the command: *{command_name}*."
                },
                "accessory": {
                    "type": "multi_static_select",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Select outputs"
                    },
                    "options": choices,
                    "action_id": "command_outputs_static_select-action"
                }
            },
            {"type": "divider"}
        ]
        blocks.extend(output_blocks)
        if command_row['outputs'].notnull().any():
            return True, blocks
        else:
            return False, blocks

    @classmethod
    def command_arguments_blocks(cls, command_reader, command_name, command_outputs=None):
        blocks = [{"type": "divider"}]
        command_row = command_reader[command_reader['name'] == command_name]
        if command_row.empty:
            return None
        if command_row['arguments'].notnull().any():
            arguments = command_row['arguments'].values[0]

            arguments = ast.literal_eval(arguments)
            # Sort arguments based on their required attribute
            arguments.sort(key=lambda x: x['required'], reverse=True)
            command_blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Please provide values for the following arguments for the command:  *{command_name}*:"
                    }
                }
            ]

            for arg in arguments:
                # If the argument is required, prepend an asterisk to its name
                arg_name = f"*{arg['name']}" if arg['required'] else arg['name']
                arg_text = f"{arg_name} : {arg['description']}"

                block = {
                    "type": "input",
                    "element": {
                        "type": "plain_text_input",
                        "multiline": False,
                        "action_id": arg['name']
                    },
                    "label": {
                        "type": "plain_text",
                        "text": arg_text
                    }
                }
                command_blocks.append(block)
            command_blocks.append({"type": "divider"})

        else:
            command_blocks = [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"No arguments found :ghost: for the command :  *{command_name}*"
                    }
                },
                {"type": "divider"}
            ]

        blocks.extend(command_blocks)
        # Add a submit button
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": "Submit"
                    },
                    "style": "primary",
                    "action_id": "submit_command_arguments",
                    "value": command_name+"::"+','.join(command_outputs or "-")
                }
            ]
        })
        return blocks

    @classmethod
    def payload_to_command_line(cls, payload):
        command_name = payload['actions'][0]['value'].split("::")[0]
        command_outputs = payload['actions'][0]['value'].split("::")[1]
        state_values = payload['state']['values']

        arguments_line = ''
        for block_id, block_value in state_values.items():
            for action_id, action_value in block_value.items():
                value = action_value.get('value')
                if value is not None:
                    arguments_line += f" {action_id}={value}"

        return f"!{command_name}{arguments_line}", command_outputs.split(",")
