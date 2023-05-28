
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
