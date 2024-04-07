import os
import asyncio
import ast
import shlex
import re
import json
import urllib3
import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from slack_sdk import WebClient
from slack_sdk.webhook import WebhookClient
from slack_sdk.errors import SlackApiError
import logging


# Custom logging filter
class CustomFilter(logging.Filter):
    def filter(self, record):
        return 'Bolt app is running!' not in record.getMessage()


# Set up logging
slack_logger = logging.getLogger("internal_slack")
slack_logger.addFilter(CustomFilter())

# Globals and constants
SEVERITY_DICT = {'Unknown': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
SCORE_DICT = {'Unknown': 0, 'Good': 1, 'Suspicious': 2, 'Bad': 3}

LONG_RUNNING_ENABLED = demisto.params().get('longRunning', True)

SSL_VERIFY = demisto.params().get('unsecure', False)
DEBUG_START = demisto.params().get('debug_start', False)
BOT_TOKEN = demisto.params().get('slack_bot_token', {}).get('password', '')
APP_TOKEN = demisto.params().get('slack_app_token', {}).get('password', '')
XSOAR_API_URL = demisto.params().get('xsoar_url')
XSOAR_API_KEY = demisto.params().get('xsoar_api_key', {}).get('password', '')
XSOAR_API_KEY_ID = demisto.params().get('xsoar_api_key_id', {}).get('password', '')

os.environ["SLACK_BOT_TOKEN"] = BOT_TOKEN
os.environ["SLACK_APP_TOKEN"] = APP_TOKEN
xsoar_url = XSOAR_API_URL.replace('api-', '')

proxies = handle_proxy()
proxy_url = proxies.get('http')  # aiohttp only supports http proxy

COMMAND_LIST = {
    "xsoar_health":
        {
            "cmd": "xsoar_health",
            "args": "n/a",
            "description": "Check That XSOAR is Up.\n"
        },
    "block_mac":
        {
            "cmd": "block_mac",
            "args": "*mac*=MAC Address",
            "description": "Block by MAC in Firewalls\n"
        },
    "block_ip":
        {
            "cmd": "block_ip",
            "args": "*ip*=IP Address",
            "description": "Block by IP in Firewalls\n"
        },
    "wireless_client_lookup":
        {
            "cmd": "wireless_client_lookup",
            "args": "*mac*=MAC Address\n*ip*=IP Address",
            "description": "Search For Wireless Clients by MAC\n"
        },
    "firewall_request":
        {
            "cmd": "firewall_request",
            "args": "*option*=change|outage|threat|other\n*details*=\"Request something Here.\"",
            "description": "Send request to the firewall team."
        },
    "qos_mac":
        {
            "cmd": "qos_mac",
            "args": "*mac*=MAC Address",
            "description": "Set QoS by MAC in Firewalls\n"
        },
    "check_ioc":
        {
            "cmd": "check_ioc",
            "args": "*url*=<list of urls>\n*ip*=<list of IPs>\n*email*=<list of emails>"
                    "\n*domain*=<list of domains>\nrep=Unknown|Good|Suspicious|Bad\n",
            "description": "Check & Enrich IOCs\n"
        },
    "my_incidents":
        {
            "cmd": "my_incidents",
            "args": "n/a",
            "description": "List Your Incidents\n"
        },
    "xsoar_invite":
        {
            "cmd": "xsoar_invite",
            "args": "*email*=<preferred email address>",
            "description": "Invite yourself to XSOAR.\n"
        }
}

app = App(token=BOT_TOKEN, logger=slack_logger)


# Decorator class for utility methods

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
                    "value": command_name + "::" + ','.join(command_outputs or "-")
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


# XSOAR Client for interacting with XSOAR API

class XSOARClient:
    def __init__(self, url, api_key, api_key_id):
        self.url = url
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-xdr-auth-id": api_key_id,
            'Authorization': api_key
        }

    # Slack Command Methods
    @property
    def health(self):
        try:
            response_api = requests.get(self.url + "/", headers=self.headers, verify=SSL_VERIFY)
        except Exception as e:
            print("Error Occurred. " + str(e.args))
            return str(e.args)
        else:
            return response_api.status_code

    def create_incident(self, incident_type, incident_owner, incident_name, incident_severity, incident_detail):
        if incident_owner:
            data = {
                "type": incident_type,
                "name": incident_name,
                "details": incident_detail,
                "severity": incident_severity,
                "owner": incident_owner,
                "createInvestigation": True
            }
        else:
            data = {
                "type": incident_type,
                "name": incident_name,
                "details": incident_detail,
                "severity": incident_severity,
                "createInvestigation": True
            }
        try:
            response_api = requests.post(self.url + "/xsoar/public/v1/incident", headers=self.headers,
                                         data=json.dumps(data),
                                         verify=SSL_VERIFY)
        except Exception as e:
            print("Error Occurred. " + str(e.args))
            return str(e.args)
        else:
            return response_api.text

    def search_incident(self, data):
        try:
            response_api = requests.post(self.url + "/xsoar/public/v1/incidents/search", headers=self.headers,
                                         data=json.dumps(data), verify=SSL_VERIFY)
        except Exception as e:
            print("Error Occurred. " + str(e.args))
            return str(e.args)
        else:
            if response_api.status_code == 200:
                return response_api.text
            else:
                return response_api.status_code

    def search_indicator(self, data):
        try:
            response_api = requests.post(self.url + "/xsoar/public/v1/indicators/search", headers=self.headers,
                                         data=json.dumps(data), verify=SSL_VERIFY)
        except Exception as e:
            print("Error Occurred. " + str(e.args))
            return str(e.args)
        else:
            if response_api.status_code == 200:
                return response_api.text
            else:
                return response_api.status_code


# Helper functions for Slack message handling

def slack_send(json_str):
    blocks = ""
    channel_id = ""
    text = ""
    message = json.loads(json.dumps(json_str))
    if "channel" in message:
        channel_id = message['channel']
    if "text" in message:
        text = message['text']
    if "blocks" in message:
        blocks = message['blocks']
    if text and not blocks:
        app.client.chat_postMessage(channel=channel_id, text=str(text))
    if blocks:
        app.client.chat_postMessage(channel=channel_id, blocks=blocks)

    return


def send_notification():
    """
    Send Slack Message
    """
    app.client.chat_postMessage(channel="C04PLC4SQDP", text="Test Send Notifications.")
    args = demisto.args()
    message = args.get('message', '')
    to = args.get('to')
    original_channel = args.get('channel')
    channel_id = demisto.args().get('channel_id', '')
    group = args.get('group')
    message_type = args.get('messageType', '')  # From server
    original_message = args.get('originalMessage', '')  # From server
    entry = args.get('entry')
    ignore_add_url = args.get('ignoreAddURL', False) or args.get('IgnoreAddURL', False)
    thread_id = args.get('threadID', '')
    severity = args.get('severity')  # From server
    blocks = args.get('blocks', [])
    entry_object = args.get('entryObject')  # From server, available from demisto v6.1 and above
    entitlement = ''

    """
    blocks = ""
    channel_id = ""
    text = ""
    message = json.loads(json.dumps(json_str))
    if "channel" in message:
        channel_id = message['channel']
    if "text" in message:
        text = message['text']
    if "blocks" in message:
        blocks = message['blocks']
    if text and not blocks:
        app.client.chat_postMessage(channel=channel_id, text=str(text))
    if blocks:
        app.client.chat_postMessage(channel=channel_id, blocks=blocks)


    if message and not blocks:
        json_string = {"channel": channel_id, "text": message}
        slack_send(json_string)
    if blocks:
        json_string = {"channel": channel_id, "blocks": blocks}
        slack_send(json_string)
    """


def get_user_name(user_id):
    try:
        response = app.client.users_info(user=user_id)
        return response['user']['name']
    except Exception as e:
        demisto.error(f"The Loop has failed to run {str(e)}")


def human_date_time(date_time_str):
    """
    print(date_time_str)
    time_zone = []
    # Get Date
    date_time = date_time_str.split("T")
    date_str = str(date_time[0])

    # Get Time
    if "-"  in date_time[1]:
        time_zone = date_time[1].split("-")
    elif "+" in date_time[1]:
        time_zone = date_time[1].split("+")

    print(time_zone)
    time_str = str(time_zone[0])

    # Get Time Zone
    get_zone = date_time[1].split(time_str)
    zone_str = str(get_zone[1])

    new_time = date_str + " " + time_str.split(".")[0] + " TZ= " + zone_str
    """

    return str(date_time_str)


def clean_urls(url_str):
    ret_str = ""
    i = 0
    val_list = url_str.split(",")
    for val in val_list:
        i = i + 1
        domain_str = val.split("|")
        ret_str = ret_str + domain_str[0].replace("<", "")
        if i < len(val_list):
            ret_str = ret_str + ","
    return ret_str


def clean_domains(dom_str):
    ret_str = ""
    i = 0
    val_list = dom_str.split(",")
    for val in val_list:
        i = i + 1
        if "|" in val:
            domain_str = val.split("|")
            ret_str = ret_str + domain_str[1].replace(">", "")
        if i < len(val_list):
            ret_str = ret_str + ","
    return ret_str


def clean_emails(email_str):
    ret_str = ""
    i = 0
    val_list = email_str.split(",")

    if val_list == -1:
        if "|" in val_list:
            domain_str = email_str.split("|")
            email_str = ret_str + domain_str[1].replace(">", "")
        if is_email(email_str):
            ret_str = email_str
    else:
        for val in val_list:
            i = i + 1
            if "|" in val:
                domain_str = val.split("|")
                ret_str = ret_str + domain_str[1].replace(">", "")
            if is_email(val):
                ret_str = val
            if i < len(val_list) and is_email(ret_str):
                ret_str = ret_str + ","
    return ret_str


def append_section(dict_obj, key, value):
    if key in dict_obj:
        if not isinstance(dict_obj[key], list):
            dict_obj[key] = [[dict_obj[key]]]

        dict_obj[key].append(value)
    else:
        dict_obj[key] = value
    return dict_obj


def create_command_menu(json_string):
    divider_dict = {
        "type": "divider"
    }

    for command in COMMAND_LIST:
        section_dict = {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Description:*"
                },
                {
                    "type": "mrkdwn",
                    "text": str(COMMAND_LIST[command]['description'])
                },
                {
                    "type": "plain_text",
                    "text": " "
                },
                {
                    "type": "plain_text",
                    "text": " "
                },
                {
                    "type": "mrkdwn",
                    "text": "*!" + str(COMMAND_LIST[command]['cmd']) + "*"
                },
                {
                    "type": "mrkdwn",
                    "text": " " + str(COMMAND_LIST[command]['args'])
                }
            ]
        }
        append_section(json_string, 'blocks', section_dict)
        append_section(json_string, 'blocks', divider_dict)
    return json_string


def return_dict(json_string):
    return json.loads(json_string)


def decode_string(my_string):
    my_string = my_string.replace("&amp;#x2F;", "/")
    my_string = my_string.replace("&amp;quot;", "\"")
    return my_string


def get_params(param_list):
    param_list = re.sub('\s*=\s*', "=", param_list)
    if "\u201d" in param_list:
        param_list = param_list.replace("\u201d", "\"")
    if "\u201c" in param_list:
        param_list = param_list.replace("\u201c", "\"")
    param_dict = dict(token.split('=') for token in shlex.split(param_list))
    return param_dict


# Validator functions

def is_email(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.fullmatch(regex, email):
        return True
    else:
        return False


def is_ip(ip):
    regex = "\d*.\d*\.\d*\.\d*"
    if re.fullmatch(regex, ip):
        return True

    else:
        return False


def is_sha256(sha256):
    regex = "[A-Fa-f0-9]{64}"
    if re.fullmatch(regex, sha256):
        return True
    else:
        return False


def is_mac(mac):
    regex = "([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
    if re.fullmatch(regex, mac):
        return True

    else:
        return False


def is_command(text_message):
    text_message = text_message.strip()
    if text_message[:1] == "!":
        return True
    else:
        return False


def is_valid_json(json_string):
    try:
        ret_dict = json.loads(json_string)
        return ret_dict
    except ValueError:
        pass
        return False


def check_key(dict_obj, key):
    if key in dict_obj.keys():
        return True
    else:
        return False


# Run Commands Function

def run_command(command_text, url, api_key, api_key_id, channel, user, bot_handle, channel_name, thread):
    xsoar_client = XSOARClient(url, api_key, api_key_id)
    command_text = command_text.strip().replace('!', '')
    command_line = command_text.split(" ")

    # Slack Command Run Method
    if command_line[0] == COMMAND_LIST["xsoar_health"]['cmd']:
        xsoar_val = xsoar_client.health
        if xsoar_val == 200:
            # return_val = "XSOAR is Up!"
            return_val = {"channel": channel, "text": "XSOAR is Up!"}
        else:
            # return_val = "XSOAR may not be Up. " + xsoar_val
            return_val = {"channel": channel, "text": "XSOAR may not be Up. " + xsoar_val}
        return return_val
    elif command_line[0] == COMMAND_LIST["block_mac"]['cmd']:
        command_line = command_text.strip().replace(COMMAND_LIST['block_mac']['cmd'] + " ", '')
        incident = get_params(command_line)
        incident_json = xsoar_client.create_incident("Blackhat MAC", "", "Block Mac " + incident['mac'],
                                                     SEVERITY_DICT['High'], "mac=" + incident['mac'] + "\nslack_handle="
                                                     + user + "\nbot_handle=" + bot_handle + "\nchannel_name="
                                                     + channel_name + "\nslack_channel=" + channel)
        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        json_string = {
            "channel": channel,
            "text": f"New Incident created by <@{user}>",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "New XSOAR Incident #" + incident_dict['id'],
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + incident_dict['type']
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Created by:*\n<@{user}>"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        }
        return json_string
    elif command_line[0] == COMMAND_LIST["block_ip"]['cmd']:
        command_line = command_text.strip().replace(COMMAND_LIST['block_ip']['cmd'] + " ", '')
        incident = get_params(command_line)
        incident_json = xsoar_client.create_incident("Blackhat IP", "", "Block IP " + incident['ip'],
                                                     SEVERITY_DICT['High'], "ip=" + incident['ip'] + "\nslack_handle="
                                                     + user + "\nbot_handle=" + bot_handle + "\nchannel_name="
                                                     + channel_name + "\nslack_channel=" + channel)
        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        json_string = {
            "channel": channel,
            "text": f"New Incident created by <@{user}>",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "New XSOAR Incident #" + incident_dict['id'],
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + incident_dict['type']
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Created by:*\n<@{user}>"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        }
        return json_string
    elif command_line[0] == COMMAND_LIST["qos_mac"]['cmd']:
        command_line = command_text.strip().replace(COMMAND_LIST['qos_mac']['cmd'] + " ", '')
        incident = get_params(command_line)
        incident_json = xsoar_client.create_incident("Blackhat Qos", "", "Qos Mac " + incident['mac'],
                                                     SEVERITY_DICT['Low'], "mac=" + incident['mac'] + "\nslack_handle="
                                                     + user + "\nbot_handle=" + bot_handle + "\nslack_channel="
                                                     + channel)
        incident_dict = return_dict(incident_json)
        incident_link = f"{xsoar_url}/Custom/caseinfoid/{str(incident_dict['id'])}"
        json_string = {
            "channel": channel,
            "text": f"New Incident created by <@{user}>",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "New XSOAR Incident #" + str(incident_dict['id']),
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + str(incident_dict['type'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Created by:*\n<@{user}>"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        }
        return json_string
    elif command_line[0] == COMMAND_LIST["wireless_client_lookup"]['cmd']:
        command_line = command_text.strip().replace(COMMAND_LIST["wireless_client_lookup"]["cmd"] + " ", '')
        incident = get_params(command_line)
        incident_details = ""
        if "mac" in incident:
            mac_list = clean_urls(incident['mac'])
            incident_details = incident_details + "mac=" + str(mac_list) + "\n"
        if "ip" in incident:
            ip_list = clean_urls(incident['ip'])
            incident_details = incident_details + "ip=" + str(ip_list) + "\n"

        incident_json = xsoar_client.create_incident("Blackhat-wireless-client-lookup", "", "Wireless Search "
                                                     + incident_details, SEVERITY_DICT['Low'], incident_details
                                                     + "\nslack_handle=" + user + "\nbot_handle=" + bot_handle
                                                     + "\nslack_channel=" + channel)
        incident_dict = return_dict(incident_json)
        incident_link = f"{xsoar_url}/Custom/caseinfoid/{str(incident_dict['id'])}"
        json_string = {
            "channel": channel,
            "text": f"New Incident created by <@{user}>",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "New XSOAR Incident #" + str(incident_dict['id']),
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + str(incident_dict['type'])
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Created by:*\n<@{user}>"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        }
        return json_string
    elif command_line[0] == COMMAND_LIST["firewall_request"]['cmd']:
        if len(command_line) > 2:
            command_line = command_text.strip().replace(COMMAND_LIST['firewall_request']['cmd'] + " ", '')
            incident = get_params(command_line)
            incident_json = xsoar_client.create_incident("Blackhat Firewall Request", "", "Black Hat Firewall Request "
                                                         + incident['option'], SEVERITY_DICT['Low'], "option="
                                                         + incident['option'] + "\nslack_handle=" + user
                                                         + "\nbot_handle=" + bot_handle + "\nslack_channel="
                                                         + channel + "\n\nDetails:\n" + incident['details'])
            incident_dict = return_dict(incident_json)
            incident_link = xsoar_url + "/Custom/caseinfoid/" + str(incident_dict['id'])
            json_string = {
                "channel": channel,
                "text": f"New Incident created by <@{user}>",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "New XSOAR Incident #" + str(incident_dict['id']),
                            "emoji": True
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": "*Type:*\n" + str(incident_dict['type'])
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Created by:*\n<@{user}>"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                            }
                        ]
                    },
                    {
                        "type": "actions",
                        "block_id": "actionblock789",
                        "elements": [
                            {
                                "type": "button",
                                "action_id": "openincident",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Open Incident"
                                },
                                "url": incident_link
                            }
                        ]
                    }
                ]
            }
            return json_string
        else:
            return {"channel": channel,
                    "text": "This command requires parameters. " + COMMAND_LIST['firewall_request']['args']}
            # return "This command requires parameters. " + COMMAND_LIST['firewall_request']['args']
    elif command_line[0] == COMMAND_LIST["check_ioc"]['cmd']:
        if len(command_line) > 1:
            indicator_set = False
            command_line = command_text.strip().replace(COMMAND_LIST['check_ioc']['cmd'] + " ", '')
            incident = get_params(command_line)
            incident_details = ""
            indicator_id = ""
            indicator_link = ""
            if "url" in incident:
                url_list = clean_urls(incident['url'])
                incident_details = incident_details + "url=" + str(url_list) + "\n"
                indicator_set = True
            if "domain" in incident:
                dom_list = clean_domains(incident['domain'])
                incident_details = incident_details + "domain=" + str(dom_list) + "\n"
                indicator_set = True
            if "ip" in incident:
                incident_details = incident_details + "ip=" + str(incident['ip']) + "\n"
                indicator_set = True
            if "email" in incident:
                email_list = clean_emails(incident['email'])
                incident_details = incident_details + str(email_list) + "\n"
                indicator_set = True
            if "rep" in incident:
                incident_details = incident_details + "reputation=" + str(incident['rep']) + "\n"
                if not check_key(SCORE_DICT, incident['rep']):
                    return {"channel": channel,
                            "text": "Reputation is case sensitive. " + COMMAND_LIST['check_ioc']['args']}
                    # return "Reputation is case sensitive. " + COMMAND_LIST['check_ioc']['args']

            if incident_details and indicator_set:
                incident_json = xsoar_client.create_incident("Blackhat IOC Check", "", "Enrich IOC "
                                                             + incident_details[0:20], SEVERITY_DICT['Low'],
                                                             incident_details + "slack_handle=" + user
                                                             + "\nslack_thread=" + thread + "\nbot_handle="
                                                             + bot_handle + "\nchannel_name=" + channel_name
                                                             + "\nslack_channel=" + channel)
                if len(str(incident_json)) > 0:
                    incident_dict = return_dict(incident_json)
                    incident_link = f"{xsoar_url}/Custom/caseinfoid/{str(incident_dict['id'])}"
                    json_string = {
                        "channel": channel,
                        "text": f"New Incident created by <@{user}>",
                        "blocks": [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Executing New XSOAR Incident #" + incident_dict['id'],
                                    "emoji": True
                                }
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": "*Type:*\n" + incident_dict['type']
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Created by:*\n<@{user}>"
                                    }
                                ]
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": "<" + incident_link + "| Incident #" + incident_dict[
                                            'id'] + " " + command_text + ">"
                                    }
                                ]
                            },
                            {
                                "type": "actions",
                                "block_id": "actionblock789",
                                "elements": [
                                    {
                                        "type": "button",
                                        "action_id": "openincident",
                                        "text": {
                                            "type": "plain_text",
                                            "text": "Open Incident"
                                        },
                                        "url": incident_link
                                    }
                                ]
                            }
                        ]
                    }
                else:
                    # json_string = "No Data"
                    json_string = {"channel": channel, "text": "No Data"}
            else:
                # json_string = "Invalid IOC.  You need an IOC"
                json_string = json_string = {"channel": channel, "text": "Invalid IOC.  You need an IOC"}
            return json_string

        else:
            # return "This command requires parameters. " + COMMAND_LIST['check_ioc']['args']
            return {"channel": channel,
                    "text": "This command requires parameters. " + COMMAND_LIST['check_ioc']['args']}
    elif command_line[0] == COMMAND_LIST["my_incidents"]['cmd']:
        search_str = {
            "filter": {
                "query": "-status:closed -category:job details:*slack_handle=" + user + "*"
            }
        }
        incident_json = xsoar_client.search_incident(search_str)
        incident_dict = return_dict(incident_json)
        return_str = ""

        for incident in incident_dict['data']:
            incident_link = "#" + incident['id'] + " - " + incident['name'].strip() + "\n*Status:* " + incident[
                'runStatus'] + "\n" + xsoar_url + "/Custom/caseinfoid/" + str(incident['id']) + "\n"
            return_str = return_str + incident_link

        return_str = {"channel": channel, "text": return_str}
        return return_str
    elif command_line[0] == COMMAND_LIST["xsoar_invite"]['cmd']:
        command_line = command_text.strip().replace(COMMAND_LIST['xsoar_invite']['cmd'] + " ", '')
        incident = get_params(command_line)
        incident_details = ""
        if "email" in incident:
            email_list = clean_emails(incident['email'])
            incident_details = incident_details + "email=" + email_list + "\n"
        incident_json = xsoar_client.create_incident("Blackhat XSOAR Invite", "", "XSOAR Invite "
                                                     + incident_details[0:20], SEVERITY_DICT['Low'], incident_details
                                                     + "slack_handle=" + user + "\nbot_handle=" + bot_handle
                                                     + "\nslack_channel=" + channel)
        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        json_string = {
            "channel": channel,
            "text": f"New Incident created by <@{user}>",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "New XSOAR Incident #" + incident_dict['id'],
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + incident_dict['type']
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Created by:*\n<@{user}>"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        }
        return json_string
    elif command_line[0] == "help":
        json_string = {
            "channel": channel,
            "text": f"List of Commands",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "List of Commands\n",
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Command:*"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Parameters:*"
                        }
                    ]
                },
                {
                    "type": "divider"
                }
            ]
        }
        json_string = create_command_menu(json_string)
        return json_string
    else:
        # return "Command Not Found!"
        return {"channel": channel, "text": "Command Not Found!"}


#######################
# Slack Event Section
#######################

@app.event("app_home_opened")
def update_home_tab(client: WebClient, event: dict, logger):
    """
    Event handler for 'app_home_opened' event.

    This function updates the home tab with a welcome message when the app home is opened.
    """
    user_id = event["user"]
    try:
        client.views_publish(
            user_id=user_id,
            view={
                "type": "home",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "Welcome to *SlackBot*! :wave:\n\nUnveiling the untold, "
                                    "one story at a time. Work in progress .."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "*Features*"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":microphone: *Voice to Text*:\nSlackBot can transcribe your voice notes "
                                    "into text using the Whisper ASR system."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speech_balloon: *Text-Based AI Chat*:\nSlackBot uses OpenAI's GPT-3 model "
                                    "to comprehend the context and generate a response."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speaker: *Text to Voice*:\nSlackBot converts the generated text response "
                                    "into voice using the Eleven Labs Text-to-Speech service, providing a "
                                    "voice-enabled conversational experience."
                        }
                    }
                ]
            }
        )
    except SlackApiError as e:
        logger.error(f"Error updating home tab for user {user_id}: {e}")


@app.event("team_join")
def ask_for_introduction(event, say):
    user_id = event['user']
    text = f"Welcome to the team, <@{user_id}>!"
    say(text=text)


@app.event("message")
def handle_message_events(body, logger):
    logger.info(body)


@app.event("app_mention")
def handle_app_mention(body, say):
    if check_key(body['event'], 'user'):
        user = body['event']['user']
    else:
        user = body['event']['bot_id']
    text = body['event']['text']
    channel = body['event']['channel']
    bot_handle = body['authorizations'][0]['user_id']
    text = text.replace(f"<@{bot_handle}>", "")  # Remove the bot handle from
    channel_info = app.client.conversations_info(channel=channel)
    channel_name = channel_info['channel']['name']
    thread = body['event']['ts']

    # print('Bot = ' + bot_handle + ' Channel=' + channel + ' Text=' + text + ' from User=' + user)
    # print(botpress_ready)

    if is_command(text):
        json_string = {"channel": channel, "text": "Your wish is my command!"}
        slack_send(json_string)
        command_response = run_command(text, XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID, channel, user, bot_handle,
                                       channel_name,
                                       thread)
        if command_response:
            slack_send(command_response)
        else:
            json_string = {"channel": channel, "text": "No Text in Response to channel=" + channel_name}
            slack_send(json_string)
            # app.client.chat_postMessage(channel=channel, text="No Text in Response to channel=" + channel_name)

    elif "thread_ts" in str(body):
        xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
        user_messages = []
        thread_ts = body['event']['thread_ts']
        channel_id = body['event']['channel']
        channel_info = app.client.conversations_info(channel=channel_id)
        channel_name = channel_info['channel']['name']
        message_text = app.client.conversations_replies(channel=channel_id, ts=thread_ts)
        for message in message_text['messages']:
            if not message.get("subtype") and '@BlackHat Bot' not in message['text']:
                user_id = message['user']
                user_name = get_user_name(user_id)
                user_messages.append(
                    {
                        'user_id': user_id,
                        'user_name': user_name,
                        'timestamp': message['ts'],
                        'text': message['text']
                    }
                )
        mytext = "thread_id=" + thread_ts + "\nchannel_id=" + channel_id + "\nchannel_name=" + channel_name + "\nthread_messages=" + str(
            user_messages)
        xsoar_client.create_incident("Blackhat Monitored Thread", "",
                                     f"Blackhat Monitored Thread Incident, Thread: {thread_ts}"
                                     , SEVERITY_DICT['Low'], mytext)

    else:
        # app.client.chat_postMessage(channel=channel, text="Hi there.\n  If you need help use the !help command.")
        json_string = {"channel": channel, "text": "Hi there.\n  If you need help use the /menu command."}
        say(json_string)


#######################
# Slack Command Section
#######################

@app.command("/xsoar-health")
def handle_xsoar_health_command(ack, body):
    ack()
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
    webhook = WebhookClient(body.get("response_url"))
    xsoar_val = xsoar_client.health
    if xsoar_val == 200:
        message = "XSOAR is Up!"
        webhook.send(text=message)
    else:
        message = "XSOAR may not be Up. " + xsoar_val
        webhook.send(text=message)


@app.command("/my-incidents")
def handle_my_incidents_command(ack, body, say):
    ack()
    user_id = body['user_id']  # Extracting the user ID from the body
    webhook = WebhookClient(body.get("response_url"))
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
    search_str = {
        "filter": {
            "query": "-status:closed -category:job details:*slack_handle=" + user_id + "*"
        }
    }
    incident_json = xsoar_client.search_incident(search_str)

    incident_dict = return_dict(incident_json)
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Your Open Incidents"
            }
        },
        {
            "type": "divider"
        }
    ]

    if incident_dict['data']:
        for incident in incident_dict['data']:
            incident_link = f"<{xsoar_url}/Custom/caseinfoid/{incident['id']}|Case #{incident['id']} - {incident['name'].strip()}> *Status:* {incident['runStatus']}"
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": incident_link
                }
            })
    else:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "You have no cases. Check that your slack handle is in the XSOAR incident details."
            }
        })
    webhook.send(blocks=blocks)


@app.command("/check-ioc")
def handle_check_ioc(ack, body):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    ioc_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Check IOC",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "IOC Type"
            },
            "accessory": {
                "type": "static_select",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select an type",
                    "emoji": True
                },
                "options": [
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "SHA256",
                            "emoji": True
                        },
                        "value": "sha256"
                    }, {
                        "text": {
                            "type": "plain_text",
                            "text": "IP Address",
                            "emoji": True
                        },
                        "value": "ip"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "URL",
                            "emoji": True
                        },
                        "value": "url"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Email",
                            "emoji": True
                        },
                        "value": "email"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Domain",
                            "emoji": True
                        },
                        "value": "domain"
                    }
                ],
                "action_id": "check_ioc_select_ioc_type"
            }
        }
    ]
    webhook.send(blocks=ioc_block)


@app.command("/check-ip")
def handle_check_ip_command(ack, body):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    ip_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Check An IP Address",
                "emoji": True
            }
        },
        {
            "type": "input",
            "block_id": "ip_input_block",
            "element": {
                "type": "plain_text_input",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Enter the IP address to check",
                },
                "action_id": "ip_input_action"
            },
            "label": {
                "type": "plain_text",
                "text": "IP Address",
                "emoji": True
            }
        },
        {
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Check IP",
                    "emoji": True
                },
                "value": "check_ip",
                "action_id": "check_ip_submit_action"  # Action
            }]
        }
    ]
    webhook.send(blocks=ip_block)


@app.command("/check-mac")
def handle_check_mac_command(ack, body):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    mac_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Check A MAC Address",
                "emoji": True
            }
        },
        {
            "type": "input",
            "block_id": "mac_address_input",
            "element": {
                "type": "plain_text_input",
                "action_id": "mac_input"
            },
            "label": {
                "type": "plain_text",
                "text": "Enter MAC Address:",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Click the button to check the MAC address."
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Check MAC Address",
                    "emoji": True
                },
                "value": "check_mac",
                "action_id": "submit_mac_check"
            }
        }
    ]
    webhook.send(blocks=mac_block)


@app.command("/create-incident")
def handle_create_incident(ack, body, say, user_id, channel_name, channel_id):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    params_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Incident Request Details"
            }
        },
        {
            "type": "input",
            "element": {
                "type": "static_select",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select an item"
                },
                "options": [
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Incident Response"
                        },
                        "value": "ir"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Hunting"
                        },
                        "value": "hunting"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Blank"
                        },
                        "value": "blank"
                    }
                ]
            },
            "label": {
                "type": "plain_text",
                "text": "Type:"
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "multiline": True,
                "action_id": "plain_text_input-action"
            },
            "label": {
                "type": "plain_text",
                "text": "Details:"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": " "
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Submit"
                },
                "value": "click_me_123",
                "action_id": "incident-type-action"
            }
        }
    ]
    webhook.send(blocks=params_block)


@app.command("/firewall-request")
def handle_firewall_request_command(ack, body, say, user_id, channel_name, channel_id):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    params_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Request Details"
            }
        },
        {
            "type": "input",
            "element": {
                "type": "static_select",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select a tag"
                },
                "options": [
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "reg-server-abusers"
                        },
                        "value": "reg-server-abusers"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "infected"
                        },
                        "value": "infected"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "illegal-activity"
                        },
                        "value": "illegal-activity"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "qos-bad-user"
                        },
                        "value": "qos-bad-user"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "cryptomining"
                        },
                        "value": "cryptomining"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "plain-text-creds"
                        },
                        "value": "plain-text-creds"
                    }
                ]
            },
            "label": {
                "type": "plain_text",
                "text": "Tag:"
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "multiline": True,
                "action_id": "plain_text_input-action"
            },
            "label": {
                "type": "plain_text",
                "text": "Input IP or Mac:"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": " "
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Submit"
                },
                "value": "click_me_123",
                "action_id": "firewall-request-details-action"
            }
        }
    ]
    webhook.send(blocks=params_block)


@app.command("/block-ip")
def handle_block_ip_command(ack, body, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))

    channel_name = body['channel_name']
    channel = body['channel_id']
    user_id = body['user_id']
    ip_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Block An IP",
                "emoji": True
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "action_id": "plain_text_input-action"
            },
            "label": {
                "type": "plain_text",
                "text": " ",
                "emoji": True
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "multiline": True,
                "action_id": "plain_text_input-action"
            },
            "label": {
                "type": "plain_text",
                "text": "Details:"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": " "
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Block Me",
                    "emoji": True
                },
                "value": "click_me_123",
                "action_id": "block-ip-action"
            }
        }
    ]
    webhook.send(blocks=ip_block)


@app.command("/xsoar-invite")
def handle_xsoar_invite_command(ack, body, say):
    ack()
    channel_name = body['channel_name']
    channel = body['channel_id']
    user_id = body['user_id']
    webhook = WebhookClient(body.get("response_url"))
    email_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "Email to Invite To XSOAR",
                "emoji": True
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "action_id": "plain_text_input-action"
            },
            "label": {
                "type": "plain_text",
                "text": " ",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": " "
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Invite Me",
                    "emoji": True
                },
                "value": "click_me_123",
                "action_id": "xsoar-invite-email-action"
            }
        }
    ]
    webhook.send(blocks=email_block)



@app.command("/menu")
def handle_menu_command(ack, body, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "List of Slash Commands\n"
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Usage:*"
                },
                {
                    "type": "mrkdwn",
                    "text": "*Parameters:*"
                }
            ]
        },
        {
            "type": "divider"
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/xsoar-health*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Check That XSOAR is Up."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/check-ioc*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Check That XSOAR is Up."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/check-mac*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Get Details about a MAC Address"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/check-ip*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Get Details about a IP Address"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/block-ip*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Block an IP at the Firewall."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/firewall-request*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Send a request to the firewall team, report an outage, a threat, make a change, or anything else."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/xsoar-invite*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Get a login to XSOAR and include your slack ID to track your incidents."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/my-incidents*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Get a list of all your open incidents."
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*/ask*"
                },
                {
                    "type": "mrkdwn",
                    "text": "Ask Black Hat Bot anything. i.e. 'What are the latest APTs in cyber security?'"
                }
            ]
        }
    ]
    webhook.send(blocks=blocks)


#######################
# Slack Actions Section
#######################

# Check IOC Actions
@app.action("check_ioc_select_ioc_type")
def handle_ioc_type_action(body, ack, say, user_id, channel_name, channel_id):
    ack()
    ioc_type = ""
    webhook = WebhookClient(body.get("response_url"))
    webhook.send(text="One Moment ...")
    selected_option = body['actions'][0]['selected_option']['value']

    if selected_option == "url":
        ioc_type = "URL"
    if selected_option == "ip":
        ioc_type = "IP"
    if selected_option == "domain":
        ioc_type = "Domain"
    if selected_option == "email":
        ioc_type = "Email"
    if selected_option == "sha256":
        ioc_type = "File SHA256"

    ioc_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": ioc_type + " IOC Information",
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Minimum Reputation To Return"
            },
            "accessory": {
                "type": "static_select",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Reputation Search Level",
                    "emoji": True
                },
                "initial_option": {
                    "text": {
                        "type": "plain_text",
                        "text": "Suspicious",
                        "emoji": True
                    },
                    "value": "Suspicious"
                },
                "options": [
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Unknown",
                            "emoji": True
                        },
                        "value": "Unknown"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Good",
                            "emoji": True
                        },
                        "value": "Good"
                    }, {
                        "text": {
                            "type": "plain_text",
                            "text": "Suspicious",
                            "emoji": True
                        },
                        "value": "Suspicious"
                    },
                    {
                        "text": {
                            "type": "plain_text",
                            "text": "Bad",
                            "emoji": True
                        },
                        "value": "Bad"
                    }
                ],
                "action_id": "ioc_rep_selection"  # Action
            }
        },
        {
            "type": "input",
            "element": {
                "type": "plain_text_input",
                "action_id": "ioc_details_input"  # Action
            },
            "label": {
                "type": "plain_text",
                "text": ioc_type,
                "emoji": True
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": " "
            },
            "accessory": {
                "type": "button",
                "text": {
                    "type": "plain_text",
                    "text": "Submit " + ioc_type,
                    "emoji": True
                },
                "value": "submit_ioc_check",
                "action_id": "submit_ioc_check_action"  # Action
            }
        }
    ]

    if ioc_type != "":
        webhook.send(blocks=ioc_block)


@app.action("ioc_rep_selection")
def handle_ioc_rep_selection(body, ack, say, user_id, channel_id):
    ack()


@app.action("submit_ioc_check_action")
def handle_check_ioc_click_actions(body, ack, say):
    ack()
    ioc_valid = False
    ioc_type = ""
    reputation = ""
    ioc_str = ""
    incident_details = ""
    incident_json = ""
    incident_block = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']
    webhook = WebhookClient(body.get("response_url"))

    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)

    if "'plain_text'" in str(body):
        results = re.search(r"'plain_text',\s+'text':\s'Submit\s(.*?)'", str(body))
        ioc_type = results.group(1)

    if "'selected_option'" in str(body):
        results = re.search(r"selected_option':\s+{.*?},\s+'value': '(.*?)'", str(body))
        reputation = results.group(1)
    else:
        reputation = "Suspicious"

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value': '(.*?)'", str(body))
        ioc_str = results.group(1)

    if ioc_type == "File SHA256":
        if is_sha256(ioc_str):
            ioc_valid = True
        incident_details = incident_details + "sha256=" + str(ioc_str) + "\n"
    if ioc_type == "URL":
        url_list = clean_urls(ioc_str)
        ioc_valid = True
        incident_details = incident_details + "url=" + str(url_list) + "\n"
    if ioc_type == "Domain":
        dom_list = clean_domains(ioc_str)
        ioc_valid = True
        incident_details = incident_details + "domain=" + str(dom_list) + "\n"
    if ioc_type == "IP":
        ioc_valid = True
        incident_details = incident_details + "ip=" + str(ioc_str) + "\n"
    if ioc_type == "Email":
        ioc_valid = True
        email_list = clean_emails(ioc_str)
        incident_details = incident_details + str(email_list) + "\n"
    if reputation:
        incident_details = incident_details + "reputation=" + str(reputation) + "\n"

    command_text = "check_ioc " + ioc_type + "=" + ioc_str

    mytext = incident_details + "slack_handle=" + user_id + "\nslack_thread=" + str(
        thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel

    if ioc_valid:
        if reputation and ioc_str and ioc_type:
            incident_json = xsoar_client.create_incident("Blackhat IOC Check", "", "Enrich IOC " + ioc_str[0:20],
                                                         SEVERITY_DICT['Low'], mytext)

        if len(str(incident_json)) > 0:
            incident_dict = return_dict(incident_json)
            incident_link = xsoar_url + "/Custom/caseinfoid/" + str(incident_dict['id'])
            incident_block = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "Executing New XSOAR Incident #" + incident_dict['id'],
                        "emoji": True
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*Type:*\n" + incident_dict['type']
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*Created by:*\n<@" + user_id + ">"
                        }
                    ]
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                        },
                        {
                            "type": "mrkdwn",
                            "text": "<" + incident_link + "| Incident #" + incident_dict[
                                'id'] + " " + command_text + ">"
                        }
                    ]
                },
                {
                    "type": "actions",
                    "block_id": "actionblock789",
                    "elements": [
                        {
                            "type": "button",
                            "action_id": "openincident",
                            "text": {
                                "type": "plain_text",
                                "text": "Open Incident"
                            },
                            "url": incident_link
                        }
                    ]
                }
            ]
        else:
            incident_block = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "No Data",
                        "emoji": True
                    }
                }
            ]
    else:
        incident_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "This " + ioc_str + " is not Valid",
                    "emoji": True
                }
            }
        ]

    webhook.send(blocks=incident_block)


@app.action("check_ip_submit_action")
def handle_check_ip_action(body, ack, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    ip_str = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']
    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value': '(.*?)'", str(body))
        ip_str = results.group(1)
    ip_valid = is_ip(ip_str)
    if ip_valid:
        webhook.send(text="Looking up IP Address ...")
        xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
        incident_details = "ip=" + ip_str + "\n"
        mytext = incident_details + "slack_handle=" + user_id + "\nslack_thread=" + str(
            thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel
        incident_json = xsoar_client.create_incident("BlackHat IP Lookup", "", "Check IP " + ip_str,
                                                     SEVERITY_DICT['Low'], mytext)
        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        check_ip_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "New XSOAR Incident #" + incident_dict['id'],
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Type:*\n" + incident_dict['type']
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Created by:*\n<@" + user_id + ">"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Status:*\n Asking Approval"
                    }
                ]
            },
            {
                "type": "actions",
                "block_id": "actionblock789",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "openincident",
                        "text": {
                            "type": "plain_text",
                            "text": "Open Incident"
                        },
                        "url": incident_link
                    }
                ]
            }
        ]
    else:
        check_ip_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "This IP " + ip_str + " is not Valid",
                    "emoji": True
                }
            }
        ]
    webhook.send(blocks=check_ip_block)


@app.action("submit_mac_check")
def handle_check_mac_action(body, ack, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))

    mac_str = ""
    incident_details = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value': '(.*?)'", str(body))
        mac_str = results.group(1)

    mac_valid = is_mac(mac_str)

    if mac_valid:
        webhook.send(text="Looking up MAC Address ...")
        xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
        incident_details = "mac=" + mac_str + "\n"
        mytext = incident_details + "slack_handle=" + user_id + "\nslack_thread=" + str(
            thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel
        incident_json = xsoar_client.create_incident("BlackHat Mac Lookup", "", "Check MAC " + mac_str,
                                                     SEVERITY_DICT['Low'], mytext)

        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        check_mac_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "New XSOAR Incident #" + incident_dict['id'],
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Type:*\n" + incident_dict['type']
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Created by:*\n<@" + user_id + ">"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Status:*\n Asking Approval"
                    }
                ]
            },
            {
                "type": "actions",
                "block_id": "actionblock789",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "openincident",
                        "text": {
                            "type": "plain_text",
                            "text": "Open Incident"
                        },
                        "url": incident_link
                    }
                ]
            }
        ]
    else:
        check_mac_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "This MAC " + mac_str + " is not Valid",
                    "emoji": True
                }
            }
        ]
    webhook.send(blocks=check_mac_block)


@app.action("xsoar-invite-email-action")
def handle_xsoar_invite_email_action(body, ack, say):
    ack()
    email_str = ""
    incident_details = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value': '(.*?)'", str(body))
        email_str = results.group(1)

    webhook = WebhookClient(body.get("response_url"))

    email_valid = is_email(email_str)

    if email_valid:
        incident_details = "email=" + email_str + "\n"
        mytext = incident_details + "slack_handle=" + user_id + "\nslack_thread=" + str(
            thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel
        incident_json = xsoar_client.create_incident("Blackhat XSOAR Invite", "", "XSOAR Invite " + email_str[0:20],
                                                     SEVERITY_DICT['Low'], mytext)

        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        invite_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "New XSOAR Incident #" + incident_dict['id'],
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Type:*\n" + incident_dict['type']
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Created by:*\n<@" + user_id + ">"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                    }
                ]
            },
            {
                "type": "actions",
                "block_id": "actionblock789",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "openincident",
                        "text": {
                            "type": "plain_text",
                            "text": "Open Incident"
                        },
                        "url": incident_link
                    }
                ]
            }
        ]
    else:
        invite_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "This Email is not Valid",
                    "emoji": True
                }
            }
        ]

    webhook.send(blocks=invite_block)


@app.action("block-ip-action")
def handle_block_ip_action(body, ack, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))

    ip4_str = ""
    incident_details = ""
    details = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value': '(.*?)'}},.*'plain_text_input',\s+'value': '(.*?)'",
                            str(body))
        ip4_str = results.group(1)
        details = results.group(2)

    ip_valid = is_ip(ip4_str)

    if ip_valid:
        xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
        incident_details = "ip=" + ip4_str + "\n"
        mytext = incident_details + "slack_handle=" + user_id + "\nslack_thread=" + str(
            thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel + "\n\nMessage:\n" + details + "\n---\n"
        incident_json = xsoar_client.create_incident("Blackhat IP", "", "Block IP " + ip4_str, SEVERITY_DICT['High'],
                                                     mytext)

        incident_dict = return_dict(incident_json)
        incident_id = str(incident_dict['id']).strip()
        incident_link = xsoar_url + "/Custom/caseinfoid/" + incident_id
        ip_block_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "New XSOAR Incident #" + incident_dict['id'],
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*Type:*\n" + incident_dict['type']
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Created by:*\n<@" + user_id + ">"
                    }
                ]
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Status:*\n Asking Approval"
                    }
                ]
            },
            {
                "type": "actions",
                "block_id": "actionblock789",
                "elements": [
                    {
                        "type": "button",
                        "action_id": "openincident",
                        "text": {
                            "type": "plain_text",
                            "text": "Open Incident"
                        },
                        "url": incident_link
                    }
                ]
            }
        ]
    else:
        ip_block_block = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "This IP is not Valid",
                    "emoji": True
                }
            }
        ]

    webhook.send(blocks=ip_block_block)


@app.action("firewall-request-details-action")
def handle_firewall_request_details_action(body, ack, say, user_id, channel_name, channel_id):
    ack()
    incident_details = ""
    incident_json = ""
    incident_block = ""
    channel_name = body['channel']['name']
    channel = body['channel']['id']
    user_id = body['user']['id']
    thread = body['container']['message_ts']

    webhook = WebhookClient(body.get("response_url"))
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)

    # Grab the Option and Details
    if "'plain_text" in str(body):
        results = re.search(r"'plain_text',\s+'text':\s+'(.*?)'", str(body))
        tag = results.group(1)

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value':\s+'(.*?)'", str(body))
        to_be_tagged = results.group(1)
    incident_details = "Tag:" + tag + "\nToBeTagged:" + to_be_tagged
    mytext = incident_details + "\nslack_handle=" + user_id + "\nslack_thread=" + str(
        thread) + "\nchannel_name=" + channel_name + "\nslack_channel=" + channel

    # Create a Firewall Request in XSOAR
    incident_json = xsoar_client.create_incident("Blackhat Firewall Request", "",
                                                 f"Blackhat Firewall Request Created by {user_id}"
                                                 , SEVERITY_DICT['Low'], mytext)

    incident_dict = return_dict(incident_json)
    incident_link = xsoar_url + "/Custom/caseinfoid/" + str(incident_dict['id'])
    response_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "New XSOAR Incident #" + str(incident_dict['id']),
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Type:*\n" + str(incident_dict['type'])
                },
                {
                    "type": "mrkdwn",
                    "text": "*Created by:*\n<@" + user_id + ">"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                }
            ]
        },
        {
            "type": "actions",
            "block_id": "actionblock789",
            "elements": [
                {
                    "type": "button",
                    "action_id": "openincident",
                    "text": {
                        "type": "plain_text",
                        "text": "Open Incident"
                    },
                    "url": incident_link
                }
            ]
        }
    ]
    webhook.send(blocks=response_block)


@app.action("incident-type-action")
def handle_check_incident_type_actions(body, ack, say, user_id, channel_name, channel_id):
    ack()

    webhook = WebhookClient(body.get("response_url"))
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)

    # Grab the Option and Details
    if "'plain_text" in str(body):
        results = re.search(r"'plain_text',\s+'text':\s+'(.*?)'", str(body))
        option = results.group(1)

    if "'plain_text_input'" in str(body):
        results = re.search(r"'plain_text_input',\s+'value':\s+'(.*?)'", str(body))
        details = results.group(1)

    if option == "Incident Response":
        incident_json = xsoar_client.create_incident("Blackhat Incident Response", "",
                                                     f"Blackhat Incident Response Created by {user_id}"
                                                     , SEVERITY_DICT['Low'], "\nslack_handle=" + user_id
                                                     + "\nslack_channel=" + channel_id + "\n\nDetails:\n" + details)
    elif option == "Hunting":
        incident_json = xsoar_client.create_incident("Blackhat Hunting", "",
                                                     f"Blackhat Hunting Request Created by {user_id}"
                                                     , SEVERITY_DICT['Low'], "\nslack_handle=" + user_id
                                                     + "\nslack_channel=" + channel_id + "\n\nDetails:\n" + details)
    else:
        incident_json = xsoar_client.create_incident("Blackhat Blank", "",
                                                     f"Blackhat Blank Request Created by {user_id}"
                                                     , SEVERITY_DICT['Low'], "\nslack_handle=" + user_id
                                                     + "\nslack_channel=" + channel_id + "\n\nDetails:\n" + details)

    incident_dict = return_dict(incident_json)
    incident_link = xsoar_url + "/Custom/caseinfoid/" + str(incident_dict['id'])
    response_block = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "New XSOAR Incident #" + str(incident_dict['id']),
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*Type:*\n" + str(incident_dict['type'])
                },
                {
                    "type": "mrkdwn",
                    "text": "*Created by:*\n<@" + user_id + ">"
                }
            ]
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": "*When:*\n" + human_date_time(str(incident_dict["created"]))
                }
            ]
        },
        {
            "type": "actions",
            "block_id": "actionblock789",
            "elements": [
                {
                    "type": "button",
                    "action_id": "openincident",
                    "text": {
                        "type": "plain_text",
                        "text": "Open Incident"
                    },
                    "url": incident_link
                }
            ]
        }
    ]
    webhook.send(blocks=response_block)


@app.action("command_outputs_static_select-action")
def command_outputs_static_select(ack, body, say):
    ack()
    webhook = WebhookClient(body.get("response_url"))
    selected_options = body['actions'][0]['selected_options']
    outputs = []
    for option in selected_options:
        outputs.append(option.get('value'))
    command_name = body['actions'][0]['block_id'].split('_outputs')[0]
    if soar_client.up:
        command_arguments = Decorator.command_arguments_blocks(command_reader=command_reader, command_name=command_name,
                                                               command_outputs=outputs)
        webhook.send(blocks=command_arguments)
    else:
        # say(f"SOAR is not reachable, please get in touch with SOC team!")
        json_string = {"channel": channel, "text": f"SOAR is not reachable, please get in touch with SOC team!"}
        slack_send(json_string)


@app.action("submit_command_arguments")
def handle_command_line(ack, body, say):
    result = ""
    ack()
    webhook = WebhookClient(body.get("response_url"))
    if check_key(body.get('user'), 'id'):
        user = body['user']['id']
    else:
        user = body['message']['bot_id']
    command_line = Decorator.payload_to_command_line(body)
    webhook.send(text='Executing Command: ' + str(command_line[0]))
    if command_line[1] == ['-'] or "WarRoomOutput" in command_line[1]:
        results = soar_client.execute_command(command=command_line[0], return_type='wr',
                                              output_path=command_line[1])
        results = results[0].contents

    else:
        results = soar_client.execute_command(command=command_line[0], return_type='context',
                                              output_path=command_line[1])

        formatted_pairs = [f"• *{k}*:{v}" for k, v in zip(command_line[1], results)]
        results = '\n'.join(formatted_pairs)

    blocks = [{
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"The command results for *{command_line[0]}* :robot_face: :"
        }
    }, {"type": "divider"}, {
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": results
        }
    }]
    webhook.send(blocks=blocks)


@app.action("approve_button")
def handle_approve_request(ack, say):
    ack()
    say("Request approved!")


@app.action("openincident")
def handle_approve_request(ack, say):
    ack()
    say("Opening Incident!")


@app.action("actionblock789")
def handle_approve_request(ack, say):
    ack()
    say("Opening Incident!")


@app.action("rejection_button")
def handle_approve_request(ack, say):
    ack()
    say("Request rejected!")


@app.action("slot-input-button")
def handle_botpress_slot_text_input(body, ack, say):
    ack()
    xsoar_client = XSOARClient(XSOAR_API_URL, XSOAR_API_KEY, XSOAR_API_KEY_ID)
    if check_key(body.get('user'), 'id'):
        user = body['user']['id']
    else:
        user = body['message']['bot_id']
    channel = body['channel']['id']
    bot_handle = body['message']['bot_id']
    channel_info = app.client.conversations_info(channel=channel)
    channel_name = channel_info['channel']['name']
    thread = body['message']['ts']
    slot_input = body['state']['values']['slot_input_block']['botpress-slot-text-input']['value']
    say(f"Hi there, <@{user}>!\n  If you need help use the /menu command.")


def test_module():
    demisto.results('ok')


def long_running_main():
    """
    Starts the long running thread.
    """
    try:
        asyncio.run(SocketModeHandler(app, APP_TOKEN).start(), debug=True)
    except Exception as e:
        demisto.error(f"The Loop has failed to run {str(e)}")
    finally:
        loop = asyncio.get_running_loop()
        try:
            loop.stop()
            loop.close()
        except Exception as e_:
            demisto.error(f'Failed to gracefully close the loop - {e_}')


def dependencies_check_function():
    demisto.results('test')


def main() -> None:
    """
    Main
    """
    global app, EXTENSIVE_LOGGING, debug_start, verify_ssl, xsoar_client

    if SSL_VERIFY == False:
        urllib3.disable_warnings()

    commands = {
        'test-module': test_module,
        'long-running-execution': long_running_main
    }

    command_name: str = demisto.command()

    try:
        demisto.info(f'{command_name} started.')
        command_func = commands[command_name]
        support_multithreading()
        command_func()
    except Exception as e:
        return_error(str(e))
    finally:
        demisto.info(f'{command_name} completed.')  # type: ignore


''' ENTRY POINT '''
if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
