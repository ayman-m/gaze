import os
import re
import warnings
import ast
import pinecone
import pandas as pd
import requests
from slack_bolt import App
from pathlib import Path
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from numba import NumbaDeprecationWarning, NumbaPendingDeprecationWarning
from urllib3.exceptions import InsecureRequestWarning
from app.chat import SlackWebClient, OpenAIClient
from app.talk import WhisperClient, ElevenLabsClient
from app.automate import LocalTextEmbedding, PineConeTextEmbedding, SOARClient
from app.helper import Decorator

# Ignore the Numba and FP16 related warnings
warnings.filterwarnings("ignore", category=NumbaDeprecationWarning)
warnings.filterwarnings("ignore", category=NumbaPendingDeprecationWarning)
warnings.filterwarnings("ignore", "FP16 is not supported on CPU; using FP32 instead")
warnings.filterwarnings('ignore', category=InsecureRequestWarning)

# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

# Retrieve environment variables
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")

ELEVEN_LABS_URL = os.environ.get("ELEVEN_LABS_URL")
ELEVEN_LABS_KEY = os.environ.get("ELEVEN_LABS_KEY")
ELEVEN_LABS_VOICE_ID = os.environ.get("ELEVEN_LABS_VOICE_ID")
ELEVEN_LABS_MODEL_ID = os.environ.get("ELEVEN_LABS_MODEL_ID")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

EMBEDDING_INDEX_LOCATION = os.getenv("EMBEDDING_INDEX_LOCATION")

INTENT_EMBEDDING_PATH = os.getenv("INTENT_EMBEDDING_PATH")
INTENT_EMBEDDING_MODEL = os.getenv("INTENT_EMBEDDING_MODEL")
COMMAND_EMBEDDING_PATH = os.getenv("COMMAND_EMBEDDING_PATH")
COMMAND_EMBEDDING_MODEL = os.getenv("COMMAND_EMBEDDING_MODEL")
PINECONE_KEY = os.getenv("PINECONE_KEY")
PINECONE_ENV = os.getenv("PINECONE_ENV")
PINECONE_COMMAND_INDEX = os.getenv("PINECONE_COMMAND_INDEX")

SOAR_VERIFY_SSL = os.getenv("SOAR_VERIFY_SSL")

SOAR_URL = os.getenv("SOAR_URL")
SOAR_API_KEY = os.getenv("SOAR_API_KEY")
COMMAND_ARGUMENTS_FILE = os.getenv("COMMAND_ARGUMENTS_FILE")

# Initialize the clients
app = App(token=SLACK_BOT_TOKEN)
openai_client = OpenAIClient(api_key=OPENAI_API_KEY)
eleven_labs_client = ElevenLabsClient(api_key=ELEVEN_LABS_KEY, api_url=ELEVEN_LABS_URL,
                                      voice_id=ELEVEN_LABS_VOICE_ID, model_id=ELEVEN_LABS_MODEL_ID)
slack_web_client = SlackWebClient(api_key=SLACK_BOT_TOKEN)
whisper_client = WhisperClient()

if EMBEDDING_INDEX_LOCATION == 'Local':
    command_embedding = LocalTextEmbedding(text_embedding_path=COMMAND_EMBEDDING_PATH,
                                      embedding_model=COMMAND_EMBEDDING_MODEL)
elif EMBEDDING_INDEX_LOCATION == 'PineCone':
    pinecone.init(api_key=PINECONE_KEY, environment=PINECONE_ENV)
    command_index = pinecone.Index(index_name='enabled-commands-index')
    command_embedding = PineConeTextEmbedding(embedding_index=command_index,
                                              embedding_model=COMMAND_EMBEDDING_MODEL)
intent_embedding = LocalTextEmbedding(text_embedding_path=INTENT_EMBEDDING_PATH, embedding_model=INTENT_EMBEDDING_MODEL)
command_reader = pd.read_csv(COMMAND_ARGUMENTS_FILE)
soar_client = SOARClient(url=SOAR_URL, api_key=SOAR_API_KEY, verify_ssl=False)


# Event Functions

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
                            "text": "Welcome to *Gaze*! :wave:\n\nUnveiling the untold, "
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
                            "text": ":microphone: *Voice to Text*:\nGaze can transcribe your voice notes "
                                    "into text using the Whisper ASR system."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speech_balloon: *Text-Based AI Chat*:\nGaze uses OpenAI's GPT-3 model "
                                    "to comprehend the context and generate a response."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speaker: *Text to Voice*:\nGaze converts the generated text response "
                                    "into voice using the Eleven Labs Text-to-Speech service, providing a "
                                    "voice-enabled conversational experience."
                        }
                    },
                    {"type": "divider"},
                    {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": "*Commands*:\n\n:bulb: *Enrich*: This command helps you with indicator enrichment.\n\n:arrow_forward: *Automate*: Use this command to start an automated workflow or process.\n\n:question: *Ask*: This command lets you ask questions related to security and IT operations.\n\n:dart: *Intent*: Use this command to test my intent detection capability."
                            }
                    }
                ]
            }
        )
    except SlackApiError as e:
        logger.error(f"Error updating home tab for user {user_id}: {e}")


@app.event("message")
def handle_message(body, say):
    """
    This function handles messages in direct messages (DM) channels.
    If the message contains files, it assumes they are audio files, downloads and transcribes them.
    If the message is text, it directly processes it.
    In both cases, the transcribed or original text is processed with OpenAI's chat model,
    and the generated response is converted to speech using Eleven Labs' service and sent back to the user.

    Parameters:
    body (dict): The event body.
    say (function): Function to send a message back to the Slack channel.
    """
    """
    Event handler for 'message' event.

    This function handles messages in direct messages (DM) channels.
    If the message contains files, it assumes they are audio files, downloads and transcribes them.
    If the message is text, it directly processes it.
    In both cases, the transcribed or original text is processed with OpenAI's chat model,
    and the generated response is converted to speech using Eleven Labs' service and sent back to the user.

    Parameters:
    body (dict): The event body.
    say (function): Function to send a message back to the Slack channel.
    """
    channel_type = body.get("event", {}).get("channel_type", "")
    channel = body.get("event", {}).get("channel", "")
    if channel_type == "im":
        if 'files' in body.get("event", {}):
            transcript = []
            for file in body.get("event", {}).get('files', []):
                audio_file = slack_web_client.download_audio_file(file['url_private_download'])
                result = whisper_client.transcribe_audio(audio_file=audio_file, audio_format='mp4')
                os.remove(audio_file)
                transcript.append(result)
            text = '\n'.join(transcript)
        else:
            text = body.get("event", {}).get("text", "")
        intent_vector = intent_embedding.get_embedding_vectors(text)
        user_intent = intent_embedding.get_similarities(intent_vector, 1)['name'].iloc[0]
        similarity_score = intent_embedding.get_similarities(intent_vector, 1)['similarities'].iloc[0]

        if user_intent == 'ioc-enrichment' and float(similarity_score) > 0.8:
            say("Working on it, will come back shortly!.")
            indicators = soar_client.execute_command(command=f'!extractIndicators text="{text}"',
                                                     output_path=["ExtractedIndicators"], return_type='context')
            for indicator in indicators:
                indicator_object = ast.literal_eval(indicator)
                for key, values in indicator_object.items():
                    enriched_indicator = soar_client.enrich_indicator(indicator={key: values}, return_type='context')
                    print(enriched_indicator, type(enriched_indicator))
                    section_blocks = Decorator.enrichment_blocks(dict_list=enriched_indicator,
                                                                 header="Indicator Information")
                    say({
                        "blocks": section_blocks
                    })

        elif user_intent == 'automation' and float(similarity_score) > 0.8:
            say("That looks like an automation request, let me find out what we have in our automation library, "
                " will come back shortly!.")
            question_vector = command_embedding.get_embedding_vectors(text)
            top_similar_rows = command_embedding.get_similarities(question_vector, 4)
            choices = Decorator.generate_choices(top_similar_rows)
            section_block = [{
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "We have found the following similar commands to your automation question:"
                },
                "accessory": {
                    "type": "static_select",
                    "placeholder": {
                        "type": "plain_text",
                        "text": "Select a command"
                    },
                    "options": choices,
                    "initial_option": choices[0],
                    "action_id": "suggested-commands-menu-action"
                }
            }]

            say({
                "blocks": section_block
            })

        else:
            openai_response = openai_client.chat(text)
            audio_file = eleven_labs_client.text_to_speech(openai_response)
            app.client.files_upload_v2(channel=channel, file=audio_file, filename="Bot Response")
            os.remove(audio_file)
            response = {
                "response_type": "in_channel",
                "text": openai_response
            }
            say(response)


@app.command("/automate")
def handle_automate_command(ack, body, say):
    ack()
    text = body.get("text", "")
    question_vector = command_embedding.get_embedding_vectors(text)
    top_similar_rows = command_embedding.get_similarities(question_vector, 4)
    choices = Decorator.generate_choices(top_similar_rows)
    section_block = [{
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "We have found the following similar commands to your automation question:"
        },
        "accessory": {
            "type": "static_select",
            "placeholder": {
                "type": "plain_text",
                "text": "Select a command"
            },
            "options": choices,
            "initial_option": choices[0],
            "action_id": "suggested-commands-menu-action"
        }
    }]
    say({
        "blocks": section_block
    })


@app.command("/enrich")
def handle_enrich_command(ack, body, say):
    ack()
    say("Working on your request, will come back shortly!.")
    text = body.get("text", "")
    indicators = soar_client.execute_command(command=f'!extractIndicators text="{text}"',
                                             output_path=["ExtractedIndicators"], return_type='context')
    for indicator in indicators:
        indicator_object = ast.literal_eval(indicator)
        for key, values in indicator_object.items():
            enriched_indicator = soar_client.enrich_indicator(indicator={key: values}, return_type='context')
            print(enriched_indicator, type(enriched_indicator))
            section_blocks = Decorator.enrichment_blocks(dict_list=enriched_indicator,
                                                         header="Indicator Information")
            say({
                "blocks": section_blocks
            })


@app.command("/ask")
def handle_ask_command(ack, body, say):
    ack()
    text = body.get("text", "")
    channel = body.get("channel_id", "")
    openai_response = openai_client.chat(text)
    audio_file = eleven_labs_client.text_to_speech(openai_response)
    app.client.files_upload_v2(channel=channel, file=audio_file, filename="Bot Response")
    os.remove(audio_file)
    response = {
        "response_type": "in_channel",
        "text": openai_response
    }
    say(response)


@app.command("/intent")
def handle_intent_command(ack, body, say):
    ack()
    text = body.get("text", "")
    blocks = [
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Intent prediction for *'{text}'*"
            }
        }
    ]
    intent_vector = intent_embedding.get_embedding_vectors(text)
    intents = intent_embedding.get_similarities(intent_vector, 3)
    for index, row in intents.iterrows():
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{row['name']}*, Score:*{row['similarities']}*\n"
            }
        })
    say({
        "blocks": blocks
    })


@app.action("suggested-commands-menu-action")
def handle_suggested_commands_menu_actions(body, ack, say):
    """
    This function handles the actions performed in the suggested commands menu.
    It checks whether the SOAR client is up and then executes the command selected by the user.

    Parameters:
    body : dict
        The payload received from the Slack interaction which contains the user and the selected command.

    ack : function
        An acknowledgment function to respond to the Slack interaction.

    say : function
        A function to post messages to the Slack channel.

    Returns:
    None
    """
    ack()
    selected_option = body['actions'][0]['selected_option']['value']
    command_outputs = Decorator.command_outputs_blocks(command_reader=command_reader, command_name=selected_option)
    if soar_client.up:
        say({
            "blocks": command_outputs[1]
        })
    else:
        say(f"SOAR is not reachable, please get in touch with SOC team!")


@app.action("command_outputs_static_select-action")
def command_outputs_static_select(ack, body, say):
    selected_options = body['actions'][0]['selected_options']
    outputs = []
    for option in selected_options:
        outputs.append(option.get('value'))
    command_name = body['actions'][0]['block_id'].split('_outputs')[0]

    if soar_client.up:
        command_arguments = Decorator.command_arguments_blocks(command_reader=command_reader, command_name=command_name,
                                                               command_outputs=outputs)
        say({
            "blocks": command_arguments
        })
    else:
        say(f"SOAR is not reachable, please get in touch with SOC team!")
    ack()


@app.action("submit_command_arguments")
def handle_command_line(ack, body, say):
    result = ""
    ack()
    if Decorator.check_key(body.get('user'), 'id'):
        user = body['user']['id']
    else:
        user = body['message']['bot_id']
    command_line = Decorator.payload_to_command_line(body)

    say(f"Your wish is my command, <@{user}>!")
    say('Executing Command: ' + str(command_line[0]))
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

    say({
        "blocks": blocks
    })

