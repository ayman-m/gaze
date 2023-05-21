import os
import warnings

from slack_bolt import App
from pathlib import Path
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from numba import NumbaDeprecationWarning, NumbaPendingDeprecationWarning

warnings.filterwarnings("ignore", category=NumbaDeprecationWarning)
warnings.filterwarnings("ignore", category=NumbaPendingDeprecationWarning)
warnings.filterwarnings("ignore", "FP16 is not supported on CPU; using FP32 instead")

from app.clients import SlackWebClient, OpenAIClient, ElevenLabsClient, WhisperClient

env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
ELEVEN_LABS_KEY = os.environ.get("ELEVEN_LABS_KEY")
ELEVEN_LABS_URL = os.environ.get("ELEVEN_LABS_URL")
ELEVEN_LABS_VOICE_ID = os.environ.get("ELEVEN_LABS_VOICE_ID")
ELEVEN_LABS_MODEL_ID = os.environ.get("ELEVEN_LABS_MODEL_ID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

app = App(token=SLACK_BOT_TOKEN)
openai_client = OpenAIClient(api_key=OPENAI_API_KEY)
eleven_labs_client = ElevenLabsClient(api_key=ELEVEN_LABS_KEY, api_url=ELEVEN_LABS_URL, voice_id=ELEVEN_LABS_VOICE_ID,
                                      model_id=ELEVEN_LABS_MODEL_ID)
slack_web_client = SlackWebClient(api_key=SLACK_BOT_TOKEN)
whisper_client = WhisperClient()


# Helper Functions


def check_key(dict_obj, key):
    if key in dict_obj.keys():
        return True
    else:
        return False


@app.event("app_home_opened")
def update_home_tab(client: WebClient, event: dict, logger):
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
                            "text": "Welcome to *About Bot*! :wave:\n\nUnveiling the untold, one story at a time. Use the following features to interact with the bot:"
                        },
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Latest Stories"
                                },
                                "action_id": "latest_stories"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Search"
                                },
                                "action_id": "search_stories"
                            },
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Help"
                                },
                                "action_id": "help"
                            }
                        ]
                    }
                ]
            }
        )
    except SlackApiError as e:
        logger.error(f"Error updating home tab for user {user_id}: {e}")


@app.event("message")
def handle_message(body, say):
    channel_type = body.get("event", {}).get("channel_type", "")
    channel = body.get("event", {}).get("channel", "")
    if channel_type == "im":  # Direct Messages
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
        openai_response = openai_client.chat(text)
        audio_file = eleven_labs_client.text_to_speech(openai_response)
        app.client.files_upload_v2(channel=channel, file=audio_file, filename="Bot Response")
        os.remove(audio_file)
        say(openai_response)


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

    say(f"Hi there, <@{user}>!\n  If you need help use the !help command.")

# Bot Actions
