import os
import warnings

from slack_bolt import App
from pathlib import Path
from dotenv import load_dotenv
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from numba import NumbaDeprecationWarning, NumbaPendingDeprecationWarning

# Ignore the Numba and FP16 related warnings
warnings.filterwarnings("ignore", category=NumbaDeprecationWarning)
warnings.filterwarnings("ignore", category=NumbaPendingDeprecationWarning)
warnings.filterwarnings("ignore", "FP16 is not supported on CPU; using FP32 instead")

from app.clients import SlackWebClient, OpenAIClient, ElevenLabsClient, WhisperClient

# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()

# Retrieve environment variables
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
ELEVEN_LABS_KEY = os.environ.get("ELEVEN_LABS_KEY")
ELEVEN_LABS_URL = os.environ.get("ELEVEN_LABS_URL")
ELEVEN_LABS_VOICE_ID = os.environ.get("ELEVEN_LABS_VOICE_ID")
ELEVEN_LABS_MODEL_ID = os.environ.get("ELEVEN_LABS_MODEL_ID")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize the App with SLACK_BOT_TOKEN
app = App(token=SLACK_BOT_TOKEN)

# Initialize the clients for various services
openai_client = OpenAIClient(api_key=OPENAI_API_KEY)
eleven_labs_client = ElevenLabsClient(api_key=ELEVEN_LABS_KEY, api_url=ELEVEN_LABS_URL,
                                      voice_id=ELEVEN_LABS_VOICE_ID, model_id=ELEVEN_LABS_MODEL_ID)
slack_web_client = SlackWebClient(api_key=SLACK_BOT_TOKEN)
whisper_client = WhisperClient()


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
                            "text": "Welcome to *Gaze*! :wave:\n\nUnveiling the untold, one story at a time. Work in progress .."
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
                            "text": ":microphone: *Voice to Text*:\nGaze can transcribe your voice notes into text using the Whisper ASR system."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speech_balloon: *Text-Based AI Chat*:\nGaze uses OpenAI's GPT-3 model to comprehend the context and generate a response."
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":speaker: *Text to Voice*:\nGaze converts the generated text response into voice using the Eleven Labs Text-to-Speech service, providing a voice-enabled conversational experience."
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
    # Check if the event is a direct message
    channel_type = body.get("event", {}).get("channel_type", "")
    channel = body.get("event", {}).get("channel", "")
    if channel_type == "im":
        # Check if the message contains files (assumed to be audio files)
        if 'files' in body.get("event", {}):
            transcript = []
            for file in body.get("event", {}).get('files', []):
                # Download the audio file
                audio_file = slack_web_client.download_audio_file(file['url_private_download'])
                # Transcribe the audio file
                result = whisper_client.transcribe_audio(audio_file=audio_file, audio_format='mp4')
                # Remove the downloaded file
                os.remove(audio_file)
                # Add the transcription to the list of transcriptions
                transcript.append(result)
            # Combine all transcriptions into one string
            text = '\n'.join(transcript)
        else:
            # If the message is text, get the text
            text = body.get("event", {}).get("text", "")
        # Process the text with OpenAI's chat model
        openai_response = openai_client.chat(text)
        # Convert the response to speech using Eleven Labs' service
        audio_file = eleven_labs_client.text_to_speech(openai_response)
        # Send the audio file back to the user
        app.client.files_upload_v2(channel=channel, file=audio_file, filename="Bot Response")
        # Remove the generated audio file
        os.remove(audio_file)
        # Send the OpenAI response as a text message
        say(openai_response)
