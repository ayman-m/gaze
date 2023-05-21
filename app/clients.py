import os
import json
import uuid
import requests
import openai
import whisper

from pydub import AudioSegment
from openai.error import RateLimitError


class SlackWebClient:
    """
    A client for interacting with the Slack Web API.

    This client supports operations such as downloading files from Slack.

    Attributes:
        api_key (str): The API key used for authenticating with the Slack API.
        headers (dict): The headers used in API requests, including the Authorization header.
    """

    def __init__(self, api_key: str):
        """
        Initializes a new instance of the SlackWebClient class.

        Args:
            api_key (str): The API key used for authenticating with the Slack API.

        Raises:
            ValueError: If the `api_key` argument is None.
        """
        if api_key is None:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.headers = {
            'Authorization': 'Bearer %s' % api_key
        }

    def download_audio_file(self, download_url: str):
        """
        Downloads an audio file from Slack and saves it locally as an .mp4 file.

        Args:
            download_url (str): The URL from which to download the audio file.

        Returns:
            str: The name of the locally saved audio file.

        Notes:
            The audio file is saved in the current directory.
            The file name is a randomly generated UUID.
        """
        file_name = str(uuid.uuid4()) + ".mp4"
        response = requests.get(download_url, headers=self.headers, stream=True)
        with open(file_name, 'wb') as audio_file:
            audio_file.write(response.content)
        return file_name


class OpenAIClient:
    """
    A client for interacting with the OpenAI API.

    This client supports operations such as generating responses to messages using the GPT-3.5 Turbo model.

    Attributes:
        openai_client (OpenAI): The OpenAI client used to communicate with the API.
    """

    def __init__(self, api_key: str):
        """
        Initializes a new instance of the OpenAIClient class.

        Args:
            api_key (str): The API key used for authenticating with the OpenAI API.

        Raises:
            ValueError: If the `api_key` argument is None.
        """
        if api_key is None:
            raise ValueError("api_key is required")
        self.openai_client = openai
        openai.api_key = api_key

    def chat(self, message: str):
        """
        Generates a response to the given message using the GPT-3.5 Turbo model.

        Args:
            message (str): The message to generate a response to.

        Returns:
            str: The generated response.

        Notes:
            If the OpenAI API is currently overloaded with requests, this method returns a fallback response.
        """
        try:
            openai_response = self.openai_client.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": message}
                ]
            )
            return openai_response.get('choices')[0]['message']['content']
        except RateLimitError:
            return "OpenAI is currently busy, try to use our menu. "


class ElevenLabsClient:
    """
    A client for interacting with the Eleven Labs API.

    This client supports operations such as converting text to speech using a specified voice and model.

    Attributes:
        api_key (str): The API key used for authenticating with the Eleven Labs API.
        api_url (str): The URL of the Eleven Labs API.
        voice_id (str): The ID of the voice to use for text-to-speech conversion.
        model_id (str): The ID of the model to use for text-to-speech conversion.
        optimize_streaming_latency (int): The optimization level for streaming latency.
        headers (dict): The headers to include in API requests.
    """

    def __init__(self, api_url: str, api_key: str, voice_id: str, model_id: str, optimize_streaming_latency: int = 0):
        """
        Initializes a new instance of the ElevenLabsClient class.

        Args:
            api_url (str): The URL of the Eleven Labs API.
            api_key (str): The API key used for authenticating with the Eleven Labs API.
            voice_id (str): The ID of the voice to use for text-to-speech conversion.
            model_id (str): The ID of the model to use for text-to-speech conversion.
            optimize_streaming_latency (int): The optimization level for streaming latency. Defaults to 0.

        Raises:
            ValueError: If any of the `api_key`, `api_url`, `voice_id`, or `model_id` arguments are None.
        """
        if api_key is None:
            raise ValueError("api_key is required")
        self.api_key = api_key
        if api_url is None:
            raise ValueError("api_url is required")
        self.api_url = api_url
        if voice_id is None:
            raise ValueError("voice_id is required")
        self.voice_id = voice_id
        if model_id is None:
            raise ValueError("model_id is required")
        self.model_id = model_id
        self.optimize_streaming_latency = optimize_streaming_latency
        self.headers = {
            'xi-api-key': api_key,
            'Content-Type': 'application/json',
            'Accept': 'audio/mpeg'
        }

    def text_to_speech(self, text: str):
        """
        Converts the given text to speech using the specified voice and model.

        The resulting speech is saved as an MP3 file.

        Args:
            text (str): The text to convert to speech.

        Returns:
            str: The name of the file containing the resulting speech.
        """
        file_name = str(uuid.uuid4()) + ".mp3"
        payload = json.dumps({
            "text": text,
            "model_id": self.model_id
        })
        url = self.api_url+'/text-to-speech/'+self.voice_id+"?optimize_streaming_latency="\
            + str(self.optimize_streaming_latency)
        response = requests.request("POST", url,
                                    headers=self.headers, data=payload)
        with open(file_name, 'wb') as out_file:
            out_file.write(response.content)
        return file_name


class WhisperClient:
    """
    A client for interacting with the Whisper ASR (Automatic Speech Recognition) model.

    This client supports operations such as transcribing audio files.

    Attributes:
        model_id (str): The ID of the Whisper ASR model to use for transcription.
    """

    def __init__(self, model_id: str = "base"):
        """
        Initializes a new instance of the WhisperClient class.

        Args:
            model_id (str): The ID of the Whisper ASR model to use for transcription. Defaults to "base".
        """
        self.model_id = model_id

    def transcribe_audio(self, audio_file: str, audio_format: str):
        """
        Transcribes the given audio file using the specified Whisper ASR model.

        The audio file is first converted to a WAV file, which is then transcribed.
        The WAV file is deleted after transcription.

        Args:
            audio_file (str): The name of the audio file to transcribe.
            audio_format (str): The format of the audio file.

        Returns:
            str: The transcription of the audio file.
        """
        file_name = str(uuid.uuid4()) + ".wav"
        audio = AudioSegment.from_file(audio_file, format=audio_format)
        audio.export(file_name, format="wav")
        model = whisper.load_model(self.model_id)
        result = model.transcribe(file_name)
        os.remove(file_name)
        return result['text']
