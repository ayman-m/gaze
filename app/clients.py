import os
import json
import uuid
import requests
import openai
import whisper

from pydub import AudioSegment
from openai.error import RateLimitError


class SlackWebClient:
    def __init__(self, api_key: str):
        if api_key is None:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.headers = {
                    'Authorization': 'Bearer %s' % api_key
        }

    def download_audio_file(self, download_url: str):
        file_name = str(uuid.uuid4()) + ".mp4"
        response = requests.get(download_url, headers=self.headers,
                                stream=True)
        with open(file_name, 'wb') as audio_file:
            audio_file.write(response.content)
        return file_name


class OpenAIClient:
    def __init__(self, api_key: str):
        if api_key is None:
            raise ValueError("api_key is required")
        self.openai_client = openai
        openai.api_key = api_key

    def chat(self, message: str):
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
    def __init__(self, api_url: str, api_key: str, voice_id: str, model_id: str, optimize_streaming_latency: int = 0):
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
    def __init__(self, model_id: str = "base"):
        self.model_id = model_id

    def transcribe_audio(self, audio_file: str, audio_format: str):
        file_name = str(uuid.uuid4()) + ".wav"
        audio = AudioSegment.from_file(audio_file, format=audio_format)
        audio.export(file_name, format="wav")
        model = whisper.load_model(self.model_id)
        result = model.transcribe(file_name)
        os.remove(file_name)
        return result['text']

