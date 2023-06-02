import requests
import uuid
import openai


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
            print (message)
            openai_response = self.openai_client.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "Your name is Gaze, you are a helpful assistant to help the user "
                                                  "automate some tasks, the user will questions about IT and "
                                                  "cyber security topics and the use may ask you to automate some IT "
                                                  "and SOC related activities, if you think the user question or "
                                                  "message is not relevant to IT or cyber security inform the "
                                                  "user that the question is not related to his or her job "
                                                  "example of automation tasks could be:"
                                                  " 'I want to get user information from active directory. or tell "
                                                  "more about specific attack campaign , or open a case for me."
                                                  " Always start you reply with 'Automation Request' "
                                                  "if you think the user is asking how "
                                                  "to automate something or requesting some action to be taken, if the"
                                                  "user is asking for information about an IP Address , Domain Name,"
                                                  "CVE,or a URL, always start your reply with 'Enrichment Request' and"
                                                  "try to extract the entity that the user is asking about"},
                    {"role": "user", "content": message}
                ]
            )
            return openai_response.get('choices')[0]['message']['content']
        except Exception as e:
            print (e)
            return "Our Smart Bot is currently busy, try to use our menu. "

