# Gaze - A Conversational AI for Slack

Gaze is a Slack bot that uses several deep learning models to facilitate a voice-enabled conversational experience, by transcribing audio, understand the context, generate a relevant response, and convert the response into voice.

## Features

- **Voice to Text**: Gaze can transcribe your voice notes into text using the OpenAI Whisper.
- **Text-Based AI Chat**: Gaze uses OpenAI's GPT-3 model to comprehend the context and generate a response.
- **Text to Voice**: Gaze converts the generated text response into a cloned voice using the Eleven Labs Text-to-Speech service, providing a voice-enabled conversational experience, a clone of my own voice was used in the demo.

## Installation

### Prerequisites
To run Gaze, you need the following:

- Python 3.7 or later
- Slack App with bot token
- OpenAI API key for GPT-3
- Eleven Labs API key, URL, Voice ID, and Model ID
- ASR system (Whisper) with Model ID

### Steps
1. Clone the repository
    ```
    git clone https://github.com/username/gaze.git
    ```
2. Enter the directory
    ```
    cd gaze
    ```
3. Install the dependencies
    ```
    pip install -r requirements.txt
    ```
4. Rename the `.env.example` file to `.env` and fill in the required variables.
5. Run the application
    ```
    python main.py
    ```

## Usage

To interact with Gaze, you can send a direct message containing either text or an audio file.

- If you send an audio file, Gaze will transcribe it, process the text with OpenAI's chat model, and send the response as an audio file.
- If you send a text message, Gaze will directly process it with OpenAI's chat model and send the response as an audio file.

---

Note: Please replace the `https://github.com/username/gaze.git` placeholder with the actual URL of your repository.

This README provides a brief overview of your application, its features, and instructions on how to install and use it. However, you might want to enhance it further depending on your specific needs, like adding more sections (FAQs, Contributing, License, Screenshots, etc.), improving the formatting, and so on.