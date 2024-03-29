# Gaze: Your Voice-Enabled Slack Bot

Gaze is a conversational Slack bot with advanced capabilities in both voice recognition and generation, as well as complex text-based conversation. Gaze is capable of:

![alt text](img/intro.png "Intro")

- Transcribing voice notes into text with the help of the Whisper ASR (Automatic Speech Recognition) system.
- Detecting the user intent if the user wants to enrich indicators or execute general automations using Cortex XSOAR.
- Conducting a complex conversation based on context with the help of OpenAI's GPT-3 model.
- Converting text into voice with the Eleven Labs Text-to-Speech service, which offers a voice-enabled conversational experience.

## How It Works

![alt text](img/messageflow.png "Message Flow")

At its core, Gaze makes use of several sophisticated technologies and libraries. The code provided above outlines the initialization and event handling for Gaze's operation within a Slack workspace. Here is an outline of what it does:

- It first loads environment variables from a `.env` file, these are essential for accessing APIs and resources.
- Various clients are initialized, including the Slack app, OpenAI for text-based conversation, Eleven Labs for text-to-speech, the Whisper client for transcribing audio, a command embedding for processing automation requests, and a SOAR client for security tasks.
- Next, the bot registers several event handlers to respond to different events in Slack. These events include opening the app home, receiving a message in a direct message (DM) channel, and selecting a command from a suggested command menu.

When Gaze receives a direct message:

- If the message contains an audio file, Gaze uses the Whisper ASR system to transcribe the audio into text.
- If the message is a text, Gaze uses the OpenAI GPT-3 model to generate a context-aware response. Gaze is capable of recognizing certain patterns in the text that suggest the user wants to automate a task or request an enrichment of security indicators. In these cases, Gaze can provide appropriate responses or actions.
- Gaze then converts the text response into voice using the Eleven Labs Text-to-Speech service and sends the voice message back to the user.

## Libraries and Services

![alt text](img/architecture.png "Architecture")

Gaze makes use of several external libraries and services:

- [**Slack SDK**](https://slack.dev/python-slack-sdk/): The official Slack SDK for Python. It is used to interact with the Slack API.
- [**OpenAI GPT-3**](https://openai.com/research/gpt-3/): A state-of-the-art language model that uses machine learning to generate human-like text.
- [**Eleven Labs**](https://www.11-labs.com/): A service that provides high-quality Text-to-Speech capabilities.
- [**Whisper ASR**](https://openai.com/research/whisper/): An automatic speech recognition system developed by OpenAI.
- [**Command Embedding**](https://en.wikipedia.org/wiki/Word_embedding): A technique to transform textual information into vectors.
- [**SOAR Client**](https://en.wikipedia.org/wiki/Security_Orchestration,_Automation,_and_Response): A software solution that allows organizations to collect data about security threats and responds to low-level security events without human assistance.

## Configuration

Gaze is designed to be deployed in a Slack workspace. It requires the configuration of several environment variables in a `.env` file. This file should include the Slack bot token, the OpenAI API key, the Eleven Labs API key and URL, the path to the command embedding data, and the SOAR API key and URL.

## Usage

Once deployed, users can interact with Gaze in a Slack workspace. Gaze responds to direct messages (

DMs), and commands (ask, automate, enrich and intent) and can process both text and voice inputs. For voice inputs, users can simply attach audio files to their DMs. For automation or security enrichment requests, Gaze recognizes specific patterns in the text and provides appropriate responses.

## Disclaimer

Gaze is a conversational AI bot that is still in progress and as such, it should not be used as the primary source for critical processes or decision making. It's recommended to use this AI responsibly and under proper supervision.
