import os
from dotenv import load_dotenv
from slack_bolt.adapter.socket_mode import SocketModeHandler
from pathlib import Path

from app.bot import app

# Load the Slack App Token from the environment variables
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")

if __name__ == "__main__":
    # Load environment variables from .env file if it exists
    env_path = Path('.') / '.env'
    if env_path.exists():
        load_dotenv()

    # Attempt to start the SocketModeHandler with the Slack App and Token
    try:
        handler = SocketModeHandler(app, SLACK_APP_TOKEN)
        handler.start()
    except Exception as e:
        # Catch any exceptions and raise a descriptive error
        raise Exception(f"Failed to run the Slack Bot : {str(e)}")
