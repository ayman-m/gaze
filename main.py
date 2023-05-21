import os
import hupper
from dotenv import load_dotenv
from slack_bolt.adapter.socket_mode import SocketModeHandler
from pathlib import Path

from app.bot import app

SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")

if __name__ == "__main__":
    env_path = Path('.') / '.env'
    if env_path.exists():
        load_dotenv()
    try:
        handler = SocketModeHandler(app, SLACK_APP_TOKEN)
        handler.start()
    except Exception as e:
        raise Exception(f"Failed to get run the Slack Bot : str({e})")

