import os
import json
import ast
from pathlib import Path
from dotenv import load_dotenv
from automate import SOARClient
from helper import Decorator


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import demisto_client
# Load environment variables from .env file if it exists
env_path = Path('.') / '.env'
if env_path.exists():
    load_dotenv()


SOAR_URL = os.getenv("SOAR_URL")
SOAR_API_KEY = os.getenv("SOAR_API_KEY")
SOAR_VERIFY_SSL = os.getenv("SOAR_VERIFY_SSL")

soar_client = SOARClient(url=SOAR_URL, api_key=SOAR_API_KEY, verify_ssl=False)


indicators = soar_client.execute_command(command='!extractIndicators text="test 1.1.1.1,2.2.2.2 https://www.yahoo.com"',
                                         output_path=["ExtractedIndicators"], return_type='context')
indicator_object = ast.literal_eval(indicators[0])


for key, values in indicator_object.items():
    enriched_indicator = soar_client.enrich_indicator(indicator={key: values}, return_type='context')
    print (enriched_indicator, type(enriched_indicator))
    blocks = Decorator.enrichment_blocks(dict_list=enriched_indicator, header="Indicator Information")
    print (blocks)

