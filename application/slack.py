"""
https://github.com/M507
"""

from config import *
from common import *


def slack_notify(text, WEBHOOK_URL = WEBHOOK_URL):
    try:
        slack_data = {'text': text}

        response = requests.post(
            WEBHOOK_URL, data=json.dumps(slack_data),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            raise ValueError(
                'Request to slack returned an error %s, the response is:\n%s'
                % (response.status_code, response.text)
            )
        return 0
    except Exception as e:
        print("Error: slack_notify()")
        print(str(e))
        return 1