"""Example: a morning summary that grew. Reads a client export and posts to a chat webhook.
Placeholder values only. Expected triggers: sensitive data, acts on other systems, stored credentials."""
import json
import urllib.request

api_token = "placeholder-not-a-real-token"

with open("/shared/clients/flows_today.csv") as fh:
    lines = fh.read().splitlines()

body = json.dumps({"text": "%d client flow rows today" % len(lines)}).encode()
req = urllib.request.Request("https://chat.example.invalid/hook", data=body,
                             headers={"Authorization": "Bearer " + api_token})
urllib.request.urlopen(req)
