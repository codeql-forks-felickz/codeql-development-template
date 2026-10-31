import os
import uuid
import datetime
import subprocess
import urllib.parse


def lambda_handler(event, context):  # $ Source[py/command-line-injection]
    key = event['Records'][0]['s3']['object']['key']
    key = urllib.parse.unquote_plus(urllib.parse.unquote(key))
    download_path = f'/tmp/{str(uuid.uuid4())}.txt'
    date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

    # Reduced from the AI scan finding: only `date` and `download_path` reach the
    # shell, neither of which is derived from the Lambda event, so no alert.
    os.system(f'echo -e "\t\tDate: {date}" >> ' + download_path)

    # Event-derived data in the shell command is reported.
    os.system(f'echo "Order: {key}" >> ' + download_path)  # $ Alert[py/command-line-injection]

    # Safe: argument list, no shell.
    subprocess.run(["cp", key, download_path])
