import requests
import json

API_KEY = "AIzaSyBPkKT5lczvRzwVS3B-dDyc_tPggJg3DxE"
url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={API_KEY}"

headers = {
    'Content-Type': 'application/json'
}

data = {
    "contents": [
        {
            "parts": [
                {"text": "Write me one sentence joke"}
            ]
        }
    ]
}

response = requests.post(url, headers=headers, data=json.dumps(data))

# Extracting and formatting the response
if response.status_code == 200:
    response_json = response.json()
    answer = response_json['candidates'][0]['content']['parts'][0]['text']
    print(answer)
else:
    print(f"Error: {response.status_code} - {response.text}")
