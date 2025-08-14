import requests

llm_url = 'http://genai-alb-15e3e8d-397362491.ap-southeast-1.elb.amazonaws.com/api/chat/completions'
token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjNkZDlkZmJiLTJmZTUtNGE5MC05ZWJjLWU0OTRlNGVhZjRmNyJ9.Mk1Jk79XwO-132DhCRy8QVnUBiQDu31N7AzA9lPD49c'
model = 'google_genai.gemini-1.5-pro'

def chat_with_file(url, token, model, query, file_id):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': query}],
        'files': [{'type': 'file', 'id': file_id}]
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()

def chat_completion(url, token, model, query):
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': model,
        'messages': [{'role': 'user', 'content': query}]
    }
    response = requests.post(url, headers=headers, json=payload)
    return response.json()

print("Testing chat completion")
print(chat_completion(llm_url, token, model, "What is the capital of France?"))
