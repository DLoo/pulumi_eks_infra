curl -X POST http://genai-alb-15e3e8d-397362491.ap-southeast-1.elb.amazonaws.com/api/chat/completions \
-H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjNkZDlkZmJiLTJmZTUtNGE5MC05ZWJjLWU0OTRlNGVhZjRmNyJ9.Mk1Jk79XwO-132DhCRy8QVnUBiQDu31N7AzA9lPD49c" \
-H "Content-Type: application/json" \
-d '{
      "model": "google_genai.gemini-1.5-pro",
      "messages": [
        {
          "role": "user",
          "content": "Why is the sky blue?"
        }
      ]
    }'