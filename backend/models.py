from pydantic_ai.agent import Agent, RunContext
from pydantic_ai.models.google import GoogleModel, GoogleProvider
import os
import asyncio
from dotenv import load_dotenv
# Load env
load_dotenv()

provider = GoogleProvider(api_key=os.getenv('GOOGLE_API_KEY'))
model = GoogleModel('gemini-1.5-flash', provider=provider)
