import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from main_api import app

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
