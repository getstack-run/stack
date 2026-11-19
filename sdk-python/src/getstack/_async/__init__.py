"""Async service modules (full parity with sync).

Each AsyncXxxService mirrors the sync XxxService surface exactly:
same method names, same kwargs, same return types. The only
difference is `async def` and `await self._client.x` instead of
`self._client.x`. The Mission ergonomic gets an AsyncMission
context manager that uses asyncio.create_task + asyncio.sleep
instead of threading.Timer.

Import via AsyncStack:
    from getstack import AsyncStack
    async with AsyncStack(api_key="sk_live_...") as stack:
        agents = await stack.agents.list()
"""
