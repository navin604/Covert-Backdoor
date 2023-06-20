import asyncio
from evdev import InputDevice, categorize, ecodes

dev = InputDevice('link')

async def helper(dev):
    async for ev in dev.async_read_loop():
        print(repr(ev))



if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(helper(dev))
