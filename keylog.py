import asyncio
from evdev import InputDevice, ecodes



async def keylog(dev):
    async for event in dev.async_read_loop():
        if event.type == ecodes.EV_KEY and event.code == 1:
            print(repr(event))



if __name__ == "__main__":
    device = InputDevice('link')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(keylog(device))
