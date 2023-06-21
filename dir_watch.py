import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

file = "ran.txt"

class EventHandler(FileSystemEventHandler):
    def on_created(self, event):
        print(event)
        file = event.src_path.split("/")[-1]
        print(f"File created: {file}")
        print("--------------------------------------------------")


def main():
    if sys.argv[1] == "watch":
        event_handler = EventHandler()
        observer = Observer()
        observer.schedule(event_handler, "./test", recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            observer.stop()
            observer.join()
    else:
        pass

if __name__ == "__main__":
    main()