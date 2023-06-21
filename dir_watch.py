import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time

class EventHandler(FileSystemEventHandler):
    def on_created(self, event):
        print("FIle created")
        print(event)


def main():
    if sys.argv[1] == "watch":
        event_handler = EventHandler()
        observer = Observer()
        observer.schedule(event_handler, "./tes.txt", recursive=True)
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