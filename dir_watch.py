import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from os.path import exists


file = "ran.txt"

class EventHandler(FileSystemEventHandler):
    def on_created(self, event):
        #Watch for creation of specific file
        print(event)
        file_ = event.src_path.split("/")[-1]
        if file_ == file:
            print(f"File created: {file}")
            print("--------------------------------------------------")
        print("--------------------------------------------------")
    def on_modified(self, event):
        print(event)
        file_ = event.src_path.split("/")[-1]
        if file_ == file:
            print(f"File modified: {file}")
            print("--------------------------------------------------")
        print("--------------------------------------------------")

def search(file: str):
    # Search for file and see if it exists
    file_exists = exists(file)
    if file_exists: print("Exists")
    else: print("Not exist my mans")

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

    if sys.argv[1] == "search":
        search("./test/poo.txt")


if __name__ == "__main__":
    main()