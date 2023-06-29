import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
from os.path import exists



class EventHandler(FileSystemEventHandler):
    def __init__(self, file, obj):
        super().__init__()
        self.file = file
        self.m = False
        self.obj = obj

    def on_created(self, event):
        #Watch for creation of specific file
        file_ = event.src_path.split("/")[-1]
        if not event.is_directory and file_ ==  self.file:
            self.m = True


    def on_modified(self, event):
        file_ = event.src_path.split("/")[-1]
        if not event.is_directory and file_ == self.file:
            print(f"File Created: {file_}")
            if self.m:
                self.obj.send_file()
                self.m = not self.m


    def on_deleted(self, event):
        print(f"{event.src_path} has been deleted!")

