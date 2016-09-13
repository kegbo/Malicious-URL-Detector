from __future__ import print_function
from PyQt4.QtCore import QThread,SIGNAL
from time import sleep

class statusThread(QThread):

    def __init__(self, queue):
        QThread.__init__(self)
        self.myqueue = queue

    def run(self):
        print("status threading running")
        while True:
            if(self.myqueue.empty()):
                sleep(3)
            else:
                status = self.myqueue.get()
                self.emit(SIGNAL('status_update(QString)'), status)
            
        
            

