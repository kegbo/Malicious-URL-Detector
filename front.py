from PyQt4 import QtGui,QtCore
from PyQt4.QtCore import SIGNAL
import sys
import design
import time
from fileReaderThread import fileReaderThread
from status import statusThread
from multiprocessing import freeze_support
import Queue



class Ui(QtGui.QMainWindow, design.Ui_MainWindow):
    
    def __init__(self):
        super(self.__class__, self).__init__()
        self.setupUi(self)
        self.start_pushButton.clicked.connect(self.start_classification)
        self.submit_file()
        self.input_file = None
        self.start_time = time.clock()
        self.myqueue = Queue.Queue()
    
    def submit_file(self):
        self.connect(self.select_pushButton, QtCore.SIGNAL('clicked()'), self.browse_folder)
    
    def browse_folder(self):
   
        filename = QtGui.QFileDialog.getOpenFileName(self, 'Select file')
        if filename:
            self.filepicker_textEdit.setPlainText(filename) 
            myfile = open(filename,'r')
            self.input_file = myfile.readlines()           
        else:
            self.filepicker_textEdit.setPlainText('No file selected')
                    
    def start_classification(self):
       
        url_list = self.input_file        
        self.progressBar.setMaximum(len(url_list))
        self.progressBar.setValue(0)
        self.get_thread = fileReaderThread(url_list,self.myqueue)
        self.status_thread = statusThread(self.myqueue)
        self.connect(self.get_thread, SIGNAL("add_post(QString)"), self.add_post)
        self.connect(self.status_thread, SIGNAL("status_update(QString)"), self.status_update)
        self.connect(self.get_thread, SIGNAL("finished()"), self.done)
        
        self.get_thread.start()
        self.status_thread.start()
        self.stop_pushButton.setEnabled(True)
        
        self.stop_pushButton.clicked.connect(self.get_thread.terminate)
        
        self.start_pushButton.setEnabled(False)

    def add_post(self, post_text):
      
        if(self.result_textEdit.toPlainText()):
            self.result_textEdit.appendPlainText(post_text)
        else:
            self.result_textEdit.setPlainText(post_text)
                    
        self.progressBar.setValue(self.progressBar.value()+1)
    
    def status_update(self, status):
        
        if(self.report_textEdit.toPlainText()):
            self.report_textEdit.appendPlainText(status)
        else:
            self.report_textEdit.setPlainText(status)

    def done(self):
        
        self.stop_pushButton.setEnabled(False)
        self.start_pushButton.setEnabled(True)
        self.progressBar.setValue(0)
        print (time.clock() - self.start_time, "seconds")
        QtGui.QMessageBox.information(self, "Done!", "Done fetching posts!")
 
def main():
    freeze_support()
    app = QtGui.QApplication(sys.argv)
    form = Ui()
    form.show()
    app.exec_()

if __name__ == '__main__':
    main()