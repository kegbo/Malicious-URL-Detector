from __future__ import print_function
from PyQt4.QtCore import QThread,SIGNAL
from Feature_Extractor import Feature_extraction
import svm
#import k_nearest


#import K_clusters as kclus


class fileReaderThread(QThread):


    def __init__(self, url_list,queue):
        QThread.__init__(self)
        self.myqueue = queue
        self.url_list =url_list
        self.lst = []
        self.blacklist = False 
        
        

    def __del__(self):
        self.wait()
        
           

    def get_classification(self, url):
       
        self.extractor = Feature_extraction(url,self.myqueue)
        result = self.prediction()
        if(result == 1):
            value = url + ' = Benign'
        if(result == 0):
            value = url + 'Malicious'
            
        f = open('myfileb.txt','w')
        print(value, file=f)
        return value
    
    def prediction(self):        
        if self.lst is None:
            self.lst = []
        
        if(self.extractor.get_blacklist()):
            self.blacklist = True
        else:    
            self.lst = self.extractor.get_features()
                      
        print (self.myqueue.qsize())
#   
        if(self.blacklist):
                #result = [0,0]
                result = 0
        else:
            data = (list(self.lst))
            svm_prdt =  svm.predict(data)
            #kclus_prdt = kclus.predict(data)        
            #result = [svm_prdt[0],kclus_prdt[0]]
            result = svm_prdt[0]
        return result
    
#slot
    def run(self):
        print("running...")
        for url in self.url_list:
            result = self.get_classification(url)
            self.emit(SIGNAL('add_post(QString)'), result)
            
            