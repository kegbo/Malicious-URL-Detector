from Feature_Extractor import Feature_extraction
import pandas as pd
from pandas.core.frame import DataFrame
from multiprocessing.dummy import Pool as Pool
#import svm
#import k_nearest



class Trainer:
    
    def __init__(self,url):      
        self.url = url
        self.lst = []
        self.blacklist = False   
        

    def feature_extraction(self):
        if self.lst is None:
            self.lst = []
        features = Feature_extraction(self.url)
        if(features.get_blacklist()):
            self.blacklist = True
        else:    
            self.lst.append(features.get_features())
   
    def process(self,url):
        pool = Pool()
        result = pool.map(self.feature_extraction,(url), chunksize=800)
        

    def read_from_csv(self):
        self.df = pd.read_csv('verified_online.csv',encoding='latin-1')
        self.df['label'] = self.df['phish_id'] * 0
        mal_urls = self.df['url']
        self.df2 = pd.read_csv('test_ben.csv',encoding='latin-1')
        self.df2['label'] = self.df['phish_id']/self.df['phish_id']
        ben_urls = self.df2['urls']
        test = ben_urls
        self.process(ben_urls)

    def write_to_csv(self):
        nw_df = DataFrame(list(self.lst))
        nw_df.columns = ['Redirect count','ssl_classification','url_length','hostname_length','subdomain_count','at_sign_in_url','exe_extension_in_request_url','exe_extension_in_landing_url',
                            'ip_as_domain_name','no_of_slashes_in requst_url','no_of_slashes_in_landing_url','no_of_dots_in_request_url','no_of_dots_in_landing_url','tld_value','age_of_domain',
                            'age_of_last_modified','content_length','same_landing_and_request_ip','same_landing_and_request_url']
        frames = [self.df['label'],self.df2['label']]
        new_df = pd.concat(frames)
        new_df = new_df.reset_index()
        nw_df['label'] = new_df['label']
        nw_df.to_csv('dataset1.csv',sep=',', encoding='latin-1')
        
    def classifier(self):
        df =  pd.read_csv('dataset.csv')
        label = df['label']
        data = df.drop('label',axis = 1)  
        col = len(data.columns)
 #       kclus.run(data,label)
 #       svm.run(data,label)
      
