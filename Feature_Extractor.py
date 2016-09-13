import requests
import socket
import dns.resolver
import csv
import tldextract
import ipaddress
#import ipaddr
import whois
from datetime import datetime
import threading as thread







class Feature_extraction():
    
    __request_url = None
    __redirect_count = 0
    __ssl_classification = 1
    __blacklist = False
    __whitelist = False
    __request_ip = None
    __landing_ip = None
    __landing_url = None
    __hosting_servers = []
    __url_length = 0
    __hostname_length = 0
    __subdomains_count = 0
    __at_sign_in_url = 0
    __exe_extension_in_url = 0
    __exe_extension_in_landing_url = 0
    __ip_as_domain = 0
    __no_of_slashes_landing_url = 0
    __no_of_slashes_request_url = 0
    __no_of_dots_request_url = 0
    __no_of_dots_landing_url = 0
    __tld_value = 0
    __age_of_domain = 0
    __age_last_modified = 0
    __content_length = 0
    __same_landing_and_request_url = 1
    __same_landing_and_request_ip = 1
    __bls = ["zen.spamhaus.org","dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net", "xbl.spamhaus.org", "pbl.spamhaus.org", "barracudacentral.org","invaluement.com","mxtoolbox.com"]
    
    __tld = [".com",".co.uk",".edu",".gov",".ru",".net",".org",".de",".jp",".uk",".br",".pl",".in",
             ".in",".it",".fr",".au",".nl",".info",".ir",".cn",".es",".cz",
             ".kr",".ua",".ca",".eu",".biz",".za",".gr",".co",".ro",".se",".tw"
             ".mx",".vn",".tr",".downlaod",".top",".gdn",".science",".review",".stream",
             ".diet",".tokyo",".link",".accountant"]
    features = None
    
    #myqueue = Queue.Queue()
    
   
    
    #constructor
    def __init__(self,url,queue):
        self.myqueue = queue
        self.__request_url = url
        self.init()
                 
        
    def setUrl(self,url):
        self.__request_url = url
                       
    #length of url string
    def __length_of_url(self):
        status = "Checking the length of url"
        self.myqueue.put(status)
        
        self.__url_length = len(self.__request_url)
        return self.__url_length
    
    #lemgth of hostname
    def __length_of_hostname(self):
        status = "Counting characterfs in hostname"
        self.myqueue.put(status)
        self.__hostname_length = len(tldextract.extract(self.__strip_url_slashes(self.__request_url)).domain) 
        return self.__hostname_length
    
    #Number of subdomians in url
    def __number_of_subdomains(self):  
        status = "Checking number of subdomains"
        self.myqueue.put(status)
        self.__subdomains_count = 0     
        subdomain =  tldextract.extract(self.__strip_url_slashes(self.__request_url)).subdomain
        if subdomain:
            if(subdomain.count(".")):
                self.__subdomains_count = subdomain.count(".") + 1
            else:
                self.__subdomains_count = 1
                
        return self.__subdomains_count
    
    #Number of dots in landing url
    def __number_of_dots_landing_url(self):
        status = "Chcking number of subdomains in landing url"
        self.myqueue.put(status)
        if(self.__landing_url):
            if(self.__same_landing_and_request_url):
                self.__no_of_dots_landing_url = self.__no_of_dots_request_url
            else:
                self.__no_of_dots_landing_url = self.__landing_url.count(".")
        else:
            self.__no_of_dots_landing_url = 1000  
    
    #Number of dots in request url
    def __number_of_dots_request_url(self):
        status = "Checking number of subdomains in request url"
        self.myqueue.put(status)
        self.__no_of_dots_request_url = self.__request_url.count(".")
        return self.__no_of_dots_request_url
                          
    #check if the url contains an at sign    
    def __presence_of_at_sign(self):
        status = "checking presence of @ sing in url"
        self.myqueue.put(status)
        if(self.__request_url.count("@") == 0):
            self.__at_sign_in_url = 1
            
    #check the presence of exe in url        
    def __presence_of_exe(self):
        status = "Check if url leads to an executable"
        self.myqueue.put(status)
        if(self.__request_url.count(".exe") == 0):
            self.__exe_extension_in_url = 1
            return self.__exe_extension_in_url
    #check the presence of exe in url        
    def __presence_of_exe_in_landing_url(self):
        status = "Check if url leads to an executable"
        self.myqueue.put(status)
        if(self.__landing_url):
            if(self.__landing_url.count(".exe") == 0):
                self.__exe_extension_in_landing_url = 1
        return self.__exe_extension_in_landing_url
            
    #check the number of slashes in url        
    def __number_of_slashes_landing_url(self):
        status = "Counting number of slashes in landing url"
        self.myqueue.put(status)
        if(self.__landing_url):
            if(self.__same_landing_and_request_url):
                self.__no_of_slashes_landing_url= self.__no_of_slashes_request_url
            else:
                self.__no_of_slashes_landing_url= self.__landing_url.count("/")  
        else:
            self.__no_of_slashes_landing_url = 1000     
    #check the number of slashes in url        
    def __number_of_slashes_request_url(self):
        status = "Counting number of slashes in request url"
        self.myqueue.put(status)
        self.__no_of_slashes_request_url= self.__request_url.count("/")
     
    #tld values based on dict
    def __value_of_tld(self):
        status = "Getting value of tld"
        self.myqueue.put(status)
        tld = tldextract.extract(self.__request_url).suffix
        
        try: 
            self.__tld_value = self.__tld.index(tld)
        except Exception:
            self.__tld_value = 100
        
        return self.__tld_value
    
    #check the age of domain
    def __domaain_age(self):
        status = "Cheacking age of domain"
        self.myqueue.put(status)
        try:
            query =  whois.query(self.__request_url)
            last_updated = query.last_updated
            creation_date = query.creation_date
            self.__age_of_domain =  (datetime.today() - creation_date).days
            self.__age_last_modified = (datetime.today() - last_updated).days        
        except:
            self.__age_of_domain =  0
            self.__age_last_modified = 0      
                    
    #check if domain is an Ip address
    def __ip_as_domain_name(self):
        status = "Check if ip is used as domain name"
        self.myqueue.put(status)
        value = 0       
        url = tldextract.extract(self.__request_url).domain
        try:
            ipaddress.ip_network(url)
            value = 1
        except ValueError:
            pass
                            
        #=======================================================================
        # try:
        #     ipaddr.IPNetwork(url)
        #     value = 1
        # except ValueError:
        #     pass
        #=======================================================================
            
        if(value):
            self.__ip_as_domain = 1
    #same request and landing url
    def __same_landing_request_urls(self):
        status = "Ckeck if request and landing url are same"
        self.myqueue.put(status)
        self.__same_landing_and_request_url = 1
        if(self.__landing_url != self.__request_url):
            self.__same_landing_and_request_url = 0  
        
        return self.__same_landing_and_request_url
    
    #same request and landing url
    def __same_landing_request_ip(self):
        status = "Check if request and landing ip are same"
        self.myqueue.put(status)
        self.__same_landing_and_request_ip = 1
        if(self.__landing_ip != self.__request_ip):
            self.__same_landing_and_request_ip = 0 
        
        return self.__same_landing_and_request_ip
                               
    #length of redirect chain and validity of ssl certificate    
    def __redirect_chain_length(self):
        status = "Counting number of redirects"
        self.myqueue.put(status)
        status = "Checking SSL"
        self.myqueue.put(status)
        status = "Getting landing url"
        self.myqueue.put(status)
        try:
            r = requests.get(self.__request_url, verify=True)
            if(r.headers.get('Content-Length')):
                self.__content_length = r.headers.get('Content-Length')      
            for resq in r.history:
                self.__redirect_count+= 1
                self.__landing_url = resq.url
                self.__ssl_classification = 1
        except requests.exceptions.SSLError:
            self.__ssl_classification = 0
        except requests.exceptions.ConnectionError:
            pass
        except requests.exceptions.InvalidSchema:
            self.__blacklist = True
        except UnicodeDecodeError:
            pass
        except requests.exceptions.TooManyRedirects:
            self.__redirect_count =  30
        except requests.exceptions.ContentDecodingError:
            pass
        
       
   
        
            
    
    #check if url is in blacklist
    def __blacklist_check(self): 
        status = "Checking url in blacklist"
        self.myqueue.put(status)       
        my_resolver = dns.resolver.Resolver()
        my_resolver.timeout = 10
        my_resolver.lifetime = 10
        for bl in self.__bls:
            try:             
                query = '.'.join(reversed(str(self.__request_ip).split("."))) + "." + bl
                my_resolver.query(query, "A")
                my_resolver.query(query, "TXT")
                self.__blacklist = True
                if( self.__blacklist):
                    break
            except dns.exception.Timeout:
                pass
            except dns.resolver.NXDOMAIN:
                self.__blacklist = False
            except dns.resolver.NoNameservers:
                pass
               
    def __blacklist_check_landing_url(self):
        status = "Checking landing url in blacklist"
        self.myqueue.put(status)   
        
        my_resolver = dns.resolver.Resolver()
        my_resolver.timeout = 10
        my_resolver.lifetime = 10
        for bl in self.__bls:
            try:              
                query = '.'.join(reversed(str(self.__landing_ip).split("."))) + "." + bl
                my_resolver.query(query, "A")
                my_resolver.query(query, "TXT")
                self.__blacklist = True
                if( self.__blacklist ):
                    break
            except dns.exception.Timeout:
                pass
            except dns.resolver.NXDOMAIN:
                self.__blacklist = False
            except dns.resolver.NoNameservers:
                pass
    
    
    #check alexa 1miillion list
    def __whitelist_check(self):
        with open('top-1m.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if(self.__strip_url_slashes(self.__request_url) == row[1]):
                    self.__whitelist = True
                    break     
     
    def __whitelist_check_landing_url(self):
        with open('top-1m.csv', 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                if(self.__strip_url_slashes(self.__landing_url) == row[1]):
                    self.__whitelist = True
                    break                     
    #set the ipADDRESS   
    def __get_request_ip_address(self): 
        status = "Getting url ip address"
        self.myqueue.put(status)
        try:
            self.__request_ip = socket.gethostbyname(self.__strip_url_slashes(self.__request_url))
        except socket.gaierror:
            pass
        except UnicodeError:
            print(self.__strip_url_slashes(self.__request_url))
             
        
    #set the ipADDRESS   
    def __get_landing_ip_address(self):
        status = "Getting landing ip address"
        self.myqueue.put(status)
        try:
            if(self.__landing_url): 
                    self.__landing_ip = socket.gethostbyname(self.__strip_url_slashes(self.__landing_url))
        except socket.gaierror:
            print("soket gai error from -- ")
            print(self.__strip_url_slashes(self.__request_url))
            print(self.__strip_url_slashes(self.__landing_url))
            print("above is landing url")
            pass
    #check domain name sever
    def __check_hosting_server(self): 
        status = "Checking hosting server"
        self.myqueue.put(status)
        url = self.__strip_url_slashes()   
        myResolver = dns.resolver.Resolver() #create a new instance named 'myResolver'
        myAnswers = myResolver.query(url,"NS") #Lookup the 'A' record(s) for google.com
        for rdata in myAnswers: #for each response
            self.__hosting_servers.append(rdata) #print the data
   
    #removes the http protocol from the url
    def __strip_url_slashes(self,url):
        status = "Striping Url Slashes"
        self.myqueue.put(status)
        lines = url
        lines = lines.replace("http://","")
        lines = lines.replace("https://","")
        lines = lines.replace("www.", "") # May replace some false positives ('www.com')
        urls = [url.split('/')[0] for url in lines.split()]
        return '\n'.join(urls)
   
    #return blacklist value
    def get_blacklist(self):
        status = "Getting blacklist result"
        self.myqueue.put(status)
        return self.__blacklist
    
    #return whitelist value
    def get_whitelist(self):
        return self.__whitelist_check()
    
    
    
    #initialize all methods
    def init(self):  
        status = "Initializing"
        
        self.myqueue.put(status)  
          
        self.__redirect_chain_length()
        self.__blacklist_check()
        self.__blacklist_check_landing_url()
        #self.__whitelist_check()
        #self.__whitelist_check_landing_url()
        t1 = thread.Thread(target = self.__get_request_ip_address)
        t2 = thread.Thread(target = self.__get_landing_ip_address)
        t3 = thread.Thread(target = self.__length_of_hostname)
        t4 = thread.Thread(target = self.__length_of_hostname )
        t5 = thread.Thread(target = self.__length_of_url)
        t6 = thread.Thread(target = self.__number_of_subdomains)
        t7 = thread.Thread(target = self.__number_of_dots_request_url)
        t8 = thread.Thread(target = self.__number_of_dots_landing_url)
        t9 = thread.Thread(target = self.__presence_of_at_sign)
        t10 = thread.Thread(target = self.__presence_of_exe)
        t11 = thread.Thread(target = self.__number_of_slashes_request_url)
        t12 = thread.Thread(target = self.__number_of_slashes_landing_url)
        t13 = thread.Thread(target = self.__value_of_tld)
        t14 = thread.Thread(target = self.__domaain_age)
        t15 = thread.Thread(target = self.__ip_as_domain_name )
        t16 = thread.Thread(target = self.__presence_of_exe_in_landing_url)
        
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()
        t6.start()
        t7.start()
        t8.start()
        t9.start()
        t10.start()
        t11.start()
        t12.start()
        t13.start()
        t14.start()
        t15.start()
        t16.start()
        
        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()
        t6.join()
        t7.join()
        t8.join()
        t9.join()
        t10.join()
        t11.join()
        t12.join()
        t13.join()
        t14.join()
        t15.join()
        t16.join()
        
        
        self.__same_landing_request_urls()
        self.__same_landing_request_ip()  
        

        
            
    #return features      
    def get_features(self):
        status = "Getting Features...."
        self.myqueue.put(status)
        
        if self.features is None:
            self.features = []
        
        self.features.insert(0, self.__redirect_count)
        self.features.insert(1, self.__ssl_classification)
        self.features.insert(2, self.__url_length)
        self.features.insert(3, self.__hostname_length)
        self.features.insert(4, self.__subdomains_count)
        self.features.insert(5, self.__at_sign_in_url)
        self.features.insert(6, self.__exe_extension_in_url)
        self.features.insert(7, self.__exe_extension_in_landing_url)
        self.features.insert(8, self.__ip_as_domain)
        self.features.insert(9, self.__no_of_slashes_request_url)
        self.features.insert(10, self.__no_of_slashes_landing_url)
        self.features.insert(11, self.__no_of_dots_landing_url)
        self.features.insert(12, self.__no_of_dots_request_url)
        self.features.insert(13, self.__tld_value)
        self.features.insert(14, self.__age_of_domain)
        self.features.insert(15, self.__age_last_modified)
        self.features.insert(16, self.__content_length)
        self.features.insert(17, self.__same_landing_and_request_ip)
        self.features.insert(18, self.__same_landing_and_request_url)
        
        return self.features

        
            


