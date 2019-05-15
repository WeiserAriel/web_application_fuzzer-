import requests
import os
import argparse
import logging
import re
import paramiko

# from non standard directory
from beautifultable import BeautifulTable


class Fuzzer:
    #TODO - Complete all fuzzing files
    base =  os.getcwd().split('src')[0] + 'fuzzing_files' + os.sep
    fuzzing_payload = {'alphbets': base + 'alphbets', 'http_methods': base + 'http_methods','integer_overflow': base + 'integer_overflow'}
    # each url is a list which has this structure of list:
    # list[0] = HTTP Method
    # list[1] = URL
    # list[2] = HTTP Method params (optional)
    # list[3] = HTTP Body (optional)
    urls = {"UFM": [["GET","http://ip/ufmRest/monitoring/topx", (('object', '@@Node@@'),('attr', 'TxBW'),),""], \
                ["GET","http://ip/ufmRest/app/users","",""] ,\
                ["GET","http://ip/ufmRest/monitoring/resources","",""], \

                ], 'mlnx_os': []}
    REST_LOG_FILE_PATH = '/opt/ufm/log/rest_api.log'

    def __init__(self, fuzzing_file , product , ip):
        self.fuzzing_file = fuzzing_file
        self.product = product
        self.ip = ip
        self.session = requests.session()
        self.results_headers = ['HTTP METHOD','URL','query params','body','status code', 'elapsed time (ms)', 'LOG ERROR','Reflected']
        self.table = BeautifulTable()
        self.table.column_headers = self.results_headers
        self.init_table()
        self.results = []
        self.result_file = os.getcwd() + 'results_file.txt'
        self.shell = None
        self.init_results_file()
        self.init_ssh()
        self.fuzzer_mamager()

    def init_ssh(self):
        logging.debug("start init_ssh ")
        ip = self.ip
        ssh = self.SSHConnect(ip , 'root', '3tango')
        self.shell = self.createshell(ssh)

        logging.debug("end init_ssh")


    def clear_rest_api_log(self):
        logging.debug("start clear rest api log")
        cmd = "echo>" + Fuzzer.REST_LOG_FILE_PATH
        expected = ""
        result , output = self.run_par_cmd(cmd= cmd, expect= expected, shell= self.shell)
        if not output:
            logging.error("rest api log was not cleared successfully")
        else:
            logging.debug("rest api log was cleared.")
        logging.debug("end clear rest api log")

    def check_errors_in_rest_log(self):
        cmd = 'cat ' + Fuzzer.REST_LOG_FILE_PATH + '| ' + 'grep -i ERR|CRITICAL|FAILED'
        expected = ''
        result , out = self.run_par_cmd(cmd= cmd, expect= expected, shell= self.shell)
        # result should be '0' and 'out' should be empty in this case.
        if not out:
            logging.critical("Errors was found in REST API log ")
            logging.critical("log file content after running cmd (" + str(cmd) + "): " + str(out))
            return True
        else:
            logging.debug("REST API log has not errors")
            return False

    @staticmethod
    def get_ufm_headers():
        headers = {
            'Pragma': 'no-cache',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,he;q=0.8,it;q=0.7,es;q=0.6',
            'Authorization': 'Basic YWRtaW46MTIzNDU2',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/plain, */*',
            'Cache-Control': 'no-cache',
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
            'Referer': 'http://10.209.24.48/ufm_web/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36',
            'Expires': 'Sat, 01 Jan 2000 00:00:00 GMT',
        }

        return headers

    def load_fuzz_list(self):
        logging.info("Open selected fuzzing file..")
        try:
            filename = Fuzzer.fuzzing_payload[self.fuzzing_file]
            logging.debug("Fuzzing file is " + str(filename))
            with open(filename,'r') as f:
                return [line.strip() for line in f.readlines()]
        except Exception as e:
            logging.error("Exception : couldn't open fuzzing file")
            exit(1)
        logging.debug("load_fuzz_list ended successfully")
    
    def clear_results_for_next_url(self):
        logging.debug("Clearing results for next url")
        self.results = []

        #clearing beautifulTable:
        for _ in range(len(self.table)):
            del self.table[0]

    @staticmethod
    def SSHConnect(ip, username, passowrd):
        ssh = paramiko.SSHClient()
        logging.debug(msg="Open SSH Client to :" + str(ip))
        try:
            ssh.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())
            ssh.connect(ip, port=22, username=username, password=passowrd, allow_agent=False, look_for_keys=False)
        except Exception as ex:
            logging.error(msg="SSH Client wasn't established!")
            sys.exit(0)
        logging.info(msg="Open SSH Client to :" + str(ip) + "established!")
        return ssh

    @staticmethod
    def createshell(ssh):
        shell = ssh.invoke_shell()
        shell.settimeout(0.5)
        shell.recv(1024)
        # time.sleep(10)
        return shell

    @staticmethod
    def run_par_cmd(cmd, expect, shell):
        '''

          :param shell:
          :param cmd: cmd command like ' show version'
          :param expect: string to look for like '
          :return: 0 if the expected string was found in output.
          '''
        # sleeping for 3 seconds to the command will be executed after shell prompt is printed.
        shell.send(cmd + '\n')
        out = ''
        while True:
            try:
                tmp = shell.recv(1024)
                if not tmp:
                    break
            except Exception as e:
                break
            out += tmp.decode("utf-8")
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        out = ansi_escape.sub('', out)
        if expect not in out:
            return (1, out)
        return (0, out)


    def add_ip_to_url(self, url):
        url = str(url).replace('ip',self.ip)
        return url

    
    def fuzzer_mamager(self):

        #Load fuzzing option:
        fuzz_words = self.load_fuzz_list()
        product_urls = Fuzzer.urls[self.product]
        for url in product_urls:
            # Before we start to fuzz we want to make sure the basic URL ends with '200' OK.
            self.validate_url(url , fuzz_word = None)
            #if basic url doesn't work i want to skip fuzzing
            if str(self.results[0][4]) == '200':
                for word in fuzz_words:
                    #TODO - delete
                    word = '<script>alert(\'xss\')</script>'
                    self.validate_url(url, fuzz_word=word)
                self.print_results()
                self.save_results()
                self.clear_results_for_next_url()
            else:
                logging.critical("request for basic url failed, skipping url: " + str(self.results[0][1]))



        #response = requests.get('http://10.209.24.48/ufmRest/app/users', headers=headers)

    
    def validate_current_url(self,http_method, url , params, body):
        logging.debug("start validating current url")
        try:
            #check which http method is required:
            if http_method == 'GET':
                if params:
                    logging.debug("request is GET with params:")
                    r = self.session.get(url,params=params, headers= self.get_ufm_headers())
                else:
                    logging.debug("request is GET without params:")
                    r = self.session.get(url,headers=self.get_ufm_headers())
            elif http_method =='POST':
                if body:
                    logging.debug("request is POST wih body:")
                    r = self.session.post(url, body, headers= self.get_ufm_headers())
            else:
                logging.error("request method couldn't be found in validate current url")

            return r
        except Exception as e:
            logging.error("Exception received in validate current url" + str(e))
            return None

    @staticmethod
    def cls():
        os.system('cls' if os.name == 'nt' else 'clear')

    def init_results_file(self):
        with open(self.fuzzing_file, 'w') as results_file:
            results_file.write('\n')

    @staticmethod
    def convert_tuple_to_string(tup):
        tup_str = ""
        for t in tup:
            tup_str +='='.join(t)
            tup_str+=','
        tup_str = tup_str[:-1]
        return tup_str

    def save_results(self):
        logging.debug("starting save results")
        logging.info("saving results of fuzzing file: " + self.fuzzing_file)
        with open(self.fuzzing_file, 'a') as results_file:
            for row in self.results:
                for item in row:
                    if isinstance(item, tuple):
                        item = self.convert_tuple_to_string(item)
                    results_file.write(str(item))
                    results_file.write('.')
                results_file.write('\n')
        logging.debug("end save results")

    def print_results(self):
        #clear the screen before printing the results:
        self.cls()
        #save results into text file



        logging.debug("start print_result")
        logging.info("printing all fuzzing results for url: " + str(self.results[0][1]))
        for row in self.results:
            self.table.append_row(row)

        print(self.table)
        print("\n" *3)
        logging.debug("end print_result")


    def parse_request_results(self,r, curent_url_type, current_params,current_body, fuzz_word):
        logging.debug("start parse request result")
        try:
            result_list = []
            r_status_code = r.status_code
            r_elapsed_time = re.search('\d*\.{1}\d*[0-4]', str(r.elapsed))[0]
            r_url = r.url
            r_url_type = curent_url_type
        except Exception as e:
            logging.error("Exception in parse_request_results" + str(e) + "exiting")
            exit(1)

        if not current_params:
            current_params = 'N/A'
        if not current_body:
            current_body = 'N/A'

        #check if i received any errors in log file:
        error_in_log = self.check_errors_in_rest_log()
        if error_in_log == True:
            error_in_log = 'Yes'
        else:
            error_in_log = 'No'
        reflected = self.check_payload_reflected_in_html(r, fuzz_word)
        if reflected == True:
            reflected = 'Yes'
        else:
            reflected = 'No'

        result_list = [r_url_type,r_url,current_params,current_body,r_status_code,r_elapsed_time,error_in_log,reflected]


        logging.debug("adding result into result container")
        self.results.append(result_list)
        logging.debug("end parse request result")

    def check_payload_reflected_in_html(self, r, fuzz_word):
        logging.debug("start check payload reflected in html")

        if fuzz_word is None:
            logging.debug("skip check of reflected XSS in base url")
            return False

        if fuzz_word in r.content.decode('utf-8'):
            logging.critical("XSS reflected was found! fuzz_word = " + str(fuzz_word) + "URL = " + str(r.url))
            return True
        else:
            logging.debug("XSS reflected wasn't found for URL = " + str(r.url))
            return False
        logging.debug("end check payload reflected in html")

    def init_table(self):
        self.table.max_table_width = 160
        for attr in self.results_headers:
            self.table.left_padding_widths[attr] = 1
            self.table.right_padding_widths[attr] = 1


    def validate_url(self, url ,fuzz_word):
        logging.debug("start validating basic url")
        url_with_fuzz_sign = str(url[0]).replace("@@","")
        #check if url contains any parameters
        curent_url_type = url[0]
        current_url = self.add_ip_to_url(url[1])

        #checking if there is params for the request

        current_params = ''
        if url[2]:
            params = url[2]
            current_params = ()
            #params is tuple so i want to create new tuple without '@@' signs.
            first_tup_flag = True
            for tup in params:
                new_tup = ()
                if not fuzz_word:
                    first, second =str(tup[0]).replace('@@',"") ,str(tup[1]).replace("@@",'')
                else:
                    first, second = str(re.sub(r'@@.*@@',fuzz_word,tup[0])),str(re.sub(r'@@.*@@',fuzz_word,tup[1]))

                new_tup = (first,second)
                if first_tup_flag:
                    current_params = (first,second)
                    first_tup_flag = False
                else:
                    current_params  = (current_params,new_tup)
        #check if there is body for the request
        current_body = ""
        if url[3]:
            if not fuzz_word:
                current_body = str(url[3]).replace("@@","")
            else:
                current_body = str(re.sub('@@.@@',fuzz_word,url[3]))
        #TODO - for debuggig
        #print(curent_url_type,current_url, current_params, current_body)
        logging.info("validate basic url before fuzzing: " + current_url)
        r = self.validate_current_url(curent_url_type,current_url, current_params, current_body)
        self.parse_request_results(r, curent_url_type, current_params,current_body,fuzz_word)


def main():
    parser = argparse.ArgumentParser(description='Fuzzing tool for web applications')
    parser.add_argument('--fuzzing_type',dest='fuzzing_type', choices=['alphbets', 'http_methods', 'integer_overflow','long'], help='choose fuzzing type')
    parser.add_argument('--project',choices=['UFM','UFMAPL','NEO','MFT','HPCX'] , dest='project', help='select a project from list')
    parser.add_argument('--ip',  dest='ip',help='ip of your the machine you fuzz', required=True)
    parser.add_argument('--debug', dest='debug', action='store_true', help='change to debug mode')

    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(filename='web_fuzzer.log',
                        level=level,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%m-%d %H:%M',
                        filemode='w')

    logging.info("Start Script...")

    fuzz = Fuzzer(str(args.fuzzing_type).lower(), args.project, args.ip)

if __name__ == '__main__':
    main()