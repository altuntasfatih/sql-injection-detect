

import apache_log_parser
import glob
import logging
import re
import sys
import os


APACHE_FORMAT = "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
Pages={}
threshold=0.35
msg1="This requests probably provoke eror such as database eror,server site eror or 404 not found  .."
bracket="------------------------------------------------------------------------------------------"
msg2="This request lower likelihood exploit sql injection vulnerabilty,\n" \
          " Program don't have  enought profile of this page Which means behavior of this path on website    \n" \
          " Program can extract profile of this path When there are enought  normal respose    \n"
msg3="This request most likely exploit sql injection vulnerabilty,\n" \
          " When produce this result,program consider profile of path Therefore success rate very high      \n"


class PageProfile:
   def __init__(self,path,length,parameter):
     self.urlpath = path
     self.averagelength=int(length)
     self.occurence=1
     self.maxlength = int(length)
     self.minlength = int(length)

     self.parameter={'number':0,'args':{}}

     #{'id': default length, 'Submit': default length}
     if parameter != None  and len(parameter)!=0:
         self.updateParameter(parameter)

   def updatePage(self,length,parameter):
     length=int(length)
     self.occurence+=1
     self.averagelength=(self.averagelength*(self.occurence-1))+ int(length)
     self.averagelength/=self.occurence

     if self.maxlength< length:
         self.maxlength=length
     elif self.minlength>length:
         self.minlength = length

     if parameter != None and len(parameter)!=0:
         self.updateParameter(parameter)

   def updateParameter(self,parameter):
       self.parameter['number'] += 1
       for key, value in parameter.items():
           if key not in  self.parameter['args']:
               self.parameter['args'][key] = len(value)
           else:
               self.parameter['args'][key] = (self.parameter['args'][key]*(self.parameter['number']-1))+len(value)
               self.parameter['args'][key] /=self.parameter['number']

   def toString(self):
       print("Url : ",self.urlpath," ,repet : ",self.occurence,", AvgLen:", self.averagelength, ", MaxLen: ", self.maxlength,", MinLen: ", self.minlength,", Parameter: ",  self.parameter)




def readLogFile(log_file_path, pattern=APACHE_FORMAT):

    log_data = []
    line_parser = apache_log_parser.make_parser(pattern)
    for file_name in glob.glob(log_file_path):
        logging.info("File_Name: %s" % file_name)
        file = open(file_name, 'r')
        lines = file.readlines()
        file.close()
        logging.info(" Read %s Lines" % len(lines))
        for line in lines:
            line_data = line_parser(line)
            if line_data['status'] == '200' and checkRegMatch(line_data['request_url_query_simple_dict']) == 0:
                insertPage(line_data)
            else:
                log_data.append(line_data)

    logging.info("Total Number of Logs: %s" % len(lines))
    return log_data


def insertPage(request):
    path=request['request_url_path']
    #toStringLine(request)
    if path not in  Pages:
        temp = PageProfile(path, request['response_bytes_clf'],request['request_url_query_simple_dict'])
        Pages[path]=temp

    else:
        temp=Pages[path]
        temp.updatePage(request['response_bytes_clf'],request['request_url_query_simple_dict'])



def checkRegMatch(parameters):
    regex=r"(\%27)|(\')|(\%22)|(\")|(=)|(\%3D)|(\))|(\-\-)|(\%23)|(#)"
    for key, value in parameters.items():
        match = re.search(regex, value)
        if match:
            return 1
    return 0
def checkRegMatch2(parameters):
    regex = r"(\%27)|(\')|(\%22)|(\")|(=)|(\%3D)|(\))|(\-\-)|(\%23)|(#)"
    regex2 = r"(union)|(UNION)|(CONCAT)|(SELECT)|(concat)|(select)|(ORDER)|(order)|(By)|(OR)|(by)|(exec(\s|\w))"
    for key, value in parameters.items():
        match1 = re.search(regex, value)
        match2 = re.search(regex2, value)
        if match1 or match2:
            return 1

    return 0


def toStringLine(line):
    path = line['request_url']
    sizebyte = line['response_bytes_clf']
    status=line['status']
    if len(path)>120:
        print("Url : ", path[0:120], "...... ,length : ", sizebyte," status: ",status)
    else:
        print("Url : ", path, " ,length : ", sizebyte, " status: ", status)


def writeReport(line,f,flag):
    if flag:
        f.write(str(line)+"\n")
    else:
        path = line['request_url']
        sizebyte = line['response_bytes_clf']
        status = line['status']
        remote_host = line['remote_host']
        time = line['time_received']
        text="Remote_host: " + remote_host + " Time: " + time + ", Path: "+ path + " ,Size: " + sizebyte + " ,status: " + status
        f.write(str(text)+'\n')


def run(path):
    global Pages
    if os.path.isdir(path):
        logging.error("Filepath is mising")
        return

    diceylogs = readLogFile(path)


    logging.info("Number of Suspicious  Logs ->  %s " %len(diceylogs))

    print("-------------------------------Profiles of Paths ------------------------------------------")
    print("number of path ->",len(Pages))
    print("")
    for key in Pages:
        temp=Pages[key]
        temp.toString()
    print()
#    print(bracket)
#    for i in range(len(diceylogs)):
#        toStringLine(diceylogs[i])


    print("-------------------------------Report(detailed output on report.txt file) ------------------------------------------")
    outcome=splitLogs(diceylogs)
    dumpResult(outcome)




def splitLogs(diceylogs):
    erorrequest=[]
    riskyrequest = []
    hackedrequest = []


    try:
        for i in range(len(diceylogs)):
            request = diceylogs[i]
            path = request['request_url_path']
            sizebyte = request['response_bytes_clf']
            if path not in Pages:
                if checkRegMatch2(request['request_url_query_simple_dict']):
                    riskyrequest.append(request)
            else:
                temp = Pages[path]
                proportion = temp.averagelength / float(sizebyte)
                if (proportion < 0.97 or proportion > 1.03) and proportion < 2 and checkRegMatch2(request['request_url_query_simple_dict']):
                    hackedrequest.append(request)
                elif proportion > 2:
                    erorrequest.append(request)

    except Exception as e:
        #print("This log can  not parsed ->","Eror -> ",str(e))
        pass


    return [erorrequest,riskyrequest,hackedrequest]



def dumpResult(outcome):
    f = open('report.txt', 'a+')

    print(bracket)
    writeReport(bracket, f,1)
    print(msg1)
    writeReport(msg1,f,1)
    print()
    for item in outcome[0]:
        toStringLine(item)
        writeReport(item, f,0)


    print(bracket)
    writeReport(bracket, f, 1)
    print(msg2)
    writeReport(msg2, f, 1)

    for item in outcome[1]:
        toStringLine(item)
        writeReport(item, f, 0)


    print(bracket)
    writeReport(bracket, f, 1)
    print(msg3)
    writeReport(msg3, f, 1)

    for item in outcome[2]:
        toStringLine(item)
        writeReport(item, f, 0)













run("/Users/fatih/Desktop/orginal_log/firstsnapshotlog.log")