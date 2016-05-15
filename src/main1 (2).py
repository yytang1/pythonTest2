#encoding=utf-8
'''
All diff files should be put in the directory '../diffs' along with the xls file
And the diff filename should all be <cve_id>.txt and the xls name should be linux_kernel.xlsx
Use this function by setting the value for 'start' and 'end' variables in <main> function which represents the start row and the end row of the information sheet
NOTE:
No check for uploading diff files, please make sure that the file exists and is correct
And the result of uploading vuln_info is stored in vulnResult in <main> function, please be sure to make good use of it :-)
HTMLParser may break down when it's fed with incorrect html file.This would be helpful when debugging
'''
import urllib2
from bs4 import BeautifulSoup
from HTMLParser import HTMLParser
import cookielib
import urllib
import MultipartPostHandler
import xlrd
import os
import types
import zipfile
class Dawn:
    timeout = 30
    def __init__(self):
        ''' initialize and add cookie support'''
        httpHandler = urllib2.HTTPHandler()
        httpsHandler = urllib2.HTTPSHandler()
        cookie = cookielib.CookieJar()
        cookie_support = urllib2.HTTPCookieProcessor(cookie)
        opener = urllib2.build_opener(cookie_support, httpHandler, httpsHandler,MultipartPostHandler.MultipartPostHandler)
        urllib2.install_opener(opener)

    def getHeader(self):
        '''return the header of the browers'''
        header = {
            "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13",
            #"User-Agent" = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-cn,zh;q=0.5",
            #"Accept-Encoding":"gzip,deflate",
            "Accept-Charset":"GB2312,utf-8;q=0.7,*;q=0.7",
            "Keep-Alive":"115",
            "Connection":"keep-alive"
            }
        return header

    def request(self, url, headers=None, data = None):
        if headers is None:
            header = self.getHeader()

        #setting the data
        req = urllib2.Request(
            url = url,
            headers = header
            )
        #if data is not None:
        #    data = urllib.urlencode(data)

        #start request
        resp = urllib2.urlopen(req, data, self.timeout)
        contents = resp.read()
        resp.close()
        return contents
class xslprocesser:
    sheetname0 = 'Sheet0'
    sheetname='Sheet1'
    sheetname1 = 'Sheet2'
    def __init__(self,filename):
        self.workbook=xlrd.open_workbook(filename)
        try:
            self.sheetInstant=self.workbook.sheet_by_name(self.sheetname)
        except:
            try:
                self.sheetInstant = self.workbook.sheet_by_name(self.sheetname1)
            except:
                self.sheetInstant=self.workbook.sheet_by_name(self.sheetname0)
        self.rownum=self.sheetInstant.nrows
        self.colnum=self.sheetInstant.ncols
    def retrivedata(self,rowstart,rowend,col):
        resultset = []
        for row in range(rowstart,rowend):
            temp = self.sheetInstant.cell(row,col).value
            if type(temp) == types.FloatType:
                temp = str(temp)
            resultset.append(str(temp.replace(u'\xa0', u' ').replace(u'\xef','')).strip())
        return resultset

class MyHTMLParser1(HTMLParser):   
    def __init__(self):
        HTMLParser.__init__(self)   
        self.value = []
        self.name = []
        self.isoption = 0
    def handle_starttag(self, tag, attrs):   
        #print "Encountered the beginning of a %s tag" % tag   
        if tag == "option":
            if len(attrs) == 0:   
                pass   
            else:
                for (variable, value) in attrs:
                    self.value.append(value)
                    self.isoption = 1
    def handle_data(self, data):
        if self.isoption:
            self.name.append(data)
            self.isoption=0
def divideByComma(tar):
    resultset = []
    #print type(tar)
    #print tar
    if tar.find(',') == -1:
        if len(tar) == 0:
            return 'None'
        else:
            return tar
    startPos = 0
    endPos = tar.find(',')
    while True:
        if endPos == -1:
            endPos = len(tar)
            #print tar[startPos:endPos]
            resultset.append(tar[startPos:endPos].strip())
            break
        #print tar[startPos:endPos]
        resultset.append(tar[startPos:endPos].strip())
        startPos = endPos+1
        endPos = tar.find(',',endPos+1)
    return resultset
def processInfo(vuln_files,vuln_funcs,vuln_types,cves,soft_vers):
    i = 0
    for index in range(0,len(vuln_files)):
        #print vuln_files[index-i]
        #print vuln_funcs[index-i]
        if vuln_funcs[index-i].find(';') ==-1 and vuln_files[index-i].find(',') == -1:
            if vuln_funcs[index-i] == '' or vuln_funcs[index-i]=='unknown' or vuln_funcs[index-i]=='Unknown':
                vuln_funcs[index-i] = 'None'
        if (vuln_files[index-i].find(';') == -1) and (vuln_funcs[index-i].find(',') !=-1):
            func_block = divideByComma(vuln_funcs[index-i])
            for item in func_block:
                vuln_files.append(vuln_files[index-i])
                #print vuln_files[index-i]
                vuln_funcs.append(item)
                #print item
                vuln_types.append(vuln_types[index-i])
                cves.append(cves[index-i])
                soft_vers.append(soft_vers[index-i])
            del vuln_files[index-i]
            del vuln_funcs[index-i]
            del vuln_types[index-i]
            del cves[index-i]
            del soft_vers[index-i]
            i +=1
            continue
        if vuln_files[index-i].find(';')!=-1:#find ';'
            raw_file = vuln_files[index-i]
            raw_func = vuln_funcs[index-i]
            raw_type = vuln_types[index-i]
            raw_cve = cves[index-i]
            raw_vers = soft_vers[index-i]
            del vuln_files[index-i]
            del vuln_funcs[index-i]
            del vuln_types[index-i]
            del cves[index-i]
            del soft_vers[index-i]
            i += 1
            startPosInFile = 0
            endPosInFile = raw_file.find(';')
            startPosInFunc = 0
            endPosInFunc = raw_func.find(';')
            #print 'start:'+str(startPosInFile)+' end:'+str(endPosInFile)+' total:'+str(len(raw_file))
            #print 'start:'+str(startPosInFunc)+' end:'+str(endPosInFunc)+' total:'+str(len(raw_func))
            while True:
                if endPosInFile!=-1 and endPosInFunc == -1:
                    print(raw_cve  + ' has a format error!')
                    break
                if endPosInFile == -1:
                    endPosInFile = len(raw_file)
                    endPosInFunc = len(raw_func)
                    func_block = divideByComma(raw_func[startPosInFunc:endPosInFunc])
                    if type(func_block) == types.UnicodeType or type(func_block) == types.StringType:
                        vuln_files.append(raw_file[startPosInFile:endPosInFile])
                        #print raw_file[startPosInFile:endPosInFile]
                        vuln_funcs.append(func_block)
                        vuln_types.append(raw_type)
                        cves.append(raw_cve)
                        soft_vers.append(raw_vers)
                        #print func_block
                        break
                    else:
                        for item in func_block:
                            vuln_files.append(raw_file[startPosInFile:endPosInFile])
                            #print raw_file[startPosInFile:endPosInFile]
                            vuln_funcs.append(item)
                            vuln_types.append(raw_type)
                            cves.append(raw_cve)
                            soft_vers.append(raw_vers)
                            #print item
                        break
                else:
                    func_block = divideByComma(raw_func[startPosInFunc:endPosInFunc])
                    if type(func_block) == types.UnicodeType or type(func_block) == types.StringType:
                        vuln_files.append(raw_file[startPosInFile:endPosInFile])
                        vuln_funcs.append(func_block)
                        vuln_types.append(raw_type)
                        cves.append(raw_cve)
                        soft_vers.append(raw_vers)
                    else:
                        for item in func_block:
                            vuln_files.append(raw_file[startPosInFile:endPosInFile])
                            vuln_funcs.append(item)
                            vuln_types.append(raw_type)
                            cves.append(raw_cve)
                            soft_vers.append(raw_vers)
                    startPosInFile = endPosInFile +1
                    endPosInFile = raw_file.find(';',endPosInFile+1)
                    startPosInFunc=endPosInFunc+1
                    endPosInFunc = raw_func.find(';',endPosInFunc+1)
    return vuln_files,vuln_funcs,vuln_types,cves,soft_vers
def remove_comma(str_):
    if len(str_) > 0:
        if str_[-1] == ',':
            return str_[0:-1]
    return str_
'''
zipfile_name must specify its location so that this function can find it
'''
def main(zipfile_name = '',start = 1,end = 0):
    url = 'http://211.69.198.89:8000/accounts/login/?next=/index/'
    diffurl='http://211.69.198.89:8000/diffTest/import_diff/'
    infourl='http://211.69.198.89:8000/diffTest/import_vuln/'
    if not os.path.exists('./diffs/'):
        os.mkdir('diffs')
    zipfile_name = ''# this filename must include path so that it can be found
    zip_ = zipfile.ZipFile(zipfile_name,'r')
    zip_.extractall(r'./diffs')
    zip_.close()
    xlc_filename = ''
    xlc_count = 0
    for filename in os.listdir(r'./diffs'):
        if filename.split('.')[-1] == 'xls' or filename.split('.')[-1] == 'xlsx':
            xlc_filename = filename
            xlc_count += 1
    if xlc_count > 1 :
        print 'multiple excel found, pls check your zip file and upload again'
        return 0
    
    os.chdir('./diffs/')
    xslpro = xslprocesser(xlc_filename)
    if end == 0:
        end = xslpro.rownum
    
    print 'start submitting diff files'
    diffResult = []
    cves = xslpro.retrivedata(start,end,0)#row 0 is the title
    vuln_funcs=xslpro.retrivedata(start,end,5)
    soft_names = xslpro.retrivedata(start, end, 2)
    soft_vers = xslpro.retrivedata(start,end,9)
    for index in range(0,len(soft_vers)):
        if soft_names[index].strip().lower()=='linux_kernel':
            soft_vers[index] = 'linux-'+str(soft_vers[index]).strip()
        else:
            soft_vers[index] = str(soft_names[index]).strip().lower() + '-'+str(soft_vers[index]).strip()
    cwes = xslpro.retrivedata(start,end,1)
    
    conn = Dawn()
    for index in range(0,len(soft_vers)):
        getstr = conn.request(diffurl,None,None)
        soup = BeautifulSoup(getstr,'lxml')
        cookie = soup.find('input',attrs={'type':'hidden'})
        cookiename = cookie.get('name')
        cookie = cookie.get('value')
          
        hp1=MyHTMLParser1()#get options
        hp1.feed(getstr)
        hp1.close()
        if soft_vers[index] in hp1.name:
            selectindex = hp1.name.index(soft_vers[index])#get the index accoring to its name
        else:
            diffResult.append('Softvare not submit:'+cves[index] +' missing: '+soft_vers[index])
            continue
        cveid = cves[index]
        cweid = cwes[index]
        vuln_soft = hp1.value[selectindex]
        openfilename = cveid+'.txt'
        if os.path.exists(openfilename) == False:
            diffResult.append('diff file missing! '+openfilename)
            continue
        difffilepayload = {'cveid':cveid,'vuln_soft':vuln_soft,cookiename:cookie,'diff_file': open(openfilename, "rb"),'cweid':cweid}
        getstr = conn.request(diffurl,None,difffilepayload)
        if getstr.find('璇ヨˉ涓佹枃浠跺凡缁忎笂浼�') != -1:
            diffResult.append('Already Exist '+cveid)
            continue
        if getstr.find('褰曞叆鎴愬姛锛屾劅璋�') != -1:
            diffResult.append('Success'+cveid)
        else:
            diffResult.append('Unknown Error.Check the http form '+cveid) 
    ''' upload diff file complete'''
     
     
    total = 0
    success = 0
    fail = 0
    for item in diffResult:
        if item.find('Success') ==-1 and item.find('Already Exist') == -1:
            fail += 1
            total += 1
            print item
        else:
            success +=1
            total +=1
    print 'total '+str(total)+' success: '+str(success)+' fail: '+str(fail)
    
    
    print 'start submitting vuln info'
    vuln_funcs=xslpro.retrivedata(start,end,5)
    vuln_funcs = map(remove_comma,vuln_funcs)
    vuln_files = xslpro.retrivedata(start,end,4)
    vuln_types = xslpro.retrivedata(start,end,7)
                    
    vulnResult=[]
    
    vuln_files,vuln_funcs,vuln_types,cves,soft_vers=processInfo(vuln_files, vuln_funcs,vuln_types,cves,soft_vers)
    for index in range(0,len(vuln_files)):
        getstr=conn.request(infourl,None,None)
        soup = BeautifulSoup(getstr,'lxml')
        cookie = soup.find('input',attrs={'type':'hidden'})
        cookiename = cookie.get('name')
        cookie = cookie.get('value')
        
        hp1=MyHTMLParser1()#get options
        hp1.feed(getstr)
        hp1.close()
        cves[index] = cves[index]+'['+soft_vers[index]+']'
        if cves[index].lower() in hp1.name:
            selectindex = hp1.name.index(cves[index].lower())#this must be lower
        else:
            vulnResult.append('Diff not submit '+cves[index].lower())
            continue
        vuln_file = vuln_files[index]
        vuln_func = vuln_funcs[index]
        vuln_type = vuln_types[index]
        cveid = hp1.value[selectindex]
        '''retrive data and put it into var'''
        info_payload={'vuln_func_file':vuln_file,cookie:cookiename,'vuln_type':vuln_type,'vuln_func':vuln_func,'cve_id':cveid}
        info_payload = urllib.urlencode(info_payload)
        getstr = conn.request(infourl,None,info_payload)
        if getstr.find('鏈壘鍒版寚瀹氱殑婕忔礊鏂囦欢锛岃鎸夌収鎻愮ず鎻愪氦骞舵牳瀹炴枃浠跺悕') != -1:
            vulnResult.append('No file '+cves[index] + 'missing:'+vuln_file+' '+vuln_func+' '+vuln_type)
            continue
        if getstr.find('鎵惧埌澶氫釜鍚屽悕鏂囦欢锛岃鎸夌収鎻愮ず杈撳叆骞舵牳瀹炴枃浠跺悕') != -1:
            vulnResult.append('Multiple file '+cves[index])
            continue
        if getstr.find('鍦ㄦ寚瀹氭枃浠朵腑鏈壘鍒拌鍑芥暟锛岃鏍稿疄鍚庡啀鎻愪氦') != -1:
            vulnResult.append('No function '+cves[index]+ ' missing:'+vuln_file+' '+vuln_func+' '+vuln_type)
            continue
        if getstr.find('璇ユ紡娲炰俊鎭凡缁忎笂浼�') != -1:
            vulnResult.append('Already Exist '+cves[index])
            continue
        if getstr.find('褰曞叆鎴愬姛锛屾劅璋�')!= -1:
            vulnResult.append('Success '+cves[index])
            continue
        else:
            vulnResult.append('Unknown Error.Check the http form '+cves[index])
    '''upload vuln_info complete'''
    total = 0
    success = 0
    fail = 0
    print 
    for item in vulnResult:
        if item.find('Success')== -1 and item.find('Already Exist')== -1:
            fail += 1
            total += 1
            print item
        else:
            success +=1
            total +=1
    print 'total '+str(total)+' success: '+str(success)+' fail: '+str(fail)
    os.chdir('..')
    return 0
if __name__ == "__main__":
    main()