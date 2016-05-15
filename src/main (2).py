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
from HTMLParser import HTMLParser
import cookielib
import urllib
import MultipartPostHandler
import xlrd
import os
import types
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
    workbook=None
    sheetname='Sheet1'
    sheetname1 = 'Sheet2'
    sheetInstant=None
    def __init__(self,filename):
        self.workbook=xlrd.open_workbook(filename)
        try:
            self.sheetInstant=self.workbook.sheet_by_name(self.sheetname)
        except:
            self.sheetInstant = self.workbook.sheet_by_name(self.sheetname1)
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
        
class MyHTMLParser(HTMLParser):   
    def __init__(self):
        HTMLParser.__init__(self)   
        self.cookie = ''
        self.name = ''
    def handle_starttag(self, tag, attrs):   
        #print "Encountered the beginning of a %s tag" % tag   
        if tag == "input":
            if len(attrs) == 0:   
                pass   
            else:
                temp = []
                for (variable, value) in attrs:
                    temp.append(value)
                if 'hidden' in temp:
                    for (variable, values) in attrs:
                        if variable == "value":   
                            self.cookie= values
                        if variable == 'name':
                            self.name = values
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
            if vuln_funcs[index-i] == '' or vuln_funcs[index-i]=='unknown':
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
                    print raw_cve  + ' has a format error!'
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
if __name__ == "__main__":
    diffurl='http://127.0.0.1:8000/vulnerability/importDiff/'
    if os.path.exists('../diffs'):
        os.chdir('../diffs')
    else:
        if os.path.exists('diffs'):
            os.chdir('diffs')
        else:
            print('no such dir as diffs!')
            exit()
       
    conn = Dawn()
    getstr = conn.request(url,None,None)
    hp = MyHTMLParser()
    hp.feed(getstr)
    hp.close()
    data = {'password':'2012tyytyy','username':'yytang',hp.name:hp.cookie}#这里是因为网站本身带了cookie，每次要把cookie里面的值作为表单的一部分上传
    data = urllib.urlencode(data)
    getstr = conn.request(url,None,data)
    '''login complete'''
    
    xlc_filename = raw_input('请输入excel文件名称（包含后缀）:')
    xslpro = xslprocesser(xlc_filename)
    start = int(raw_input('请输入开始行号(excel 行数减一):'),10)
    end = int(raw_input('请输入结束行号(excel 行数 不 减一):'),10)
    print('start submitting diff files')
    diffResult = []
    
    cves = xslpro.retrivedata(start,end,0)#row 0 is the title
    softwares=xslpro.retrivedata(start,end,1)
    software_versions=xslpro.retrivedata(start,end,2)
    vuln_files=xslpro.retrivedata(start,end,3)
    vuln_funcs=xslpro.retrivedata(start,end,4)
    diff_links=xslpro.retrivedata(start,end,5)
    contain_versions=xslpro.retrivedata(start,end,7)
    reuse_versions=xslpro.retrivedata(start,end,10)

    # for index in range(0,len(soft_vers)):
    #     if softwares[index].strip().lower()=='linux_kernel':
    #         soft_vers[index] = 'linux-'+str(soft_vers[index]).strip()
    #     else:
    #         soft_vers[index] = str(soft_names[index]).strip().lower() + '-'+str(soft_vers[index]).strip()
    
    for index in range(0,len(cves)):
        cveid = cves[index]
        openfilename = cveid+'.txt'
        software=softwares[index]
        if os.path.exists(openfilename) == False:
            diffResult.append('diff file missing! '+openfilename)
            continue
        difffilepayload = {'cve':cveid,'software':software,hp.name:hp.cookie,'vuln_file':vuln_files[index],'vuln_func':vuln_funcs[index],'diff_file': open(openfilename, "rb"),'softwareVersion':softwareVersions[index],'contain_version':contain_versions[index],'reuse_version':reuse_versions[index],'diff_link':diff_links[index]}
        getstr = conn.request(diffurl,None,difffilepayload)
        print(getstr)
        if getstr.find('该补丁文件已经上传') != -1:
            diffResult.append('Already Exist '+cveid)
            continue
        if getstr.find('录入成功，感谢') != -1:
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
            print(item)
            success +=1
            total +=1
    print('total '+str(total)+' success: '+str(success)+' fail: '+str(fail))
