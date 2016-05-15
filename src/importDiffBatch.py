# encoding=utf-8
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
from bs4 import BeautifulSoup
class Dawn:
    timeout = 30
    def __init__(self):
        ''' initialize and add cookie support'''
        httpHandler = urllib2.HTTPHandler()
        httpsHandler = urllib2.HTTPSHandler()
        cookie = cookielib.CookieJar()
        cookie_support = urllib2.HTTPCookieProcessor(cookie)
        opener = urllib2.build_opener(cookie_support, httpHandler, httpsHandler, MultipartPostHandler.MultipartPostHandler)
        urllib2.install_opener(opener)

    def getHeader(self):
        '''return the header of the browers'''
        header = {
            "User-Agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13",
            # "User-Agent" = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.13) Gecko/20101206 Ubuntu/10.10 (maverick) Firefox/3.6.13",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            "Accept-Language":"zh-cn,zh;q=0.5",
            # "Accept-Encoding":"gzip,deflate",
            "Accept-Charset":"GB2312,utf-8;q=0.7,*;q=0.7",
            "Keep-Alive":"115",
            "Connection":"keep-alive"
            }
        return header

    def request(self, url, headers=None, data=None):
        if headers is None:
            header = self.getHeader()

        # setting the data
        req = urllib2.Request(
            url=url,
            headers=header
            )
        # if data is not None:
        #    data = urllib.urlencode(data)

        # start request
        resp = urllib2.urlopen(req, data, self.timeout)
        contents = resp.read()
        resp.close()
        return contents
class xslprocesser:
    workbook = None
    sheetname = 'Sheet0'
    sheetname1 = 'Sheet1'
    sheetInstant = None
    def __init__(self, filename):
        self.workbook = xlrd.open_workbook(filename)
        try:
            self.sheetInstant = self.workbook.sheet_by_name(self.sheetname)
        except:
            self.sheetInstant = self.workbook.sheet_by_name(self.sheetname1)
        self.rownum = self.sheetInstant.nrows
        self.colnum = self.sheetInstant.ncols
    def retrivedata(self, rowstart, rowend, col):
        resultset = []
        for row in range(rowstart, rowend):
            temp = self.sheetInstant.cell(row, col).value
            if type(temp) == types.FloatType:
                temp = str(temp)
            resultset.append(str(temp.replace(u'\xa0', u' ').replace(u'\xef', '')).strip())
        return resultset
        
class MyHTMLParser(HTMLParser):   
    def __init__(self):
        HTMLParser.__init__(self)   
        self.cookie = ''
        self.name = ''
    def handle_starttag(self, tag, attrs):   
        # print "Encountered the beginning of a %s tag" % tag   
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
                            self.cookie = values
                        if variable == 'name':
                            self.name = values
class MyHTMLParser1(HTMLParser):   
    def __init__(self):
        HTMLParser.__init__(self)   
        self.value = []
        self.name = []
        self.isoption = 0
    def handle_starttag(self, tag, attrs):   
        # print "Encountered the beginning of a %s tag" % tag   
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
            self.isoption = 0
def divideByComma(tar):
    resultset = []
    # print type(tar)
    # print tar
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
            # print tar[startPos:endPos]
            resultset.append(tar[startPos:endPos].strip())
            break
        # print tar[startPos:endPos]
        resultset.append(tar[startPos:endPos].strip())
        startPos = endPos + 1
        endPos = tar.find(',', endPos + 1)
    return resultset

def remove_comma(str_):
    if len(str_) > 0:
        if str_[-1] == ',':
            return str_[0:-1]
    return str_
if __name__ == "__main__":
    url = 'http://127.0.0.1:8000/login/?next=/index/'
    diffurl = 'http://127.0.0.1:8000/vulnerability/importDiff/'
    if os.path.exists('../diffs'):
        os.chdir('../diffs')
    else:
        if os.path.exists('diffs'):
            os.chdir('diffs')
        else:
            print 'no such dir as diffs!'
            exit()
       
    conn = Dawn()
    getstr = conn.request(url, None, None)
    hp = MyHTMLParser()
    hp.feed(bytes.decode(getstr))
    hp.close()
    data = {'password':'2012tyytyy', 'username':'yytang', hp.name:hp.cookie}  # 这里是因为网站本身带了cookie，每次要把cookie里面的值作为表单的一部分上传
    data = urllib.urlencode(data)
    getstr = conn.request(url, None, data)
#     xlc_filename = input('请输入excel文件名称（包含后缀）:')
#     xlc_filename = 'E:\\workspace\\pythonTest2\\src\\asteriskresult.xls'
    xlc_filename = 'E:\workspace\pythonTest2\src\Ffmpegresult.xls'
    xslpro = xslprocesser(str(xlc_filename))
    start = int(str(input('请输入开始行号(excel 行数减一):')), 10)
    end = int(str(input('请输入结束行号(excel 行数 不 减一):')), 10)
    print 'start submitting diff files'
    diffResult = []
    
    cves = xslpro.retrivedata(start, end, 0)  # row 0 is the title
    softwares = xslpro.retrivedata(start, end, 1)
    software_versions = xslpro.retrivedata(start, end, 2)
    vuln_files = xslpro.retrivedata(start, end, 3)
    vuln_funcs = xslpro.retrivedata(start, end, 4)
    diff_links = xslpro.retrivedata(start, end, 5)
    contain_versions = xslpro.retrivedata(start, end, 7)
    reuse_versions = xslpro.retrivedata(start, end, 10)
    
    getstrdiff = conn.request(diffurl, None, None)
    hpdiff = MyHTMLParser()
    hpdiff.feed(bytes.decode(getstrdiff))
    hpdiff.close()
    for index in range(0, len(cves)):
        getstr = conn.request(diffurl, None, None)
        soup = BeautifulSoup(getstr, 'lxml')
        cookie = soup.find('input', attrs={'type':'hidden'})
        cookiename = cookie.get('name')
        cookie = cookie.get('value')
        
        cveid = cves[index]
        print cveid
        openfilename = cveid + '.txt'
        software = softwares[index]
        
        if os.path.exists(openfilename) == False:
            diffResult.append('diff file missing! ' + openfilename)
            continue
        difffilepayload = {'cve':cveid, 'software':software, cookiename:cookie, 'vuln_file':vuln_files[index], 'vuln_func':vuln_funcs[index], 'diff_file': open(openfilename, "rb"), 'softwareVersion':software_versions[index], 'contain_version':contain_versions[index], 'reuse_version':reuse_versions[index], 'diff_link':diff_links[index]}
        getstr = conn.request(diffurl, None, difffilepayload)
        if getstr.find('CVE does not exists,please check')!=-1:
            diffResult.append('CVE does not exists'+cveid)
            continue
        if getstr.find('Info exists,please check')!=-1:
            diffResult.append('Already exists '+cveid+'-'+software)
            continue
        if getstr.find('Import successfully')!=-1:
            diffResult.append('Success'+cveid)
        else :
            diffResult.append('Unknown Error.Check the http form '+cveid)
    ''' upload diff file complete'''
    total = 0
    success = 0
    fail = 0
    for item in diffResult:
        if item.find('Success') != -1:
            success += 1
        if item.find('exists') != -1:
            fail += 1
        total += 1
        print item 
    print ('total ' + str(total) + ' success: ' + str(success) + ' fail: ' + str(fail))
