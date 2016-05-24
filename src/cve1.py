# -*- coding=utf-8
import os
import urllib
import zipfile
import MySQLdb
from bs4 import BeautifulSoup
import requests
import re
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

PSWD = '123321'
dbname = 'news'
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
soft_list = ['ffmpeg','linux_kernel','firefox','wireshsark']
'''
download all ZIP files under nvd.nist.gov/download.aspx
unzip and put them all into ./arch directory
'''
def download_files():
    if not os.path.exists(r'./arch'):
        os.mkdir('arch')
    if not os.path.exists(r'./xmls'):
        os.mkdir('xmls')
    download_url = 'https://nvd.nist.gov/download.aspx'
    getstr = requests.get(url=download_url,headers = header).content
    soup = BeautifulSoup(getstr,'lxml')
    for tr in soup.find_all('tr', 'xml-feed-data-row'):
        for child in tr.find_all('a'):
            if child.string == 'ZIP':
                href = child.get('href')
                filename = href.split(r'/')[-1]
                urllib.urlretrieve(href, r'arch/'+filename)
    for filename in os.listdir(r'./arch'):
        if re.match('nvdcve-\d\d\d\d.xml.zip', filename) or re.match('nvdcve-2.0-\d\d\d\d.xml.zip', filename) or 'modified' in filename or 'Modified' in filename:
            zip_ = zipfile.ZipFile((r'arch/'+filename),'r')
            zip_.extractall(r'./xmls')
            zip_.close()
def date_compare(date1,date2):
    date1 = date1.split('-')
    date2 = date2.split('-')
    if len(date1) != 3 or len(date2) != 3:
        return 'date format error'
    else:
        if int(date1[0]) > int(date2[0]):
            return -1 #which means date 1 is is newer
        elif int(date1[0]) == int(date2[0]):
            if int(date1[1]) >  int(date2[1]):
                return -1
            elif int(date1[1]) ==  int(date2[1]):
                if int(date1[2]) >  int(date2[2]):
                    return -1
                elif int(date1[2]) ==  int(date2[2]):
                    return 0#which means is the same
                else:
                    return 1# which means date_2 is newer
            else:
                return 1
        else:
            return 1
def get_newest_modified():
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cur.execute('select update_date from vulnerability_cve')
    data = cur.fetchall()
    latest = '1970-01-01'
    for date in data:
        date  = date[0]
        if date_compare(latest, str(date)) == 1:  # means what is retrived is later than latest
            latest = str(date)
    cur.close()
    db.close()
    return latest
def get_cwe(cve,option):
    cwe=''
    if 'modi' in option:
        root = ET.parse('./xmls/nvdcve-2.0-modified.xml').getroot()
        cwe = ''
        for entry in root:
            if entry.attrib['id'] == cve:
                for iter_ in entry.iter():
                    if 'cwe' in iter_.tag:
                        cwe += iter_.get('id') + ';'
                break
    elif 'revi' in option:
        year = cve.split('-')[1]
        if int(year) <= 2002:
            year = 2002
        root = ET.parse('./xmls/nvdcve-2.0-'+str(year)+'.xml').getroot()
        for entry in root:
            if entry.attrib['id'] == cve:
                for iter_ in entry.iter():
                    if 'cwe' in iter_.tag:
                        cwe += iter_.get('id') + ';'
                break
    else:
        print 'option error'
        return None
    if cwe != '':
        cwe = cwe[0:-1]
    return cwe
def retrive_functionname(cve):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cur.execute(r'''select Description from vulnerability_cve where cveid = '%s' ''' %(cve))
    desc = cur.fetchall()[0][0].replace('(','').replace(')','').replace(',','')
    function_in = find_all_subs(desc, ' function in ')
    if function_in[0] == -1:
        pass
    else:
        function_names = ''
        for pos in function_in:
            function_names += rfind_next_word(desc, pos)+';'
        function_names = function_names[0:-1].replace('\\','\\\\').replace(r"'",r"''")
        cur.execute(r''' update vulnerability_info set Vuln_Func = '%s' where cve_id = '%s' ''' %(function_names,cve))
        db.commit()
    cur.close()
    db.close()
    return 1
def rfind_next_word(str_,index):
    if str_[index] == ' ':
        r = str_.rfind(' ',0,index)
        if r != -1:
            return str_[r+1:index]
        else:
            return str_[0:index] 
    else:
        r = str_.rfind(' ',0,index)
        if r!=-1:
            rr = str_.rfind(' ',0,r)
            if rr!=-1:
                return str_[rr+1:r]
            else:
                return str_[0:r]
        else:
            return ''
def retrive_filename(cve):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    
    filenames = ''
    cur.execute(r'''select Description from vulnerability_cve where cveid = '%s' ''' %(cve))
    desc = cur.fetchall()[0][0].replace('(','').replace(')','').replace(',','')
    poses_suffixes = []
    suffixes = ('.c','.h','.cpp','.cc','.js','.idl','.html','.in','.inc')
    for suffix in suffixes:
        pos_suffix = find_all_subs(desc, suffix+' ')
        if pos_suffix[0]!= -1:
            for temp in pos_suffix:
                poses_suffixes.append(temp)
    for pos in poses_suffixes:
        temp = find_this_word(desc, pos)
        if temp.strip() not in suffixes:
            filenames +=temp.strip() +';'
    if len(filenames) != 0:
        filenames = filenames[0:-1].replace('\\','\\\\').replace(r"'",r"''")
        cur.execute(r''' update vulnerability_info set Vuln_File = '%s' where cve_id = '%s' ''' %(filenames,cve))
    db.commit()
    cur.close()
    db.close()
    return 1
def find_all_subs(main_str,sub_str):
    reset = []
    if main_str.find(sub_str) == -1:
        reset.append(-1)
        return reset
    else:
        index = main_str.find(sub_str)
        while index !=-1:
            reset.append(index)
            index = main_str.find(sub_str,index+len(sub_str))
    return reset
def find_this_word(str_,index):
    if str_[index] == ' ':               
        return ''
    else:
        former = str_.rfind(' ',0,index)
        latter = str_.find(' ',index)
        if former != -1:
            if latter != -1:
                return str_[former+1:latter]
            else:
                if str_[-1] == '.':
                    return str_[former+1:-1]
                else:
                    return str_[former+1:]
        else:
            if latter != -1:
                return str_[0:latter]
            else:
                if str_[-1] == '.':
                    return str_[former+1:-1]
                else:
                    return str[former+1:]
def retrive_vers(soft_name,cve):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
        
    cur.execute(r'''select Description from vulnerability_cve where cveid = '%s' ''' %(cve))
    desc = cur.fetchall()[0][0].replace('(','').replace(')','').replace(',','')
    if soft_name == 'ffmpeg':
        begin = find_first_among(desc, ['ffmpeg ','FFmpeg ','FFMpeg ','Libav '],0)
    if soft_name == 'linux_kernel':
        begin = find_first_among(desc, ['Linux '],0)
    if soft_name == 'wireshark':
        begin = find_first_among(desc, ['Wireshark ','wireshark '], 0)
    if soft_name =='firefox':
        begin = find_first_among(desc, ['Mozilla ','Firefox ','Netscape Navigator ','Safari '], 0)
    end = find_first_among(desc, [' on ',' for ',' can ',' incorrectly ',' increments ',' modifies',' modify',' execute',' process',' of ',' initialize',
                                      ' handle','"',' invoke',' cause',' inadvertently ',' check',' although ',' (2)',' assign',' send',' refer',' free',
                                    ' only ',' may','as','su command',' records ',' bdash game ',r' related to',' decode',' associate',' produce',
                                    'IP',' keeps ',' set',' assume',' truncate ',' using ',' contain','possib',' the',' cannot',' insert',' load',' interpret',
                                    ' returns ',' include',' enable',' expect ',' copy the wrong ',' with',' could',' try',' read',' parse',' consider',
                                    'via malformed ICMP ',' running ',' auto',' remote attacker',' tries ',' try',' mishandle',' permit',' misinterpret',
                                    ' does ','as ',' allow',' omit',' preserve',' use',' has',' have',' perform',' accept',' access',' skip',' support',
                                    ' establish','when',' attemp',' do ',' provide',' relies',' improperly',' lack',' miscalculate',' implement',
                                    ' generate',' alllow',' update',' make',' might',' call',' which',' store',' place',' create',' while'],begin)
    if begin != -5:
        result = desc[begin:end].replace('\\','\\\\').replace(r"'",r"''")
        cur.execute(r''' update vulnerability_info set SoftwareVersion = '%s' where cve_id = '%s' ''' %( result , cve))
        db.commit()
    cur.close()
    db.close()
def find_first_among(str_,words,index):
    pos = []
    max_value = 9999999999
    for word in words:
        temp = str_.find(word,index)
        if temp == -1:    
            pos.append(max_value)
        else:
            pos.append(temp)
    result = min(pos)
    if result == max_value:
        return -1
    else:
        return result
def retrive_diffs(soft_name,cve,option):
    global PSWD
    global dbname
    if not os.path.exists('diffs'):
        os.mkdir('diffs')
    flag = 0
    if 'revise' in option:
        year = cve[4:8]
        if int(year)<= 2002:
            year = '2002'
        root = ET.parse('./xmls/nvdcve-' + year +'.xml').getroot()
    if 'modified' in option:
        root = ET.parse('./xmls/nvdcve-modified.xml').getroot()
        
    resultdic = {}
    index = 0 # maintain and mark the number of the diff files that has been downloaded
    urls = ''# collecting the urls that has diffs
    no_diff_url = ''
    best_url = ''
    best_type = 6.0
    best_index = 9999 # maintain the best difffile's index and type
    if soft_name== 'ffmpeg':
        for entry in root:
            if flag == 1:
                break
            if entry.attrib['name'] == cve:
                for refs in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}refs'):
                    if flag == 1:
                        break
                    for ref in refs.iter('{http://nvd.nist.gov/feeds/cve/1.2}ref'):
                        url = ref.attrib['url']
                        if ('git.videolan.org/?p=ffmpeg' in url or 'git.libav.org' in url) and 'Changelog' not in url and 'shortlog' not in url:
                            #this function has been well accomplished
                            no_diff_url += url+' '
                            t_index = index
                            reset,index = process_git_org_code_org(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                        elif 'bugzilla.' in url:#well accomplished
                            no_diff_url += url+' '
                            t_index = index
                            reset,index = process_bugzilla(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                        elif 'github.com' in url:
                            t_index = index
                            no_diff_url += url+' '
                            reset,index = process_github(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                    flag = 1
    elif soft_name== 'wireshark':
        for entry in root:
            if flag == 1:
                break
            if entry.attrib['name'] == cve:
                for refs in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}refs'):
                    if flag == 1:
                        break
                    for ref in refs.iter('{http://nvd.nist.gov/feeds/cve/1.2}ref'):
                        url = ref.attrib['url']
                        if 'code.wireshark.org' in url and 'Changelog' not in url and 'shortlog' not in url:
                            no_diff_url += url+' '
                            t_index = index
                            reset,index = process_git_org_code_org(cve, url,index)
                                 
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                        elif 'anonsvn.wireshark.org' in url:#����Ѿ�����ɺ��ˣ�ֻ����1��ҳ���������ļ�����Ŀ¼����������
                            pass
                        elif'bugs.wireshark.org' in url:#this has been well complished
                            t_index = index
                            no_diff_url += url+' '
                            reset,index = process_bugzilla(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                    flag = 1
    elif soft_name== 'linux_kernel':
        for entry in root:
            if flag == 1:
                break
            if entry.attrib['name'] == cve:
                for refs in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}refs'):
                    if flag == 1:
                        break
                    for ref in refs.iter('{http://nvd.nist.gov/feeds/cve/1.2}ref'):
                        url = ref.attrib['url']
                        if 'git.kernel.org' in url:#�����и����⣬diff�ļ���--- a +++ b���治���л��У��������ڻ����ô���
                            no_diff_url += url+' '
                            t_index = index
                            reset,index = process_git_linux(cve, url,index)
                                 
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                        if 'github.com' in url:
                            t_index = index
                            no_diff_url += url+' '
                            reset,index = process_github(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                        if 'bugzilla.redhat.com' in url:
                            t_index = index
                            no_diff_url += url+' '
                            reset,index = process_bugzilla(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                    flag = 1
    elif soft_name == 'firefox':
        for entry in root:
            if flag == 1:
                break
            if entry.attrib['name'] == cve:
                for refs in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}refs'):
                    if flag == 1:
                        break
                    for ref in refs.iter('{http://nvd.nist.gov/feeds/cve/1.2}ref'):
                        url = ref.attrib['url']
                        if 'bugzilla.mozilla.org' in url:#well accomplished
                            no_diff_url += url+' '
                            t_index = index
                            reset,index = process_bugzilla(cve, url,index)
                                
                            for item in reset:
                                if reset[item] < best_type:
                                    best_index = item
                                    best_type = reset[item]
                                    best_url = url
                            resultdic.update(reset)
                            if index > t_index:
                                urls += url+' '
                    flag = 1
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    if len(resultdic) == 1:
        if urls[-1] == ' ':
            urls = urls[0:-1]
        sql = '''update vulnerability_info set Diff_Link = '%s',Diff_File = '%s',vuln_type = '%s',HasPatch = '1' where cve_id = '%s' '''%(urls,'diffs/'+cve+'(0).txt',str(resultdic[0]),cve)
    elif len(resultdic) == 0:
        if no_diff_url == '':
            sql = '''update vulnerability_info set Diff_Link = null,vuln_type = null,HasPatch = '0' where cve_id = '%s' '''%(cve)
        else:
            if no_diff_url[-1] == ' ':
                no_diff_url = no_diff_url[0:-1]
            sql = '''update vulnerability_info set Diff_Link = '%s',vuln_type = null,HasPatch = '0' where cve_id = '%s' '''%(no_diff_url,cve)
    elif len(resultdic) >1:#best_type must be smaller than 6.0
        if urls[-1] == ' ':
            urls = urls[0:-1]
        if best_type == 3.0:
            file_names = ''
            for item in resultdic:
                if resultdic[item] == 3.0:
                    file_names += cve+'('+str(item)+').txt;'
            file_names = file_names[0:-1]
            sql = ''' update vulnerability_info set Diff_Link = '%s',Diff_File = '%s',vuln_type = '3.0',HasPatch = '1' where cve_id = '%s' '''%(urls,'diffs/'+file_names,cve)
        if best_type == 4.0:
            file_names = cve+'(0).txt'# just pick the first one in the consideration that that are all just the same
            sql = ''' update vulnerability_info set Diff_Link = '%s',Diff_File = '%s',vuln_type = '4.0',HasPatch = '1' where cve_id = '%s' '''%(urls,'diffs/'+file_names,cve)
        if best_type < 3.0:
            sql = ''' update vulnerability_info set Diff_Link = '%s',Diff_File = '%s',vuln_type = '%s',HasPatch = '1' where cve_id = '%s' '''%(best_url,'diffs/'+cve+'('+str(best_index)+').txt',str(best_type),cve)
    if sql[sql.find("cve_id = '")+len("cve_id = '"):sql.find("cve_id = '")+len("cve_id = '")+13] != cve:
        print sql[sql.find("cve_id = '")+len("cve_id = '"):sql.find("cve_id = '")+len("cve_id = '")+13],cve,'WARNING!!'
    cur.execute(sql)
    db.commit()
    cur.close()
    db.close()

def process_git_linux(cve,url,diff_count):
    getstr = requests.get(url=url).content
    soup = BeautifulSoup(getstr,'lxml')
    diff = soup.find('table',class_='diff')
    diff_files=[]
    diff_contents = []
    diction = {}
    if diff==None:
        return diction,diff_count
    else:
        for header in diff.find_all('div',class_='head'):
            diff_files.append(header.find('a').string)
        diff_contents = get_git_linux_diff_plainfile(diff)
        if len(diff_files)!=len(diff_contents):
            print 'diff names and contents do not match up! '+url
        for index in xrange(len(diff_files)):
            diff_funcs = get_plain_difffile_functionname(diff_contents[index])
            type_=type_judge(cve, diff_funcs, [diff_files[index]],diff_contents[index])
            if type_ == 1.1 or type_ == 2.2  or type_ == 2.1 or type_ == 1.2 or type_ == 1.3:
                pass
            else:
                if cve in getstr:
                    type_ = 3.0
            diction[diff_count] = type_
            write_plain_file(cve, diff_contents[index],diff_count)
            diff_count += 1
    return diction,diff_count
def get_git_linux_diff_plainfile(diff):
    reset = []
    tem = ''
    flag = 0
    for div in diff.find_all('div'):
        if flag == 0:
            if div.get('class') == ['head']:
                for string in div.strings:
                    if string == '--- a/' or string == '+++ b/':
                        tem += string
                    else:
                        tem += string+'\n'
                    flag = 1
                continue
        if flag == 1:
            if div.get('class') == ['head']:
                reset.append(tem)
                tem = ''
                for string in div.strings:
                    if string == '--- a/' or string == '+++ b/':
                        tem +=string
                    else:
                        tem += string+'\n'
            else:
                tem += div.string+'\n'
    reset.append(tem)
    return reset

def process_git_org_code_org(cve,url,diff_count):
    getstr = requests.get(url = url,headers = header).content
    soup = BeautifulSoup(getstr,'lxml')
    table = soup.find('table',class_="diff_tree")
    filenames =  table.find_all('a',class_="list")
    diff_content = ''
    diction = {}
    diff_files = []
    diff_urls = []
    type_ = 0.0
    if len(filenames) >= 1:
        for filename in filenames:
            diff_files.append(filename.string.strip())
        for link in table.find_all('td',class_="link"):
            for as_ in link.find_all('a'):
                if as_.string == 'diff' or as_.string =='patch':
                    diff_urls.append(as_.get('href'))
        if len(diff_files) != len(diff_urls):
            print r'''Filenames and urls don't match'''
            return diction
        for index in xrange(len(diff_files)):
            if 'git.libav.org' in url:
                getstr1 = requests.get(url = 'http://git.libav.org'+diff_urls[index],headers = header).content
            elif 'git.videolan.org' in url:
                getstr1 = requests.get(url = 'http://git.videolan.org'+diff_urls[index],headers = header).content
            elif 'code.wireshark.org' in url:
                getstr1 = requests.get(url = 'https://code.wireshark.org'+diff_urls[index],headers = header).content
            diff_content = get_git_videolan_plain_text(getstr1)
            diff_funcs = get_git_difffile_functionname(getstr1)
            in_diff_files = get_plain_diff_filename(diff_content)
            type_ = type_judge(cve, diff_funcs, in_diff_files,diff_content)
            if type_ == 1.1 or type_ == 2.2  or type_ == 2.1 or type_ == 1.2 or type_ == 1.3 or type_ == 2.3:
                pass
            else:
                if cve in getstr:
                    type_ = 3.0
            diction[diff_count] = type_
            write_git_videolan_org_difffiles(getstr1, cve,diff_count)
            diff_count += 1
    return diction,diff_count
def get_git_difffile_functionname(getstr):
    soup = BeautifulSoup(getstr,'lxml')
    body = soup.find('body')
    functionnames = []
    diff_header = body.find('div',class_='patch')
    for child in diff_header.contents:
        if type(child) == type(diff_header):
            if child.attrs['class'] == ['diff', 'chunk_header']:
                string  = child.text.replace(u'\xa0',u' ')
                if '(' in string:
                    functionnames.append(string)
    return functionnames
def get_git_videolan_plain_text(getstr):
    result = ''
    soup = BeautifulSoup(getstr,'lxml')
    body = soup.find('body')
    diff_header = body.find('div',class_='patch')
    for child in diff_header.contents:
        if type(child) == type(diff_header):
            if child.attrs['class'] == ['diff', 'header'] or child.attrs['class'] == ['diff', 'extended_header'] or\
            child.attrs['class'] == ['diff', 'from_file'] or child.attrs['class'] == ['diff', 'to_file'] or\
            child.attrs['class'] == ['diff', 'chunk_header']:
                for string in child.stripped_strings:
                    result += string.replace(u'\xa0',u' ')
                result += '\n'
            else:
                if child.string != None:
                    result += child.string.replace(u'\xa0',u' ')+'\n'
    return result
def write_git_videolan_org_difffiles(getstr,cve,index):#well complished
    file_ = open(r'diffs/'+cve+'('+str(index)+')'+'.txt','w')
    soup = BeautifulSoup(getstr,'lxml')
    body = soup.find('body')
    diff_header = body.find('div',class_='patch')
    for child in diff_header.contents:
        if type(child) == type(diff_header):
            if child.attrs['class'] == ['diff', 'header'] or child.attrs['class'] == ['diff', 'extended_header'] or\
            child.attrs['class'] == ['diff', 'from_file'] or child.attrs['class'] == ['diff', 'to_file'] or\
            child.attrs['class'] == ['diff', 'chunk_header']:
                for string in child.stripped_strings:
                    file_.write(string.replace(u'\xa0',u' '))
                file_.write('\n')
            else:
                if child.string != None:
                    file_.write(child.string.replace(u'\xa0',u' ')+'\n')
    file_.close()
    
def process_github(cve,url,diff_count):
    diction = {}
    getstr = requests.get(url = url).content
    soup = BeautifulSoup(getstr,'lxml')
    diffs = soup.find_all('div',class_='file js-details-container show-inline-notes ')
    if len(diffs) == 0:
        pass
    else:
        for diff in diffs:
            file_info = diff.find('div',class_='file-info')
            filename = file_info.find('span',class_='user-select-contain')
            filename = filename.string.strip()
            difffuncs= get_github_difffile_functionname(getstr,diff.get('id'))
            diff_content = get_github_diff_file(getstr, diff.get('id'))
            type_ = type_judge(cve, difffuncs, [filename],diff_content)
            if type_ == 1.1 or type_ == 1.2 or type_ == 1.3 or type_ == 2.2  or type_ == 2.1:
                pass
            else:
                if cve in getstr:
                    type_ = 3.0
            if diff_content != '':
                write_github_difffile(cve, getstr,diff.get('id'),diff_count)
                diction[diff_count] = type_
                diff_count += 1
    return diction,diff_count
def get_github_difffile_functionname(getstr,diff_id):
    soup = BeautifulSoup(getstr,'lxml')
    functionnames = []
    diff = soup.find('div',id = diff_id)
    for name in diff.find_all('td',class_='blob-code blob-code-inner blob-code-hunk'):
        functionnames.append(name.string)
    return functionnames
def get_github_diff_file(getstr,diff_id):
    result = ''
    soup = BeautifulSoup(getstr,'lxml')
    body = soup.find('body')
    diff = body.find('div',id=diff_id)
    file_info = diff.find('div',class_='file-info')
    filename = file_info.find('span',class_='user-select-contain')
    filename = filename.string.strip()
    diff_header = diff.find('div',class_='data highlight blob-wrapper')
    if diff_header == None:
        print 'github file null'
        return result
    for child in diff_header.descendants:
        if child.name == 'span' and child.get('class') ==['blob-code-inner']:
            for string in child.strings:
                result += string.replace(u'\xa0',u' ')
            result += '\n'
        elif child.name == 'td' and child.get('class') == ['blob-code','blob-code-inner','blob-code-hunk']:
            result += child.string.replace(u'\xa0',u' ')+'\n'
    return result
def write_github_difffile(cve,getstr,diff_id,diff_count):
    soup = BeautifulSoup(getstr,'lxml')
    body = soup.find('body')
    diff = body.find('div',id=diff_id)
    file_info = diff.find('div',class_='file-info')
    filename = file_info.find('span',class_='user-select-contain')
    filename = filename.string.strip().encode('ascii',errors='ignore')
    file_ = open(r'diffs/'+cve+'('+str(diff_count)+').txt','w')
    file_.write('+++ '+filename+'\n')
    file_.write('--- '+filename+'\n')
    diff_header = diff.find('div',class_='data highlight blob-wrapper')
    for child in diff_header.descendants:
        if child.name == 'span' and child.get('class') ==['blob-code-inner']:
            for string in child.strings:
                file_.write(string.replace(u'\xa0',u' '))
            file_.write('\n')
        elif child.name == 'td' and child.get('class') == ['blob-code','blob-code-inner','blob-code-hunk']:
            file_.write(child.string.replace(u'\xa0',u' ')+'\n')
    file_.close()
    

def process_bugzilla(cve,url,diff_count):
    getstr = requests.get(url=url).content
    soup = BeautifulSoup(getstr,'lxml')
    diff_urls = []
    diction = {}
    if 'buglist.cgi' in url:
        diff_rows = []
        bug_ids = url[url.find('bug_id=') + len('bug_id='):].split(',')
        for bug_id in bug_ids:
            num1page = requests.get(url='https://bugzilla.mozilla.org/show_bug.cgi?id='+bug_id,headers = header).content
            temp_soup =  BeautifulSoup(num1page,'lxml')
            temp_rows = temp_soup.find_all('tr',class_='bz_contenttype_text_plain bz_patch')
            for temp_diff in temp_rows:
                diff_rows.append(temp_diff)
        del temp_diff
        del temp_rows
        del temp_soup
        del num1page
        del bug_id
    else:
        diff_rows = soup.find_all('tr',class_='bz_contenttype_text_plain bz_patch')
    if len(diff_rows) >= 1:
        for diff_file in diff_rows:
            for links in diff_file.find_all('a',attrs = {'title':'View the content of the attachment'}):
                if links.attrs.has_key('href'):
                    if 'bugs.wireshark.org/bugzilla/' in url:
                        diff_urls.append('https://bugs.wireshark.org/bugzilla/' + links.get('href'))
                        break
                    elif 'bugzilla.redhat.com/' in url:
                        diff_urls.append('https://bugzilla.redhat.com/'+links.get('href'))
                        break
                    elif 'bugzilla.mozilla.org' in url:
                        diff_urls.append('https://bugzilla.mozilla.org/'+links.get('href'))
                        break
    elif len(diff_rows) == 0:
        if '@@' in getstr:
            pass
        else:#ֱ�Ӹ���һ��2��ҳ������
            soup = BeautifulSoup(getstr,'lxml')
            for file_link in soup.find_all('a'):
                #print file_links.string
                if file_link.string == 'View':
                    if 'bugzilla.redhat.com/' in url:
                        diff_urls.append('https://bugzilla.redhat.com/'+file_link.get('href'))
                        break
                    if 'bugs.wireshark.org/bugzilla/' in url:
                        diff_urls.append('https://bugs.wireshark.org/bugzilla/'+file_link.get('href'))
                        break
                    if 'bugzilla.mozilla.org' in url:
                        diff_urls.append('https://bugzilla.mozilla.org/'+file_link.get('href'))#diff_urls ��diff_links�ĳ���Ӧ������ȵ�
                        break
            if len(diff_urls) ==0:
                return diction,diff_count
    for index in xrange(len(diff_urls)):# diff_urls and diff_files don't have to be the same size
        diff_content = requests.get(url = diff_urls[index],headers = header).content
        diff_files = get_plain_diff_filename(diff_content)
        diff_funcs = get_plain_difffile_functionname(diff_content)
        type_ = type_judge(cve, diff_funcs, diff_files,diff_content)
        if type_ == 1.1 or type_ == 2.2  or type_ == 2.1 or type_ == 1.2 or type_ == 1.3:
            pass
        else:
            if cve in getstr:
                type_ = 3.0
        write_plain_file(cve, diff_content,diff_count)
        diction[diff_count] = type_
        diff_count += 1
    return diction,diff_count
def write_plain_file(cve,getstr,index):
    file_ = open(r'diffs/'+cve+'('+str(index)+')'+'.txt','w')
    file_.write(getstr)
    file_.close()
def get_plain_diff_filename(diff_content):
    lines = diff_content.split('\n')
    file_names = []
    for eachline in lines:
        if (eachline[0:2] == '--' and '.' in eachline) or (eachline[0:2] == '++' and '.' in eachline):
            file_names.append(eachline.split(' ')[-1])
    return file_names
def get_plain_difffile_functionname(getstr):
    lines = getstr.split('\n')
    func_result = []
    for line in lines:
        if line[0:2] == '@@' or line[1:3] == '@@':
            func_result.append(line)
    return func_result
'''
diff_func is ought to be a list which is retrived from diff chunk header
diff_file is the name of the diff file which is ought to show its path in the source code
'''
def type_judge(cve,diff_funcs,diff_files,plain_text):
    global PSWD
    global dbname
    if type(diff_funcs) != type([1,2]) or type(diff_files)!= type([1,2]):
        print 'diff_funcs and files must be list'
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cur.execute(r'''select Vuln_Func from vulnerability_info where cve_id = '%s' ''' %(cve))
    db_funcs = cur.fetchall()[0][0]
    cur.execute(r'''select Vuln_File from vulnerability_info where cve_id = '%s' ''' %(cve))
    db_files = cur.fetchall()[0][0]
    if db_files != None:
        db_files = db_files.split(';')
    else:
        db_files = []
    if db_funcs !=None:
        db_funcs = db_funcs.split(';')
    else:
        db_funcs = []
    print 'db_file:',db_files,'db_func:',db_funcs,'diff_file:',diff_files,'diff_func',diff_funcs
    type_ = 0
    if db_funcs != []:
        if check_if_function_match(diff_funcs, db_funcs):
            type_ = 1.1
        else:
            if check_if_in(db_funcs, plain_text) or check_if_intersect(diff_files, db_files):
                type_ = 1.2
            else:
                type_ = 1.3
    else:
        if db_files !=[]:
            if len(db_files) == 1:
                if get_suffix(db_files[0]) == '.h':
                    if check_if_intersect(db_files, diff_files):
                        type_ = 2.1
                    else:
                        type_ = 2.3
                else:
                    type_ = 4.0
            else:
                flag = 0
                for db_file in db_files:
                    if get_suffix(db_file) != '.h':
                        flag = 1
                if flag == 0: # all db_file's suffix are .h
                    if check_if_intersect(db_files, diff_files):
                        type_ = 2.2
                    else:
                        type_ = 4.0
                else:
                    type_=4.0
        else:
            type_ = 4.0
    cur.close()
    db.close()
    return type_
def get_suffix(str_):
    pos = str_.rfind('.')
    return str_[pos:]
def check_if_function_match(list1,list2):
    if len(list1) == 0  or len(list2) == 0:
        return False
    else:
        for item1 in list1:
            for item2 in list2:
                if not check_if_match(item1, item2):
                    return False
    return True
def check_if_intersect(list1,list2):
    for item_1 in list1:
        for item_2 in list2:
            if check_if_match(item_1, item_2):
                return True
    return False
def check_if_match(str1,str2):
    if str1 in str2 or str2 in str1:
        return True
    else:
        return False
def check_if_in(list_,str_):
    for item in list_:
        if item in str_ or str_ in item:#���ǵ���strһ�㶼�Ǻ�ȫ��
            return True
    return False
'''
Modified.xml  maintains the data of latest 7 days ahead from now
'''
def update_table():
    global PSWD
    global dbname
    if not os.path.exists(r'./xmls/'):
        os.mkdir('xmls')
    if not os.path.exists(r'./arch/'):
        os.mkdir('arch')
    if PSWD == '':
        PSWD = raw_input('Please input your password to database:')
    if dbname == '':
        dbname = raw_input('Please input your database name:')
    
#     download_url = 'https://nvd.nist.gov/download.aspx'
#     getstr = requests.get(url=download_url,headers = header).content
#     soup = BeautifulSoup(getstr,'lxml')
#     for tr in soup.find_all('tr', 'xml-feed-data-row'):
#         for child in tr.find_all('a'):
#             if child.string == 'ZIP':
#                 href = child.get('href')
#                 if 'Modified.xml.zip' in href:
#                     filename = href.split(r'/')[-1]
#                     urllib.urlretrieve(href, r'arch/'+filename)
#                     zip_ = zipfile.ZipFile((r'arch/'+filename),'r')
#                     zip_.extractall(r'./xmls')
#                     zip_.close()
    his_first_modified  = '9999-99-99'
    root = ET.parse(r'xmls/nvdcve-modified.xml').getroot()
    for entry in root:
        modified = entry.attrib['modified']
        if date_compare(modified, his_first_modified) == 1:
            his_first_modified = modified
    my_last_modified = get_newest_modified()
    if date_compare(my_last_modified, his_first_modified) == 1:
        print 'Out of the modified.xls date,need to revise'
        revise()
    else:
        print 'Within the modified.xml dates,do not have to revise'  

    option = 'modified'
    for entry in root:
        insert_or_update(entry,option)
def revise():
#     download_files()
    option = 'revised'
    for filename in os.listdir(r'./xmls/'):
        if re.match('nvdcve-\d\d\d\d.xml', filename):
            root = ET.parse('./xmls/'+filename).getroot()
            for entry in root:
                insert_or_update(entry,option)
def insert_or_update(entry,option):
    global PSWD
    global dbname
    flag = 0
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    sql = r''' select * from vulnerability_cve where CVEID = '%s' ''' % cve
    cur.execute(sql)
    check_if_in = cur.fetchall()
    if check_if_in == ():# this cve doesn't exist in the database
        print option,cve,'do not exist in cve'
        insert_cve(entry,option)
        flag = 1
        '''cve is done'''
    sql = r''' select * from vulnerability_cvss where cveid_id = '%s' ''' % cve
    cur.execute(sql)
    check_if_in = cur.fetchall()
    if check_if_in == ():# this cve doesn't exist in the database
        print option,cve,'do not exist in cvss'
        insert_cvss(entry)
        ''' cvss is done'''
    sql = r''' select * from vulnerability_info where CVE_ID = '%s' ''' % cve
    cur.execute(sql)
    check_if_in = cur.fetchall()
    if check_if_in == ():# this cve doesn't exist in the database
        insert_info(entry,option)
        '''info is done'''
    # when executed here for the dealt cve entry it must exist in all 3 tables
    if flag == 0:
        cur.execute(r''' select update_date from vulnerability_cve where CVEID = '%s' '''% cve)
        old_update_date = str(cur.fetchall()[0][0])
        if entry.attrib.has_key('modified'):
                new_update_date = entry.attrib['modified']
        else:
            print 'xml '+ cve + ' missing modified'
        if date_compare(old_update_date, new_update_date) == 1:
            print option,cve,'needs updated'
            update_cve(entry, option)
            ''' cve id done'''
            update_cvss(entry)
            '''cvss is done'''
            update_info(entry,option)   
    cur.close()
    db.close()   
def insert_cve(entry,option):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    diction = {'User':'admin1','CVEID':cve}
    if entry.attrib.has_key('modified'):
        diction['update_date'] = entry.attrib['modified']
    descs = entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}descript')
    for desc in descs:
        if desc.attrib['source'] == 'cve':
            diction['Description'] = desc.text.replace('\\','\\\\').replace(r"'",r"''")
    if entry.attrib.has_key('CVSS_score'):
        diction['CVSS'] = entry.attrib['CVSS_score']
    else:
        diction['CVSS'] = '-1.0'
    if entry.attrib.has_key('published'):
        diction['Publish_Date'] = entry.attrib['published']
    cwe = get_cwe(cve,option)
    if cwe != '':
        diction['CWEID'] = cwe
    sql = 'insert into vulnerability_cve('
    for item in diction:
        sql += item+','
    sql = sql[0:-1] + ') values ('
    for item in diction:
        sql += "'"+diction[item]+"',"
    sql = sql[0:-1]+')'
    cur.execute(sql)
    db.commit()
    cur.close()
    db.close()
def update_cve(entry,option):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    diction = {'User':'admin1'}
    if entry.attrib.has_key('modified'):
        diction['update_date'] = entry.attrib['modified']
    descs = entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}descript')
    for desc in descs:
        if desc.attrib['source'] == 'cve':
            diction['Description'] = desc.text.replace('\\','\\\\').replace(r"'",r"''")
    if entry.attrib.has_key('CVSS_score'):
        diction['CVSS'] = entry.attrib['CVSS_score']
    else:
        diction['CVSS'] = '-1.0'
    if entry.attrib.has_key('published'):
        diction['Publish_Date'] = entry.attrib['published']
    cwe = get_cwe(cve,option)
    if cwe!= '':
        diction['CWEID'] = cwe
    sql = 'update vulnerability_cve set '
    for item in diction:
        sql += item+" = '"
        sql += diction[item]+"',"
    sql = sql[0:-1] +" where CVEID = '" + cve+"'"
    cur.execute(sql)
    db.commit()
    cur.close()
    db.close()
def insert_cvss(entry):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    cvss_diction = {}
    cvss_diction['cveid_id'] = cve
    if entry.attrib.has_key('CVSS_vector'):
        cvss_vector = entry.attrib['CVSS_vector'][1:-1].split('/')
        for item in cvss_vector:
            if item[0:2] == 'AV':
                cvss_diction['accessVector'] = item.split(':')[1]
                continue
            if item[0:2] == 'AC':
                cvss_diction['accessComplexity'] = item.split(':')[1]
                continue
            if item[0:2] == 'Au':
                cvss_diction['authentication'] = item.split(':')[1]
                continue
            if item[0:2] == 'C:':
                cvss_diction['confidentialImpact'] = item.split(':')[1]
                continue
            if item[0:2] == 'I:':
                cvss_diction['integrityImpact'] = item.split(':')[1]
                continue
            if item[0:2] == 'A:':
                cvss_diction['avalibilityImpact'] = item.split(':')[1]
    if entry.attrib.has_key('severity'):
        cvss_diction['severity'] = entry.attrib['severity'].strip()[0]
    if entry.attrib.has_key('CVSS_version'):
        cvss_diction['version'] = entry.attrib['CVSS_version']
    if entry.attrib.has_key('CVSS_base_score'):
        cvss_diction['baseScore'] = entry.attrib['CVSS_base_score']
    if entry.attrib.has_key('CVSS_impact_subscore'):
        cvss_diction['impactSubscore'] = entry.attrib['CVSS_impact_subscore']
    if entry.attrib.has_key('CVSS_exploit_subscore'):
        cvss_diction['exploitabilitySubscore'] = entry.attrib['CVSS_exploit_subscore']
    cvss_sql = 'insert into vulnerability_cvss ('
    for item in cvss_diction:
        cvss_sql += item+','
    cvss_sql = cvss_sql[0:-1] +') values ('
    for item in cvss_diction:
        cvss_sql += "'" + cvss_diction[item] + "',"
    cvss_sql = cvss_sql[0:-1]
    cvss_sql += ')'
    cur.execute(cvss_sql)
    db.commit()
    cur.close()
    db.close()
def update_cvss(entry):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    cvss_diction = {}
    if entry.attrib.has_key('CVSS_vector'):
        cvss_vector = entry.attrib['CVSS_vector'][1:-1].split('/')
        for item in cvss_vector:
            if item[0:2] == 'AV':
                cvss_diction['accessVector'] = item.split(':')[1]
                continue
            if item[0:2] == 'AC':
                cvss_diction['accessComplexity'] = item.split(':')[1]
                continue
            if item[0:2] == 'Au':
                cvss_diction['authentication'] = item.split(':')[1]
                continue
            if item[0:2] == 'C:':
                cvss_diction['confidentialImpact'] = item.split(':')[1]
                continue
            if item[0:2] == 'I:':
                cvss_diction['integrityImpact'] = item.split(':')[1]
                continue
            if item[0:2] == 'A:':
                cvss_diction['avalibilityImpact'] = item.split(':')[1]
    if entry.attrib.has_key('severity'):
        cvss_diction['severity'] = entry.attrib['severity'].strip()[0]
    if entry.attrib.has_key('CVSS_version'):
        cvss_diction['version'] = entry.attrib['CVSS_version']
    if entry.attrib.has_key('CVSS_base_score'):
        cvss_diction['baseScore'] = entry.attrib['CVSS_base_score']
    if entry.attrib.has_key('CVSS_impact_subscore'):
        cvss_diction['impactSubscore'] = entry.attrib['CVSS_impact_subscore']
    if entry.attrib.has_key('CVSS_exploit_subscore'):
        cvss_diction['exploitabilitySubscore'] = entry.attrib['CVSS_exploit_subscore']
    cvss_sql = 'update vulnerability_cvss set '
    for item in cvss_diction:
        cvss_sql += item+" = '"
        cvss_sql += cvss_diction[item]+"',"
    cvss_sql = cvss_sql[0:-1] +" where cveid_id = '" + cve+"'"
    cur.execute(cvss_sql)
    db.commit()
    cur.close()
    db.close()
def insert_info(entry,option):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    prod_names = []
    for vuln_soft in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}vuln_soft'):
        for prod in vuln_soft.iter('{http://nvd.nist.gov/feeds/cve/1.2}prod'):
            prod_name = prod.attrib['name'].replace('\\','\\\\').replace(r"'",r"''")
            if prod_name not in prod_names:
                cur.execute(r'''insert into vulnerability_info (cve_id,Software) values ('%s','%s') ''' %(cve,prod_name))
                db.commit()
    has_soft = ''# to see if this cve is within the softwares that need to be processed
    flag = 0
    for soft_name in soft_list:
        if flag == 1:
            break
        for prod_name in prod_names:
            if soft_name == prod_name:
                has_soft = soft_name
                flag = 1
                break
    if len(prod_names)!=0:
        print option,cve,'do not exist in info'
        retrive_filename(cve)
        retrive_functionname(cve)
    if has_soft != '':
        retrive_vers(has_soft, cve)
        retrive_diffs(has_soft,cve,option)
    cur.close()
    db.close()
def update_info(entry,option):
    global PSWD
    global dbname
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd=PSWD,db=dbname)
    cur = db.cursor()
    cve = entry.get('name')
    prod_names = []
    for vuln_soft in entry.iter('{http://nvd.nist.gov/feeds/cve/1.2}vuln_soft'):
        for prod in vuln_soft.iter('{http://nvd.nist.gov/feeds/cve/1.2}prod'):
            prod_name = prod.attrib['name'].replace('\\','\\\\').replace(r"'",r"''")
            if prod_name not in prod_names:
                prod_names.append(prod_name)
                cur.execute(r'''select * from vulnerability_info where cve_id = '%s' and Software = '%s' '''%(cve,prod_name))
                flag =cur.fetchall()
                if flag == ():
                    cur.execute(r'''insert into vulnerability_info (cve_id,Software) values ('%s','%s') ''' %(cve,prod_name))
                    db.commit()
    has_soft = ''
    flag = 0
    for soft_name in soft_list:
        if flag == 1:
            break
        for prod_name in prod_names:
            if soft_name == prod_name:
                has_soft = soft_name
                flag = 1
                break
    retrive_filename(cve)
    retrive_functionname(cve)
    if has_soft != '':
        retrive_vers(has_soft, cve)
        retrive_diffs(has_soft, cve,option)
    cur.close()
    db.close()
if __name__ =='__main__':
    update_table()
    print "end"