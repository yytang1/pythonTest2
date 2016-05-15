# -*- coding=utf-8
import MySQLdb
from bs4 import BeautifulSoup
import requests

def main(edb_id):
    print edb_id
    url = 'https://www.exploit-db.com/exploits/'+edb_id+'/'
    download_url = 'https://www.exploit-db.com/download/'+edb_id
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
    r = requests.get(url,headers = header)
    if 'Next Exploit' not in r.content:
        return 'Reach end'
    try:
        soup = BeautifulSoup(r.content,'lxml')
    except:
        return 'No cve'
    cve = ''
    author = ''
    publish = ''
    for td in soup.find_all('td'):
        if td.text!=None:
            if 'CVE' in td.text:
                cve =  'CVE-'+td.text.strip().split(' ')[-1]
            if 'Publish' in td.text:
                publish = td.text.strip().split(' ')[-1]
    for meta in soup.find_all('meta',attrs={'name':'author'}):
        author = meta.get('content').replace(r"'",r"''")
    if cve == 'CVE-N/A' or cve == '':
        return 'No cve'
    elif '..' in cve:
        cve = []
        for td in soup.find_all('td'):
            if td.text!=None:
                if 'CVE' in td.text:
                    a = td.find('a')
                    cves = a.get('data-content')
                    a_soup = BeautifulSoup(cves,'lxml')
                    for t_cve in a_soup.find_all('a'):
                        if len(t_cve.text.strip()) <= 14:
                            cve.append('CVE-'+t_cve.text.strip()) 
    if author == '':
        author = 'None'
    db = MySQLdb.connect(host='localhost',user='root',passwd='123321',db='news')
    cur = db.cursor()
    if publish == '':
        if len(cve) == 1:
            sql = r'''insert into vulnerability_exploit (edb_id,link,down_link,author,publish_date,cve_id) values ('%s','%s','%s',Null,'%s') ''' %(edb_id,url,download_url,author,cve)
            print sql
            cur.execute(sql)
            db.commit()
        elif len(cve) > 1:
            for t_cve in cve:
                sql = r'''insert into vulnerability_exploit (edb_id,link,.down_link,author,publish_date,cve_id) values ('%s','%s','%s',Null,'%s') ''' %(edb_id,url,download_url,author,t_cve)
                print sql
                cur.execute(sql)
                db.commit()
    else:
        if len(cve) == 1:
            sql = r'''insert into vulnerability_exploit (edb_id,link,down_link,author,publish_date,cve_id) values ('%s','%s','%s','%s','%s') ''' %(edb_id,url,download_url,author,publish,cve)
            print sql
            cur.execute(sql)
            db.commit()
        elif len(cve) >1:
            for t_cve in cve:
                sql = r'''insert into vulnerability_exploit (edb_id,link,down_link,author,publish_date,cve_id) values ('%s','%s','%s','%s','%s') ''' %(edb_id,url,download_url,author,publish,t_cve)
                print sql
                cur.execute(sql)
                db.commit()

    cur.close()
    db.close()
    return 1
def get_highest_edb_id():
    db = MySQLdb.connect(host='127.0.0.1',user='root',passwd='123321',db='news')
    cur = db.cursor()
    cur.execute("select edb_id from vulnerability_exploit")
    data = cur.fetchall()
    max_ = 0
    for edb_id in data:
        edb_id = edb_id[0]
        if int(edb_id) > max_:
            max_ = int(edb_id)
    cur.close()
    db.close()
    return max_
def update_edb():
    int_edb_id = get_highest_edb_id() + 1
    while True:
        edb_id = str(int_edb_id)
        reset = main(edb_id)
        if reset == 'Reach end':
            break
        int_edb_id += 1
if __name__ == '__main__':
    update_edb()