#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import xlrd
import types
import sys  
import os
daname = 'news'
passward = '123321'
errors = []
results = []

def updatediff_file():
    db = MySQLdb.connect(charset="utf8", host='localhost', user='root', passwd=passward, db=daname)
    cur = db.cursor()
    sqlInfo = "select * from vulnerability_info where Diff_File is null"
    print sqlInfo
    cur.execute(sqlInfo)
    rows = cur.fetchall()
    num = 0
    for row in rows:
        cur = db.cursor()
        i = 0
        cve = row[14]
        sql = "update vulnerability_info set Diff_File='%s' where cve_id='%s'" % ("diffs/" + cve + ".txt", cve)
        print sql
        cur.execute(sql)
        cur.close()
        db.commit()
        num = num + 1
        break
    cur.close()
    db.commit()
    results.append("Success")
    db.close()          
        

if __name__ == '__main__':
    print sys.getdefaultencoding()
    updatediff_file()
    
    for error in errors:
        print error
    
    print 'end import'
    
    success = 0
    total = 0
    for item in results:
        if item.find('Success') != -1:
            success += 1
        total += 1
        print item
    print ('total ' + str(total) + ' success: ' + str(success) + ' fail: ' + str(total - success))
