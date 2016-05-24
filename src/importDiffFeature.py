#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import xlrd
import types
import sys  
from _sqlite3 import Row
# 导入diff特征
# 表格需要sheet name Sheet0
# 注意表格格式
daname = 'news'
passward = '123321'
errors = []
results = []
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
            resultset.append(temp)
        return resultset
        
def importDiffFeature(xlc_filename, start, end):
        xslpro = xslprocesser(xlc_filename)
        print xslpro.rownum
        cves = xslpro.retrivedata(start, end, 0)  # row 0 is the title
        numbers = xslpro.retrivedata(start, end, 1)
        features = xslpro.retrivedata(start, end, 3)
        db = MySQLdb.connect(charset="utf8", host='localhost', user='root', passwd=passward, db=daname)
        for i in range(0, len(cves)):
            pos1=numbers[i].rfind('_')
            pos2=numbers[i].rfind('.')
            number=int(numbers[i][pos1+1:pos2])
#             number = int(numbers[i].strip()[-3:][:1])
            print number
            cur = db.cursor()
            sqlInfo = "select id from vulnerability_info where cve_id='%s'" % cves[i]
            print sqlInfo
            cur.execute(sqlInfo)
            row = cur.fetchone()
            if row == None:
                error = cves[i] + " fail,not found in vulnerability_info"
                errors.append(error)
                results.append(error)
                continue
            info_id = row[0]
            if len(features[i]) < 1:
                results.append(cves[i] + " no feature")
                continue
            if features[i].find('error')!=-1:
                results.append(cves[i] + " error feature")
                continue
            feature = features[i][1:]
            featureList = feature.split(',')
            for m in featureList:
                cur = db.cursor()
                sql = "insert into vulnerability_difffeature(number,feature_id,info_id_id) values(%d,'%s',%d)" % (number, m, int(info_id))
                print sql
                cur.execute(sql)
                cur.close()
            
            results.append(cves[i] + " Success")
        db.commit()
        db.close()

if __name__ == '__main__':
    import sys
    print sys.getdefaultencoding()
    str1 = input('请输入开始行号(excel 行数减一):')
    start = int(str(str1), 10)
    end = int(str(input('请输入结束行号(excel 行1数 不 减一):')), 10)
#     filename = 'E:\workspace\pythonTest2\src\excel\Ffmpeg_feature.xlsx'
#     filename = 'E:\workspace\pythonTest2\src\excel\linux_feature.xlsx'
    filename = 'E:\workspace\pythonTest2\src\excel\wireshark_feature.xlsx'
    importDiffFeature(filename, start, end)
    for error in errors:
        print error
    
    print 'end import'
    
    success = 0
    total = 0
    no = 0
    error=0
    for item in results:
        if item.find('Success') != -1:
            success += 1
        total += 1
        if item.find('no feature') != -1:
            no += 1
        if item.find('error') != -1:
            error+=1
        print item
    print ('total ' + str(total) + ' success: ' + str(success) + ' fail: ' + str(total - success) + ' no feature ' + str(no) +' error '+ str(error))
