#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import xlrd
import types
import sys  

daname = 'news'
passward = '123321'

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
            print temp
        return resultset
        
def importFeature(xlc_filename, start, end):
        xslpro = xslprocesser(xlc_filename)
        print xslpro.rownum
        ids = xslpro.retrivedata(start, end, 0)  # row 0 is the title
        features = xslpro.retrivedata(start, end, 1)
        db = MySQLdb.connect(charset="utf8", host='localhost', user='root', passwd=passward, db=daname)
        for i in range(0, len(ids)):
            cur = db.cursor()
            sql = "insert into vulnerability_feature(id,feature) values('%s','%s')" % (ids[i], features[i])
            print sql
            cur.execute(sql)
            cur.close()
        db.commit()
        db.close()
        
def getFeatures():  
    try:
        db = MySQLdb.connect(charset="utf8", host='localhost', user='root', passwd=passward, db=daname)
        cur = db.cursor()
        cur.execute("select * from vulnerability_feature")
        row = cur.fetchall()
        for r in row:
            print r[0], r[1]
        cur.close()
        db.close()
    except Exception , e:
        print e      

if __name__ == '__main__':
    import sys
    print sys.getdefaultencoding()
    str1 = input('请输入开始行号(excel 行数减一):')
    start = int(str(str1), 10)
    end = int(str(input('请输入结束行号(excel 行1数 不 减一):')), 10)
    filename = 'E:\\myWork\\bishe\\testData\\FeatureId.xlsx'
    importFeature(filename, start, end)
    getFeatures()
