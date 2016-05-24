#!/usr/bin/python
# -*- coding: utf-8 -*-
import MySQLdb
import xlrd
import types
import sys  
import os
import re
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
        
def importReuse(xlc_filename, start, end):
        xslpro = xslprocesser(xlc_filename)
        print xslpro.rownum
        cves = xslpro.retrivedata(start, end, 0)  # row 0 is the title
        strs = xslpro.retrivedata(start, end, 2)
        nums=xslpro.retrivedata(start, end, 1)
        features = xslpro.retrivedata(start, end, 3)
        db = MySQLdb.connect(charset="utf8", host='localhost', user='root', passwd=passward, db=daname)
        for i in range(0, len(cves)):
            cve = cves[i]
            if cve.find('_') != -1:
                cve = cve.replace('_', '-')
            print cve
            # get file number
            pos1=nums[i].rfind('_')
            pos2=nums[i].rfind('.')
            num=0
            if pos1>-1 and pos2>-1:
#                 num=int(nums[i][pos1+1:pos2])
                num=0
            else:
                results.append(cve + ' wrong number ')
                continue
            cvetemp = cve.replace('-', '_')
            temp = strs[i][len(cvetemp) + 1:].strip()
            pos = temp.find('_')
            software = temp[:pos - 1]
            strpos1 = temp[pos-1:]
            version=re.match(r'([0-9]+_)+[0-9]+',strpos1).group(0)
#             strpos2 = strpos1[strpos1.find('_') + 1:]
#             strpos3 = strpos2[strpos2.find('_') + 1:]
#             version = temp[pos - 1:temp.find(strpos3) - 1]
            version = version.replace('_', '.')
            func = temp[pos + len(version):len(temp) - 13]
            # find info_id_id
           
            cur = db.cursor()
            sqlInfo = "select id from vulnerability_info where cve_id='%s' and Software='%s'" % (cve, software)
            print sqlInfo
            cur.execute(sqlInfo)
            row = cur.fetchone()
            if row == None:
                error = cve + " fail,not found in vulnerability_info"
                errors.append(error)
                results.append(error)
                continue
            info_id = row[0]
              
            # find reuse code
            
            openfilename = cvetemp + '_' + software + version.replace('.', '_') + '_' + func
            if num>0:
                openfilename+='('+str(num)+')'
            openfilename=openfilename+ '_N.txt'
            print openfilename
            if os.path.exists(openfilename) == False:
                results.append(cve + ' reuse file missing! ' + openfilename)
                continue
            file_object = open(openfilename)
            code = None
            try:
                code = file_object.read()[len('diff的N行：\n'):]
            finally:
                file_object.close()
            code = code.replace("'", "\\'")
            sql = "insert into vulnerability_reuse(patch_func,version,code,info_id_id) values('%s','%s','%s',%d)" % (func, version, code, info_id)
#             print sql
            cur.execute(sql)
            cur.close()
              
            # get reuse id
            sqlReuse = """select id from vulnerability_reuse where patch_func="%s" and version='%s' and info_id_id='%s'""" % (func, version, info_id)
            cur = db.cursor()
            cur.execute(sqlReuse)
            print sqlReuse
            row2 = cur.fetchone()
            if row2 == None:
                error = cve + " fail,not found in vulnerability_reuse info_id=" + info_id
                errors.append(error)
                results.append(error)
                continue
            reuse_id = row2[0]
            print reuse_id
            feature = features[i][1:]
            if feature.find('error') != -1:
                error = cve + " fail,feature error"
                errors.append(error)
                results.append(error)
                continue
            if len(feature) < 1:
                error = cve + " fail,no fearure"
                errors.append(error)
                results.append(error)
                continue
            featureList = feature.split(',')
              
            for m in featureList:
                cur = db.cursor()
                sqlReuseFeature = "insert into vulnerability_reusefeature(feature_id,reuse_id) values('%s',%d)" % (m, reuse_id)
#                 print sqlReuseFeature
                cur.execute(sqlReuseFeature)
                cur.close()
                
            results.append(cve + "Success")
        db.commit()
        db.close()
        

if __name__ == '__main__':
    import sys
    print sys.getdefaultencoding()
    if os.path.exists('../reuse_N'):
        os.chdir('../reuse_N')
    else:
        if os.path.exists('reuse_N'):
            os.chdir('reuse_N')
        else:
            print 'no such dir as reuse_N!'
            exit()
    start = int(str(input('请输入开始行号(excel 行数减一):')), 10)
    end = int(str(input('请输入结束行号(excel 行1数 不 减一):')), 10)
    filename = 'E:\workspace\pythonTest2\src\excel\linux-reuse.xlsx'
    importReuse(filename, start, end)
    
    for error in errors:
        print error
    
    print 'end import'
    
    success = 0
    total = 0
    error = 0
    no = 0
    for item in results:
        if item.find('Success') != -1:
            success += 1
        if item.find('error') != -1:
            error += 1
        if item.find('no fearure') != -1:
            no += 1
        total += 1
        print item
    print ('total ' + str(total) + ' success: ' + str(success) + ' fail: ' + str(total - success) + ' error ' + str(error) + ' no feature ' + str(no))
