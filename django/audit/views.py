import json
import sqlite3

from django.shortcuts import render
from django.http import FileResponse, HttpResponse, JsonResponse

# Create your views here.

DB_PATH = "../configure/test.db"

def read_db(request, table):
    page = int(request.GET["page"])
    limit = int(request.GET["limit"])
    sort = "ASC" if request.GET["sort"] == "+id" else "DESC"
    filepath = request.GET.get("filepath", "")
    print(page, limit, sort, filepath)
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = bytes
    cur = conn.cursor()
    if not filepath: 
        sql = """select * from {} order by id {} limit {}, {}""".format(table, sort, limit * (page - 1), limit)
    else:
        sql = """select * from {} where filepath like '%{}%' order by id {} limit {}, {}""".format(table, filepath, sort, limit * (page - 1), limit)
    res_list = cur.execute(sql)
    return res_list, cur, conn, filepath

def exit_db(items, cur, conn, table, filepath=""):
    if not filepath:
        sql = """select count(id) from {}""".format(table)
    else:
        sql = """select count(id) from {} where filepath like '%{}%'""".format(table, filepath)
    total = cur.execute(sql).fetchall()[0][0]
    cur.close()
    conn.close()
    content = {
        "total": total,
        "items": items
    }
    response = HttpResponse(json.dumps(content), content_type="application/json")
    response['Access-Control-Allow-Origin'] = '*'  # 允许所有的域名地址
    response["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,PATCH,PUT"  # 允许的请求方式
    return response

def delete(table, delete_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    sql = "delete from {} where id={}".format(table, delete_id)
    cur.execute(sql)
    cur.close()
    conn.commit()
    conn.close()
    response = HttpResponse(json.dumps({}), content_type="application/json")
    response['Access-Control-Allow-Origin'] = '*'  # 允许所有的域名地址
    response["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,PATCH,PUT"  # 允许的请求方式
    return response

def table_open(request):
    res_list, cur, conn, filepath = read_db(request, "open")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['logtime'] = res[5].decode()
        try:
            d['filepath'] = res[6].decode()
        except:
            d['filepath'] = 'encode error'
        d["result"] = res[8].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "open", filepath)
    return response


def table_open_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("open", delete_id)
    return response

def table_close(request):
    res_list, cur, conn, filepath = read_db(request, "close")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['logtime'] = res[5].decode()
        try:
            d['filepath'] = res[6].decode()
        except:
            d['filepath'] = 'encode error'
        d["result"] = res[8].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "close", filepath)
    return response

def table_close_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("close", delete_id)
    return response

def table_read(request):
    res_list, cur, conn, filepath = read_db(request, "read")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['logtime'] = res[5].decode()
        try:
            d['filepath'] = res[6].decode()
        except:
            d['filepath'] = 'encode error'
        try:
            d["fdname"] = res[7].decode()
        except:
            d['fdname'] = 'encode error'
        d["result"] = res[8].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "read", filepath)
    return response

def table_read_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("read", delete_id)
    return response
    

def table_write(request):
    res_list, cur, conn, filepath = read_db(request, "write")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['logtime'] = res[5].decode()
        try:
            d['filepath'] = res[6].decode()
        except:
            d['filepath'] = 'encode error'
        try:
            d["fdname"] = res[7].decode()
        except:
            d['fdname'] = 'encode error'
        d["result"] = res[8].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "write", filepath)
    return response

def table_write_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("write", delete_id)
    return response
    

def table_kill(request):
    res_list, cur, conn, filepath = read_db(request, "kill")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['sig'] = res[6]
        d['pid_killed'] = res[7]
        d['logtime'] = res[8].decode()
        d["result"] = res[10].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "kill", filepath)
    return response


def table_kill_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("kill", delete_id)
    return response

def table_mkdir(request):
    res_list, cur, conn, filepath = read_db(request, "mkdir")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['logtime'] = res[5].decode()
        d['mode'] = res[6]
        d['dirpath'] = res[7].decode()
        d["result"] = res[8].decode()
        d["content_short"] = "123"
        d["content"] = "no"


        items.append(d)
    response = exit_db(items, cur, conn, "mkdir", filepath)
    return response


def table_mkdir_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("mkdir", delete_id)
    return response


def table_fchmodat(request):
    res_list, cur, conn, filepath = read_db(request, "fchmodat")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['mode'] = res[5]
        d['logtime'] = res[7].decode()
        try:
            d['filepath'] = res[8].decode()
        except:
            d['filepath'] = 'encode error'
        d["result"] = res[9].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "fchmodat", filepath)
    return response

def table_fchmodat_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("fchmodat", delete_id)
    return response

def table_fchownat(request):
    res_list, cur, conn, filepath = read_db(request, "fchownat")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['userid'] = res[7]
        d['logtime'] = res[9].decode()
        try:
            d['filepath'] = res[10].decode()
        except:
            d['filepath'] = 'encode error'
        d["result"] = res[11].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "fchownat", filepath)
    return response

def table_fchownat_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("fchownat", delete_id)
    return response

    
def table_unlinkat(request):
    res_list, cur, conn, filepath = read_db(request, "unlinkat")
    items = []
    # id username uid commandname pid logtime filepath opentype openresult
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        d['command'] = res[3].decode()
        d['pid'] = res[4]
        d['mode'] = res[5]
        d['logtime'] = res[7].decode()
        try:
            d['filepath'] = res[8].decode()
        except:
            d['filepath'] = 'encode error'
        d["result"] = res[9].decode()
        d["content_short"] = "123"
        d["content"] = "no"
        items.append(d)
    response = exit_db(items, cur, conn, "unlinkat", filepath)
    return response

def table_unlinkat_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    response = delete("unlinkat", delete_id)
    return response