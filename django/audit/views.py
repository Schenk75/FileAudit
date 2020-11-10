import json
import sqlite3

from django.shortcuts import render
from django.http import FileResponse, HttpResponse, JsonResponse

# Create your views here.

def table_open(request):
    page = int(request.GET["page"])
    limit = int(request.GET["limit"])
    sort = "ASC" if request.GET["sort"] == "+id" else "DESC"

    print(page, limit, sort)

    conn = sqlite3.connect('test.db')
    conn.text_factory = bytes
    cur = conn.cursor()
    sql = "select * from open order by id {} limit {}, {}".format(sort, limit * (page - 1), limit)
    res_list = cur.execute(sql)
    items = []
    # id username uid commandname pid logtime filepath opentype openresult 
    for res in res_list:
        d = dict()
        d['id'] = res[0]
        d['logtime'] = res[5].decode()
        d['username'] = res[1].decode()
        d['uid'] = res[2]
        try:
            d['filepath'] = res[6].decode()
        except:
            d['filepath'] = 'encode error'
        d["content_short"] = "123"
        d["content"] = "no"
        d['command'] = res[3].decode()
        d["result"] = res[8].decode()
        d['pid'] = res[4]
        items.append(d)

    sql = "select count(id) from open"
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
    # response["Access-Control-Allow-Headers"] = "Content-Type"  # 允许的headers
    return response

def table_open_delete(request):
    delete_id = int(request.GET["id"])
    print(delete_id)
    conn = sqlite3.connect('test.db')
    cur = conn.cursor()
    sql = "delete from open where id={}".format(delete_id)
    cur.execute(sql)
    cur.close()
    conn.commit()
    conn.close()
    response = HttpResponse(json.dumps({}), content_type="application/json")
    response['Access-Control-Allow-Origin'] = '*'  # 允许所有的域名地址
    response["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,PATCH,PUT"  # 允许的请求方式
    return response

