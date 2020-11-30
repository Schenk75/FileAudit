#! /bin/bash

gcc auditdemo.c db.h -l sqlite3 -o audit
echo "audit build done"
