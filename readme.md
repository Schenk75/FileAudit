# File Auditing

## Requirements

- gcc 7.5.0
- sqlite 3.22.0
- python 3.6.9

### Install Sqlite3

```bash
aptitude install sqlite3
aptitude install libsqlite3-dev
# or
apt install libsqlite3-0=3.22.0-1ubuntu0.4
apt install sqlite3
apt install libsqlite3-dev
```

## Build Kernel Module

### Init

```bash
make
insmod AuditModule.ko
```

### Log

```bash
dmesg
dmesg -c // clear the log
```

### Exit

```bash
rmmod AuditModule.ko
```

### Illustration

the following sentence reloads the system call

```C
sys_call_table[__NR_openat] = (demo_sys_call_ptr_t) hacked_openat;
```

## Build Audit Module

```bash
gcc auditdemo.c db.h -l sqlite3 -o audit
```

## Start Django

```bash
python manage.py runserver 0.0.0.0:4000
```

## Start Frontend

```bash
npm install --registry=https://registry.npm.taobao.org
npm run dev
```

## Todo List

- functions in db.h to be completed except insert_record()