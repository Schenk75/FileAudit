#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

sqlite3 *db = NULL;

void create_table(char *filename);
void close_table(void);
void insert_record(char *sql);
void insert_open(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, char *type);
void insert_read(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *fd_name, char *result);
void insert_write(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *fd_name, char *result);
void insert_close(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *type, char *result);
void insert_kill(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int gid, int sig, int pid_);
void insert_mkdir(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int mode);
void insert_fchmodat(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int mod, int dirfd);
void insert_fchownat(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int flags, int dirfd, int gid, int user_id);

void create_table(char *filename)
{
    char *sql;
    char *zErrMsg = 0;
    int rc;

    rc = sqlite3_open(filename, &db);
    // rc = sqlite3_open_v2(filename,&db,SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc)
    {
        fprintf(stderr,"can't open database%s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
    }
    // sql =  "CREATE TABLE save_data(num integer primary key, id int, data text, time text)";
    sql = "CREATE TABLE OPEN("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "OPENTYPE       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE READ("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "FDNAME       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE WRITE("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "FDNAME       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE CLOSE("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "CLOSETYPE      TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE KILL("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "GID            INT  ,"  \
          "SIG            INT  ,"  \
          "PID_KILLED     INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE MKDIR("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "MODE           INT,"    \
          "DIRPATH        TEXT,"   \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE FCHMODAT("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "MODE           INT  ,"  \
          "DIRFD          INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE FCHOWNAT("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "GID            INT  ,"  \
          "FLAG           INT  ,"  \
          "USERID         INT  ,"  \
          "DIRFD          INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);

    sql = "CREATE TABLE UNLINKAT("  \
          "ID INTEGER PRIMARY KEY AUTOINCREMENT ,"  \
          "USERNAME       TEXT ,"  \
          "UID            INT  ,"  \
          "COMMANDNAME    TEXT ,"  \
          "PID            INT  ,"  \
          "MODE           INT  ,"  \
          "DIRFD          INT  ,"  \
          "LOGTIME        TEXT ,"  \
          "FILEPATH       TEXT ,"  \
          "RESULT         TEXT );";
    sqlite3_exec(db, sql, 0, 0, &zErrMsg);
}

void close_table(void)
{
    sqlite3_close(db);
}

void insert_record(char *sql)
{
    char *zErrMsg = NULL;
    sqlite3_exec(db, "begin transaction", 0, 0, &zErrMsg);

    int rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    if(rc != SQLITE_OK ){
        fprintf(stderr, "SQL ERROR: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "OPEN records created successfully\n");
    }
    sqlite3_exec(db, "commit transaction", 0, 0, &zErrMsg);
}

void insert_open(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, char *type)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO OPEN (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, OPENTYPE, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', '%s')",
        username, uid, commandname, pid, logtime, filepath, type, result);

    insert_record(sql);
    sqlite3_free(sql);
}

void insert_read(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char * fd_name, char *result)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO READ (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, FDNAME, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', '%s')",
        username, uid, commandname, pid, logtime, filepath, fd_name, result);

    insert_record(sql);
    sqlite3_free(sql);
}

void insert_write(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *fd_name, char *result)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO WRITE (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, FDNAME, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', '%s')",
        username, uid, commandname, pid, logtime, filepath, fd_name, result);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_close(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *type, char *result)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO CLOSE (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, CLOSETYPE, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', '%s')",
        username, uid, commandname, pid, logtime, filepath, type, result);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_kill(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int gid, int sig, int pid_)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO KILL (ID, USERNAME, UID, COMMANDNAME, PID, GID, SIG, PID_KILLED, LOGTIME, FILEPATH, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, %d, %d, %d, '%s', '%s', '%s')",
        username, uid, commandname, pid, gid, sig, pid_, logtime, filepath, result);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_mkdir(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int mode)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO MKDIR (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, MODE, DIRPATH, RESULT) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', %o, '%s', '%s')",
        username, uid, commandname, pid, logtime, mode, filepath, result);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_fchmodat(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int mod, int dirfd)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO FCHMODAT (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, MODE, FILEPATH, RESULT, DIRFD) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', %o, '%s', '%s', %d)",
        username, uid, commandname, pid, logtime, mod, filepath, result, dirfd);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_fchownat(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int flags, int dirfd, int gid, int user_id)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO FCHOWNAT (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, RESULT, DIRFD, FLAG, GID, USERID) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', %d, %d, %d, %d)",
        username, uid, commandname, pid, logtime, filepath, result, dirfd, flags, gid, user_id);
    
    insert_record(sql);
    sqlite3_free(sql);
}

void insert_unlinkat(char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *result, int mod, int dirfd)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO UNLINKAT (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, MODE, FILEPATH, RESULT, DIRFD) " \
        "VALUES (null, '%s', %d, '%s', %d, '%s', %d, '%s', '%s', %d)",
        username, uid, commandname, pid, logtime, mod, filepath, result, dirfd);
    
    insert_record(sql);
    sqlite3_free(sql);
}