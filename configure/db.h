#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

sqlite3 *db = NULL;

static int sn = 0;

void create_table(char *filename);
void close_table(void);
void insert_record(char *table, char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *opentype, char *openresult);

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
          "OPENRESULT     TEXT );";

    sqlite3_exec(db, sql, 0, 0, &zErrMsg);
}

void close_table(void)
{
    sqlite3_close(db);
}


void insert_record(char *table, char *username, int uid, char *commandname, int pid, char *logtime, char *filepath, char *opentype, char *openresult)
{
    char *sql = NULL;
    char *zErrMsg = NULL; 
    sql = sqlite3_mprintf("INSERT INTO %s (ID, USERNAME, UID, COMMANDNAME, PID, LOGTIME, FILEPATH, OPENTYPE, OPENRESULT) VALUES (null, '%s', %d, '%s', %d, '%s', '%s', '%s', '%s')", table, username, uid, commandname, pid, logtime, filepath, opentype, openresult);
    int rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
    // printf("%s", sql);
    if( rc != SQLITE_OK ){
        fprintf(stderr, "SQL ERROR: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    } else {
        fprintf(stdout, "Records created successfully\n");
    }
    sqlite3_free(sql);
}

int sqlite_callback(void * userData,int numCol,char **colData,char **colName)
{
    int i, offset = 0;
    char *buf, *tmp;

    buf = (char *)malloc(40 * sizeof(char));
    tmp = buf;
    memset(buf,0,40);

    //printf("%d %d\n",sizeof(buf),strlen(buf));
    for (i = 1;i < numCol;i++)
    {
        buf = buf + offset;
        sprintf(buf,"%s ",colData[i]);
        offset = strlen(colData[i]) + 1; //it's need one place for put a blank so the lenght add 1
    //    printf("i %d offset %d\n",i, offset);
    }
    printf("%.4d. %s \n",++sn,tmp);

    free(tmp);
    tmp = NULL;
    buf = NULL;

    return 0;
}


void search_all(char * table)
{
    char *sql;
    char *zErrMsg = 0;

    sn = 0;

    sql = sqlite3_mprintf("select * from %s", table);
    sqlite3_exec(db, sql, &sqlite_callback, 0, &zErrMsg);
    sqlite3_free(sql);

}

void search_by_id(char * table,char * id)
{
    char * sql;
    char * zErrMsg = 0;

    sn = 0;

    sql = sqlite3_mprintf("select * from %s where id=%s",table,id);
    sqlite3_exec(db,sql,&sqlite_callback,0,&zErrMsg);
    sqlite3_free(sql);
}

void delete_by_id(char * table,char * id)
{
    int rc ;
    char * sql;
    char * zErrMsg = 0;
    sql = sqlite3_mprintf("delete from %s where id=%s",table,id);
    rc = sqlite3_exec(db,sql,0,0,&zErrMsg);
    sqlite3_free(sql);
}

void delete_all(char * table)
{
    char * sql;
    char * zErrMsg = 0;

    sql = sqlite3_mprintf("delete from %s",table);
    sqlite3_exec(db,sql,0,0,&zErrMsg);
    sqlite3_free(sql);
}

int test_table()
{
    char *filename = "test.db";
    int i;

    create_table(filename);

    insert_record("OPEN", "username", 123, "commandname", 123, "2020", "filepath", "opentype", "openresult");
  //  search_all("OPEN");

    close_table();

    return 0;
}
