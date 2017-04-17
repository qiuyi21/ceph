// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_mysql.h"

#define dout_subsys ceph_subsys_rgw

static bool m_initlib = false;
static bool m_initdb = false;
static pthread_mutex_t m_initmutex = PTHREAD_MUTEX_INITIALIZER;

bool RGWMysql::init() {
  if (!m_initlib) {
    pthread_mutex_lock(&m_initmutex);
    if (!m_initlib) {
      m_initlib = true;
      if (mysql_library_init(0, NULL, NULL)) {
        lderr(cct) << "could not initialize mysql library" << dendl;
        pthread_mutex_unlock(&m_initmutex);
        return false;
      }
    }
    pthread_mutex_unlock(&m_initmutex);
  }
  return true;
}

bool RGWMysql::connect() {
  if (connected) return true;

  string host = cct->_conf->rgw_bc_db_host;
  uint32_t port = 3306;
  size_t idx = host.rfind(':');

  if (idx != string::npos) {
    port = stoi(host.substr(idx + 1));
    host = host.substr(0, idx);
  }

  mysql_init(&mysql);

  if (!mysql_real_connect(&mysql, host.c_str(), cct->_conf->rgw_bc_db_user.c_str(),
      cct->_conf->rgw_bc_db_pwd.c_str(), cct->_conf->rgw_bc_db_name.c_str(), port,
      NULL, 0)) {
    rc = mysql_errno(&mysql);
    lderr(cct) << "connect mysql " << cct->_conf->rgw_bc_db_host << " error: " << rc << " "
          << mysql_error(&mysql) << dendl;
    return false;
  }

  connected = true;

  if (!m_initdb) {
    pthread_mutex_lock(&m_initmutex);
    if (!m_initdb) {
      m_initdb = true;
      execute_query("CREATE TABLE s3bucket (name VARCHAR(255) NOT NULL PRIMARY KEY, createTime DATETIME NOT NULL, hosts TEXT NOT NULL) ENGINE=InnoDB CHARACTER SET UTF8");
    }
    pthread_mutex_unlock(&m_initmutex);
  }

  return true;
}

void RGWMysql::disconnect() {
  if (connected) {
    mysql_close(&mysql);
    connected = false;
  }
}

bool RGWMysql::execute_query(const char *sql) {
  if (mysql_query(&mysql, sql)) {
      rc = mysql_errno(&mysql);
      if (rc == 1050      // Table already exists
          || rc == 1062   // Duplicate primary key
          ) {
        ldout(cct, 15) << "mysql_query \"" << sql << "\" error: " << mysql_error(&mysql) << dendl;
      } else {
        lderr(cct) << "mysql_query \"" << sql << "\" error: " << rc << " " << mysql_error(&mysql) << dendl;
      }
      return false;
  }

  rc = mysql_affected_rows(&mysql);
  return true;
}

int RGWMysql::assign_bucket(const string& bucket_name) {
  if (disabled()) return 0;

  if (!init()) return -ERR_INTERNAL_ERROR;

  if (mysql_thread_init()) {
    lderr(cct) << "mysql_thread_init error" << dendl;
    return -ERR_INTERNAL_ERROR;
  }

  int ret = -ERR_INTERNAL_ERROR;
  stringstream sql;

  const string& dnsname = cct->_conf->rgw_dns_name;
  size_t len = bucket_name.length();
  if (dnsname.length() > len) len = dnsname.length();
  len = len * 2 + 1;
  char *buf = (char *) malloc(len);
  if (!buf) goto out;

  if (!connect()) goto out;

  buf[0] = '\0';
  mysql_real_escape_string(&mysql, buf, bucket_name.c_str(), bucket_name.length());

  sql << "INSERT INTO s3bucket VALUES('" << buf << "',NOW(),'";
  buf[0] = '\0';
  mysql_real_escape_string(&mysql, buf, dnsname.c_str(), dnsname.length());
  sql << buf << "')";

  if (execute_query(sql.str().c_str())) {
    if (rc > 0) ret = 0;
  } else if (rc == 1062)
    ret = -EEXIST;

out:
  mysql_thread_end();
  if (buf) free(buf);
  return ret;
}

void RGWMysql::unassign_bucket(const string& bucket_name) {
  if (disabled() || !init()) return;

  if (mysql_thread_init()) {
    lderr(cct) << "mysql_thread_init error" << dendl;
    return;
  }

  stringstream sql;

  char *buf = (char *) malloc(bucket_name.length() * 2 + 1);
  if (!buf) {
    lderr(cct) << "Out of memory" << dendl;
    goto out;
  }

  if (!connect()) goto out;

  buf[0] = '\0';
  mysql_real_escape_string(&mysql, buf, bucket_name.c_str(), bucket_name.length());

  sql << "DELETE FROM s3bucket WHERE name='" << buf << "'";

  execute_query(sql.str().c_str());

out:
  mysql_thread_end();
  if (buf) free(buf);
}
