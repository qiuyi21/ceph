// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_MYSQL_H
#define CEPH_RGW_MYSQL_H

#include "rgw_common.h"
#include <mysql/mysql.h>

class RGWMysql {
private:
  CephContext *cct;
  MYSQL mysql;
  int rc;
  bool connected;

  bool init();
  bool connect();
  bool execute_query(const char *sql);

public:
  RGWMysql(CephContext *c = g_ceph_context) {
    cct = c;
    rc = 0;
    connected = false;
  }

  ~RGWMysql() { disconnect(); }

  bool disabled() { return cct->_conf->rgw_bc_db_name.empty(); }
  void disconnect();
  int assign_bucket(const string& bucket_name);
  void unassign_bucket(const string& bucket_name);
};

#endif
