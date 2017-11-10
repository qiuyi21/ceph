// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_BUCKET_POLICY_H
#define CEPH_RGW_BUCKET_POLICY_H

enum RGWPolicyEffect {
  RGW_POLICY_UNKNOWN,
  RGW_POLICY_ALLOW,
  RGW_POLICY_DENY
};

enum RGWConditionOperator {
  RGW_POL_OP_UNKNOWN,
  RGW_POL_OP_STR_EQUAL,
  RGW_POL_OP_STR_NOT_EQUAL,
  RGW_POL_OP_STR_EQUAL_I,
  RGW_POL_OP_STR_NOT_EQUAL_I,
  RGW_POL_OP_STR_LIKE,
  RGW_POL_OP_STR_NOT_LIKE,
  RGW_POL_OP_IP_ADDRESS,
  RGW_POL_OP_NOT_IP_ADDRESS
};

class RGWBucketPolicyCondition {
protected:
  __u8 op;  // RGWConditionOperator
  string key;

public:
  RGWBucketPolicyCondition() : op(0) {}
  virtual ~RGWBucketPolicyCondition() {}

  virtual bool check(struct req_state *s) const = 0;
  virtual void _encode(bufferlist& bl) const = 0;
  virtual void _decode(bufferlist::iterator& bl) = 0;

  virtual void encode(bufferlist& bl) const final {
    ENCODE_START(1, 1, bl);
    ::encode(op, bl);
    ::encode(key, bl);
    _encode(bl);
    ENCODE_FINISH(bl);
  }

  /*
   * Need to modify RGWPolicyStatement::decode_condition
   */
  /*virtual void decode(bufferlist::iterator& bl) final {
    DECODE_START(1, bl);
    ::decode(op, bl);
    ::decode(key, bl);
    _decode(bl);
    DECODE_FINISH(bl);
  }*/

  virtual void dump(Formatter *f) const = 0;
  virtual void decode_json(JSONObj *obj) = 0;
};

class RGWBucketPolicyCondStr: public RGWBucketPolicyCondition {
  vector<string> values;

public:
  RGWBucketPolicyCondStr(__u8 opnum) { op = opnum; }
  RGWBucketPolicyCondStr(__u8 opnum, const string& k) {
    op = opnum;
    key = k;
  }

  void _encode(bufferlist& bl) const override {
    ::encode(values, bl);
  }

  void _decode(bufferlist::iterator& bl) override {
    ::decode(values, bl);
  }

  bool check(struct req_state *s) const override;
  void dump(Formatter *f) const override;
  void decode_json(JSONObj *obj) override;
};

class RGWBucketPolicyCondIP: public RGWBucketPolicyCondition {
  vector<uint64_t> values;

  bool match(uint32_t ip) const;

public:
  RGWBucketPolicyCondIP(__u8 opnum) { op = opnum; }
  RGWBucketPolicyCondIP(__u8 opnum, const string& k) {
    op = opnum;
    key = k;
  }

  void _encode(bufferlist& bl) const override {
    ::encode(values, bl);
  }

  void _decode(bufferlist::iterator& bl) override {
    ::decode(values, bl);
  }

  bool check(struct req_state *s) const override;
  void dump(Formatter *f) const override;
  void decode_json(JSONObj *obj) override;
  void cidr_to_str(uint64_t ip, char *buf) const;
  bool str_to_cidr(const string& val, uint64_t& ip);
};

class RGWPolicyPrincipal {
  __u8 type;  // 1: AWS
  vector<string> name;

  bool match(const struct RGWUserInfo *user, const string& rule, bool is_auth, struct req_state *s) const;

public:
  RGWPolicyPrincipal() : type(0) {}

  bool empty() const { return name.empty(); }
  bool check(const struct RGWUserInfo *user, bool is_auth, struct req_state *s) const;

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(type, bl);
    ::encode(name, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    ::decode(type, bl);
    ::decode(name, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWPolicyPrincipal)

class RGWPolicyStatement {
  string sid;
  __u8 effect;  // RGWPolicyEffect
  RGWPolicyPrincipal principal;
  vector<string> action;
  vector<string> resource;
  vector<shared_ptr<RGWBucketPolicyCondition>> condition;

  bool match_action(int op_type, struct req_state *s) const;
  bool match_resource(const struct RGWUserInfo *user, const string& objname) const;
  bool match_condition(struct req_state *s) const;
  void decode_condition(bufferlist::iterator& bl);

public:
  RGWPolicyStatement() : effect(0) {}

  bool is_valid_action(const string& act);
  bool is_valid_resource(string& arn, const string& bucket_name);
  RGWPolicyEffect check(const struct RGWUserInfo *user, bool is_auth, int op_type,
      const string& objname, struct req_state *s) const;

  void encode(bufferlist& bl) const;
  void decode(bufferlist::iterator& bl);
  void dump(Formatter *f, const string& bucket_name) const;
  void decode_json(JSONObj *obj, const string& bucket_name);
};
WRITE_CLASS_ENCODER(RGWPolicyStatement)

class RGWBucketPolicy {
  struct req_state *s;
  string bucket_name;
  string version;
  string id;
  vector<RGWPolicyStatement> statement;

  int upgrade_from_v1(bufferlist::iterator& bl, RGWRados *store, bool& valid);

public:
  RGWBucketPolicy() : s(NULL) {}
  RGWBucketPolicy(struct req_state *rs, const string *bucketname = NULL);

  void init(struct req_state *rs, const string *bucketname = NULL) {
    s = rs;
    if (bucketname) bucket_name = *bucketname;
  }

  bool empty() { return statement.empty(); }
  RGWPolicyEffect verify_permission();
  RGWPolicyEffect verify_permission(struct RGWUserInfo *user, int op_type, const string& objname);
  string tojson();

  void clear() {
    bucket_name.clear();
    id.clear();
    version.clear();
    statement.clear();
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 2, bl);
    ::encode(bucket_name, bl);
    ::encode(id, bl);
    ::encode(version, bl);
    ::encode(statement, bl);
    ENCODE_FINISH(bl);
  }

  int decode(bufferlist::iterator& bl, RGWRados *store = NULL);
  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWBucketPolicy)

bool rgw_auth_id_is_bucket_owner(struct req_state * const s, const rgw_user *owner = NULL);

#endif
