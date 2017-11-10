// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_common.h"
#include "common/ceph_json.h"
#include "rgw_user.h"
#include "rgw_bucket.h"
#include "rgw_bucket_policy_s3.h"

#define dout_subsys ceph_subsys_rgw
#define RESOURCE_PREFIX "arn:aws:s3:::"

#define JS_DECODE_ERR(X) throw JSONDecoder::err("Invalid field " X)
#define EFFECT_ERR       JS_DECODE_ERR("Effect")
#define ACTION_ERR       JS_DECODE_ERR("Action")
#define RESOURCE_ERR     JS_DECODE_ERR("Resource")
#define STATEMENT_ERR    JS_DECODE_ERR("Statement")
#define CONDITION_ERR    JS_DECODE_ERR("Condition")
#define LOG_CONDITION(OP, key, val) dout(20) << "bucket policy condition \"" << key << " " OP " " << val << "\" is true" << dendl

struct s3_condition_str {
  const char *key;
  const char *arg_name;
};

static const s3_condition_str condition_keys[] = {
  {"s3:prefix", "prefix"},
  {"s3:delimiter", "delimiter"},
  {"s3:x-amz-acl", "HTTP_X_AMZ_ACL"},
  {"s3:x-amz-grant-read", "HTTP_X_AMZ_GRANT_READ"},
  {"s3:x-amz-grant-write", "HTTP_X_AMZ_GRANT_WRITE"},
  {"s3:x-amz-grant-read-acp","HTTP_X_AMZ_GRANT_READ_ACP"},
  {"s3:x-amz-grant-write-acp", "HTTP_X_AMZ_GRANT_WRITE_ACP"},
  {"s3:x-amz-grant-full-control", "HTTP_X_AMZ_GRANT_FULL_CONTROL"},
  {"s3:x-amz-copy-source", "HTTP_X_AMZ_COPY_SOURCE"},
  {"aws:Referer", "HTTP_REFERER"},
  {"aws:UserAgent", "HTTP_USER_AGENT"},
  {NULL, NULL}
};

static bool json_to_vector(const char *name, vector<string>& val, JSONObj *obj, bool mandatory = false,
    bool canempty = false, bool byname = true) {
  val.clear();

  JSONObjIter iter = byname ? obj->find_first(name) : obj->find_first();
  if (iter.end()) {
    if (mandatory)
      throw JSONDecoder::err(string("Missing mandatory field ") + name);
    return false;
  }

  JSONObj *jo = *iter;
  if (jo->get_data_type() == str_type) {
    string& v = jo->get_data();
    if (canempty || !v.empty()) val.push_back(v);
    return true;
  } else if (!jo->is_array())
    throw JSONDecoder::err(string("Invalid type of field ") + name);

  for (iter = jo->find_first(); !iter.end(); ++iter) {
    jo = *iter;
    if (jo->get_data_type() != str_type)
      throw JSONDecoder::err(string("Invalid type of field ") + name);
    string& v = jo->get_data();
    if (canempty || !v.empty()) val.push_back(v);
  }

  return true;
}

static void vector_to_json(const char *name, const vector<string>& l, Formatter *f) {
  if (l.size() == 1) {
    f->dump_string(name, l[0]);
  } else {
    f->open_array_section(name);
    for (auto iter = l.begin(); iter != l.end(); ++iter)
      f->dump_string("", *iter);
    f->close_section();
  }
}

class WildStr {
  string ws;
  const char *cur;
  char ch;
  bool escape;

  void readchar() {
    ch = *cur;
    if (ch == '$') {
      ch = *++cur;
      if (ch == '{') {
        const char *p = strchr(cur + 1, '}');
        if (p == cur + 2) {
          cur = p;
          ch = p[-1];
          escape = true;
          return;
        }
      }
    }
    escape = false;
  }

  inline void increase() {
    cur++;
    readchar();
  }

  inline char get() { return ch; }

public:
  WildStr(const string& str, size_t pos = 0, size_t n = string::npos) :
      cur(NULL), ch('\0'), escape(false) {
    if (!pos && n == string::npos)
      ws = str;
    else
      ws = str.substr(pos, n);
  }

  WildStr& parse(const RGWUserInfo *user) {
    static const string var_uid = "${aws:userid}";
    size_t pos = ws.find(var_uid);
    if (pos != string::npos) {
      string uid;
      user->user_id.to_str(uid);
      do {
        ws.replace(pos, var_uid.size(), uid);
        pos += uid.size();
      } while ((pos = ws.find(var_uid, pos)) != string::npos);
    }
    return *this;
  }

  int compare(const char *str) {
    cur = ws.c_str();
    if (cur[0] == '*' && !cur[1]) return 0;
    readchar();

    const char *cp = NULL, *mp = NULL;

    while (*str && (get() != '*' || escape)) {
      if (get() != *str && (get() != '?' || escape)) return 1;
      increase();
      str++;
    }

    while (*str) {
      if (get() == '*' && !escape) {
        increase();
        if (!get()) return 0;
        mp = cur;
        cp = str + 1;
      } else if (get() == *str || (get() == '?' && !escape)) {
        increase();
        str++;
      } else {
        cur = mp;
        str = cp++;
      }
    }

    while (get() == '*' && !escape) increase();
    return (get() ? -1 : 0);
  }

  //string& operator=(const WildStr& w) { return ws; }
  inline int compare(const string& str) { return compare(str.c_str()); }
  inline int cmp(const string& str) { return ws.compare(str); }
  inline int casecmp(const string& str) { return strcasecmp(ws.c_str(), str.c_str()); }
  //inline const char *c_str() { return ws.c_str(); }
};

bool RGWBucketPolicyCondStr::check(struct req_state *s) const {
  string val;
  const char *pc;

  for (const s3_condition_str *p = condition_keys; p->key; p++) {
    if (key.compare(p->key)) continue;

    if (strncmp(p->arg_name, "HTTP_", 5))
      val = s->info.args.get(p->arg_name);
    else {
      pc = s->info.env->get(p->arg_name);
      if (pc)
        val = pc;
      else
        val.clear();
    }

    for (auto iter = values.begin(); iter != values.end(); ++iter) {
      WildStr ws(*iter);
      ws.parse(s->user);
      switch (op) {
      case RGW_POL_OP_STR_EQUAL:
        if (!ws.cmp(val)) {
          LOG_CONDITION("StringEquals", val, *iter);
          return true;
        }
        break;
      case RGW_POL_OP_STR_NOT_EQUAL:
        if (ws.cmp(val)) {
          LOG_CONDITION("StringNotEquals", val, *iter);
          return true;
        }
        break;
      case RGW_POL_OP_STR_EQUAL_I:
        if (!ws.casecmp(val)) {
          LOG_CONDITION("StringEqualsIgnoreCase", val, *iter);
          return true;
        }
        break;
      case RGW_POL_OP_STR_NOT_EQUAL_I:
        if (ws.casecmp(val)) {
          LOG_CONDITION("StringNotEqualsIgnoreCase", val, *iter);
          return true;
        }
        break;
      case RGW_POL_OP_STR_LIKE:
        if (!ws.compare(val)) {
          LOG_CONDITION("StringLike", val, *iter);
          return true;
        }
        break;
      case RGW_POL_OP_STR_NOT_LIKE:
        if (ws.compare(val)) {
          LOG_CONDITION("StringNotLike", val, *iter);
          return true;
        }
        break;
      default:
        break;
      }
    }

    break;
  }

  return false;
}

void RGWBucketPolicyCondStr::dump(Formatter *f) const {
  const char *opname;

  switch (op) {
  case RGW_POL_OP_STR_EQUAL:
    opname = "StringEquals";
    break;
  case RGW_POL_OP_STR_NOT_EQUAL:
    opname = "StringNotEquals";
    break;
  case RGW_POL_OP_STR_EQUAL_I:
    opname = "StringEqualsIgnoreCase";
    break;
  case RGW_POL_OP_STR_NOT_EQUAL_I:
    opname = "StringNotEqualsIgnoreCase";
    break;
  case RGW_POL_OP_STR_LIKE:
    opname = "StringLike";
    break;
  case RGW_POL_OP_STR_NOT_LIKE:
    opname = "StringNotLike";
    break;
  default:
    return;
  }

  f->open_object_section(opname);
  vector_to_json(key.c_str(), values, f);
  f->close_section();
}

void RGWBucketPolicyCondStr::decode_json(JSONObj *obj) {
  json_to_vector(obj->get_name().c_str(), values, obj, true, true, false);
  if (values.empty())
    throw JSONDecoder::err("Invalid field " + obj->get_name());

  key = (*(obj->find_first()))->get_name();
  bool found = false;
  for (const s3_condition_str *p = condition_keys; p->key; p++) {
    if (!key.compare(p->key)) {
      found = true;
      break;
    }
  }
  if (!found) throw JSONDecoder::err("Invalid field " + key);
}

bool RGWBucketPolicyCondIP::match(uint32_t ip) const {
  for (auto iter = values.begin(); iter != values.end(); ++iter) {
    uint64_t r = *iter;
    if ((ip & (uint32_t) (r >> 32)) == (uint32_t) r)
      return op == RGW_POL_OP_IP_ADDRESS;
  }
  return op != RGW_POL_OP_IP_ADDRESS;
}

bool RGWBucketPolicyCondIP::check(struct req_state *s) const {
  struct in_addr ia;
  const char *pc = s->info.env->get("HTTP_X_FORWARDED_FOR");
  if (pc && *pc) {
    if (inet_pton(AF_INET, pc, &ia) != 1) {
      ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": invalid IPv4 " << pc << " in X_Forwarded_For" << dendl;
      return false;
    }
    if ((__u8) ia.s_addr != 127 && !match(htonl(ia.s_addr))) {
      ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": policy not allow IPv4 " << pc << " in X_Forwarded_For" << dendl;
      return false;
    }
  }

  pc = s->info.env->get("REMOTE_ADDR");
  if (!pc || !pc[0]) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": no REMOTE_ADDR" << dendl;
    return false;
  }
  if (inet_pton(AF_INET, pc, &ia) != 1) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": invalid IPv4 " << pc << " in REMOTE_ADDR" << dendl;
    return false;
  }
  if ((__u8) ia.s_addr != 127 && !match(htonl(ia.s_addr))) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": policy not allow IPv4 " << pc << " in REMOTE_ADDR" << dendl;
    return false;
  }

  return true;
}

void RGWBucketPolicyCondIP::dump(Formatter *f) const {
  const char *opname;

  switch (op) {
  case RGW_POL_OP_IP_ADDRESS:
    opname = "IpAddress";
    break;
  case RGW_POL_OP_NOT_IP_ADDRESS:
    opname = "NotIpAddress";
    break;
  default:
    return;
  }

  char buf[24];

  f->open_object_section(opname);
  if (values.size() == 1) {
    cidr_to_str(values[0], buf);
    f->dump_string(key.c_str(), buf);
  } else {
    f->open_array_section(key.c_str());
    for (auto iter = values.begin(); iter != values.end(); ++iter) {
      cidr_to_str(*iter, buf);
      f->dump_string("", buf);
    }
    f->close_section();
  }
  f->close_section();
}

void RGWBucketPolicyCondIP::cidr_to_str(uint64_t ip, char *buf) const {
  uint32_t n = (uint32_t) (ip >> 32);
  __u8 i;
  for (i = 0; i < 32 && !(n & 1); i++, n >>= 1) ;
  buf[0] = '\0';
  snprintf(buf, 24, "%hhu.%hhu.%hhu.%hhu/%hhu", (__u8) (ip >> 24), (__u8) (ip >> 16),
      (__u8) (ip >> 8), (__u8) ip, 32 - i);
}

bool RGWBucketPolicyCondIP::str_to_cidr(const string& val, uint64_t& ip) {
  string v = val;
  size_t idx = v.find('/');
  uint32_t mask = (uint32_t) -1;
  if (idx != string::npos) {
    int i = stoi(v.substr(idx + 1));
    if (i < 0 || i > 32) return false;
    v = v.substr(0, idx);
    for (i = 32 - i; i > 0; i--)
      mask <<= 1;
  }
  struct in_addr ia;
  if (inet_pton(AF_INET, v.c_str(), &ia) != 1) return false;
  ip = mask;
  ip <<= 32;
  ip |= htonl(ia.s_addr) & mask;
  return true;
}

void RGWBucketPolicyCondIP::decode_json(JSONObj *obj) {
  values.clear();

  JSONObjIter iter = obj->find_first();
  if (iter.end())
    throw JSONDecoder::err("Invalid field " + obj->get_name());

  uint64_t ip;
  JSONObj *jo = *iter;

  key = jo->get_name();
  if (key.compare("aws:SourceIp"))
    throw JSONDecoder::err("Invalid field " + key);

  if (jo->get_data_type() == str_type) {
    if (str_to_cidr(jo->get_data(), ip))
      values.push_back(ip);
  } else if (!jo->is_array()) {
    throw JSONDecoder::err("Invalid type of field " + key);
  } else {
    for (iter = jo->find_first(); !iter.end(); ++iter) {
      jo = *iter;
      if (jo->get_data_type() != str_type || !str_to_cidr(jo->get_data(), ip))
        throw JSONDecoder::err("Invalid field " + key);
      values.push_back(ip);
    }
  }
  if (values.empty())
    throw JSONDecoder::err("Invalid field " + key);
}

bool RGWPolicyPrincipal::match(const RGWUserInfo *user, const string& rule, bool is_auth,
    struct req_state *s) const {
  if (!is_auth) {    // anonymous user
    int i = rule.size() - 1;
    const char *pc = rule.c_str();
    while (i >= 0) {
      if (pc[i] != '*') {
        dout(20) << "bucket policy principal anonymous not match \"" << rule << "\"" << dendl;
        return false;
      }
      i--;
    }
  }
  WildStr wild(rule);
  bool ok = !wild.parse(user).compare(s->auth_id);
  dout(20) << "bucket policy principal \"" << s->auth_id << "\"" << (ok ? "" : " not")
    << " match \"" << rule << "\"" << dendl;
  return ok;
}

bool RGWPolicyPrincipal::check(const RGWUserInfo *user, bool is_auth, struct req_state *s) const {
  for (auto iter = name.begin(); iter != name.end(); ++iter) {
    if (match(user, *iter, is_auth, s)) return true;
  }
  return false;
}

inline void RGWPolicyPrincipal::dump(Formatter *f) const {
  vector_to_json("AWS", name, f);
}

void RGWPolicyPrincipal::decode_json(JSONObj *obj) {
  type = 1;

  if (obj->get_data_type() == str_type) {
    name.clear();
    string& v = obj->get_data();
    if (!v.compare("*")) name.push_back(v);
  } else if (!obj->is_object()) {
    throw JSONDecoder::err("Invalid type of field Principal");
  } else
    json_to_vector("AWS", name, obj, true);

  if (name.empty()) JS_DECODE_ERR("Principal");
}

bool RGWPolicyStatement::match_action(int op_type, struct req_state *s) const {
  bool ok = false;

  for (auto iter = action.begin(); iter != action.end(); ++iter) {
    const string& act = *iter;
    WildStr wild(act);

    switch (op_type) {
    case RGW_OP_GET_OBJ:
      ok = !wild.compare("s3:GetObject");
      break;
    case RGW_OP_PUT_OBJ:
    case RGW_OP_POST_OBJ:
    case RGW_OP_INIT_MULTIPART:
    case RGW_OP_COMPLETE_MULTIPART:
      ok = !wild.compare("s3:PutObject");
      break;
    case RGW_OP_DELETE_OBJ:
      ok = !wild.compare("s3:DeleteObject");
      break;
    case RGW_OP_LIST_MULTIPART:
      ok = !wild.compare("s3:ListMultipartUploadParts");
      break;
    case RGW_OP_ABORT_MULTIPART:
      ok = !wild.compare("s3:AbortMultipartUpload");
      break;
    case RGW_OP_LIST_BUCKET:
      if (s->info.args.exists("versions"))
        ok = !wild.compare("s3:ListBucketVersions");
      else
        ok = !wild.compare("s3:ListBucket");
      break;
    case RGW_OP_LIST_BUCKET_MULTIPARTS:
      ok = !wild.compare("s3:ListBucketMultipartUploads");
      break;
    case RGW_OP_DELETE_BUCKET:
      ok = !wild.compare("s3:DeleteBucket");
      break;
    case RGW_OP_GET_ACLS:
      if (!s->object.empty()) {
        ok = !wild.compare("s3:GetObjectAcl");
      } else {
        ok = !wild.compare("s3:GetBucketAcl");
      }
      break;
    case RGW_OP_PUT_ACLS:
      if (!s->object.empty()) {
        ok = !wild.compare("s3:PutObjectAcl");
      } else {
        ok = !wild.compare("s3:PutBucketAcl");
      }
      break;
    case RGW_OP_SET_BUCKET_VERSIONING:
      ok = !wild.compare("s3:PutBucketVersioning");
      break;
    case RGW_OP_SET_BUCKET_WEBSITE:
      ok = !wild.compare("s3:PutBucketWebsite");
      break;
    case RGW_OP_PUT_CORS:
    case RGW_OP_DELETE_CORS:
      ok = !wild.compare("s3:PutBucketCORS");
      break;
    default:
      break;
    }

    if (ok) {
      dout(20) << "bucket policy action " << op_type << " match \"" << act << "\"" << dendl;
      return true;
    }
  }

  return false;
}

bool RGWPolicyStatement::match_resource(const RGWUserInfo *user, const string& objname) const {
  for (auto iter = resource.begin(); iter != resource.end(); ++iter) {
    const string& res = *iter;
    if (res.empty()) {
      if (objname.empty()) return true;
      continue;
    }
    WildStr wild(res);
    if (!wild.parse(user).compare(objname)) {
      dout(20) << "bucket policy resource \"" << objname << "\" match \"" << res << "\"" << dendl;
      return true;
    }
  }
  return false;
}

inline bool RGWPolicyStatement::match_condition(struct req_state *s) const {
  for (auto iter = condition.begin(); iter != condition.end(); ++iter) {
    if (!(*iter)->check(s)) return false;
  }
  return true;
}

RGWPolicyEffect RGWPolicyStatement::check(const RGWUserInfo *user, bool is_auth, int op_type,
    const string& objname, struct req_state *s) const {
  if (match_action(op_type, s) && match_resource(user, objname) && principal.check(user, is_auth, s)
      && match_condition(s)) {
    return (RGWPolicyEffect) effect;
  }
  return RGW_POLICY_UNKNOWN;
}

inline void RGWPolicyStatement::encode(bufferlist& bl) const {
  ENCODE_START(1, 1, bl);
  ::encode(sid, bl);
  ::encode(effect, bl);
  ::encode(principal, bl);
  ::encode(action, bl);
  ::encode(resource, bl);

  uint32_t n = condition.size();
  ::encode(n, bl);
  for (auto iter = condition.begin(); iter != condition.end(); ++iter)
    (*iter)->encode(bl);

  ENCODE_FINISH(bl);
}

inline void RGWPolicyStatement::decode(bufferlist::iterator& bl) {
  DECODE_START(1, bl);
  ::decode(sid, bl);
  ::decode(effect, bl);
  ::decode(principal, bl);
  ::decode(action, bl);
  ::decode(resource, bl);
  decode_condition(bl);
  DECODE_FINISH(bl);
}

void RGWPolicyStatement::decode_condition(bufferlist::iterator& bl) {
  uint32_t n;
  ::decode(n, bl);

  condition.resize(n);

  __u8 op;
  string key;
  shared_ptr<RGWBucketPolicyCondition> sp;

  for (uint32_t i = 0; i < n; i++) {
    DECODE_START(1, bl);
    ::decode(op, bl);
    ::decode(key, bl);

    if (op <= RGW_POL_OP_STR_NOT_LIKE)
      sp = make_shared<RGWBucketPolicyCondStr>(op, key);
    else if (op <= RGW_POL_OP_NOT_IP_ADDRESS)
      sp = make_shared<RGWBucketPolicyCondIP>(op, key);
    else {
      stringstream ss;
      ss << "Invalid RGWConditionOperator " << op;
      throw buffer::malformed_input(ss.str());
    }
    sp->_decode(bl);
    condition[i] = sp;

    DECODE_FINISH(bl);
  }
}

void RGWPolicyStatement::dump(Formatter *f, const string& bucket_name) const {
  if (!sid.empty())
    encode_json("Sid", sid, f);

  encode_json("Effect", effect == RGW_POLICY_ALLOW ? "Allow" : "Deny", f);

  if (!principal.empty())
    encode_json("Principal", principal, f);

  if (!action.empty())
    vector_to_json("Action", action, f);

  if (!resource.empty()) {
    if (resource.size() == 1) {
      const string& item = resource[0];
      string v = RESOURCE_PREFIX;
      v += bucket_name;
      if (!item.empty()) {
        v += "/";
        v += item;
      }
      encode_json("Resource", v, f);
    } else {
      f->open_array_section("Resource");
      for (auto iter = resource.begin(); iter != resource.end(); ++iter) {
        string v = RESOURCE_PREFIX;
        v += bucket_name;
        if (!iter->empty()) {
          v += "/";
          v += *iter;
        }
        encode_json("", v, f);
      }
      f->close_section();
    }
  }

  if (!condition.empty()) {
    f->open_object_section("Condition");
    for (auto iter = condition.begin(); iter != condition.end(); ++iter)
      (*iter)->dump(f);
    f->close_section();
  }
}

bool RGWPolicyStatement::is_valid_action(const string& act) {
  static const char *ss[] = {
      "s3:AbortMultipartUpload",
      "s3:DeleteBucket",
      "s3:DeleteObject",
      "s3:GetBucketAcl",
      "s3:GetObject",
      "s3:GetObjectAcl",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
      "s3:ListBucketVersions",
      "s3:ListMultipartUploadParts",
      "s3:PutBucketAcl",
      "s3:PutBucketCORS",
      "s3:PutBucketVersioning",
      "s3:PutBucketWebsite",
      "s3:PutObject",
      "s3:PutObjectAcl",
      NULL
  };
  __u8 i = 0;
  WildStr wild(act);
  do {
    if (!wild.compare(ss[i])) return true;
  } while (ss[++i]);
  dout(15) << "bucket policy action not support \"" << act << "\"" << dendl;
  return false;
}

bool RGWPolicyStatement::is_valid_resource(string& arn, const string& bucket_name) {
  size_t slen = sizeof(RESOURCE_PREFIX) - 1;
  if (arn.size() < slen + 2 || arn.compare(0, slen, RESOURCE_PREFIX))
    return false;

  size_t idx = arn.find('/', slen);
  if (idx != string::npos) {
    if (arn.compare(slen, idx - slen, bucket_name))
      return false;
    arn = arn.substr(idx + 1);
  } else if (arn.compare(slen, string::npos, bucket_name))
    return false;
  else
    arn = "";
  return true;
}

void RGWPolicyStatement::decode_json(JSONObj *obj, const string& bucket_name) {
  JSONDecoder::decode_json("Sid", sid, obj);

  JSONObjIter iter = obj->find_first("Effect");
  if (iter.end()) EFFECT_ERR;
  JSONObj *jo = *iter;
  if (jo->get_data_type() != str_type) EFFECT_ERR;
  string& v = jo->get_data();
  if (!v.compare("Allow"))
    effect = RGW_POLICY_ALLOW;
  else if (!v.compare("Deny"))
    effect = RGW_POLICY_DENY;
  else
    EFFECT_ERR;

  JSONDecoder::decode_json("Principal", principal, obj, true);

  json_to_vector("Action", action, obj, true);
  for (auto iter = action.begin(); iter != action.end(); ++iter) {
    if (!is_valid_action(*iter)) ACTION_ERR;
  }
  if (action.empty()) ACTION_ERR;

  json_to_vector("Resource", resource, obj, true);
  for (auto iter = resource.begin(); iter != resource.end(); ++iter) {
    if (!is_valid_resource(*iter, bucket_name)) RESOURCE_ERR;
  }
  if (resource.empty()) RESOURCE_ERR;

  iter = obj->find_first("Condition");
  if (!iter.end()) {
    jo = *iter;
    if (!jo->is_object()) CONDITION_ERR;

    string opname;
    RGWConditionOperator op;
    shared_ptr<RGWBucketPolicyCondition> sp;

    condition.clear();
    for (iter = jo->find_first(); !iter.end(); ++iter) {
      jo = *iter;
      if (!jo->is_object())
        throw JSONDecoder::err("Invalid type of field Condition");

      opname = jo->get_name();
      if (!opname.compare("StringEquals"))
        op = RGW_POL_OP_STR_EQUAL;
      else if (!opname.compare("StringNotEquals"))
        op = RGW_POL_OP_STR_NOT_EQUAL;
      else if (!opname.compare("StringEqualsIgnoreCase"))
        op = RGW_POL_OP_STR_EQUAL_I;
      else if (!opname.compare("StringNotEqualsIgnoreCase"))
        op = RGW_POL_OP_STR_NOT_EQUAL_I;
      else if (!opname.compare("StringLike"))
        op = RGW_POL_OP_STR_LIKE;
      else if (!opname.compare("StringNotLike"))
        op = RGW_POL_OP_STR_NOT_LIKE;
      else if (!opname.compare("IpAddress"))
        op = RGW_POL_OP_IP_ADDRESS;
      else if (!opname.compare("NotIpAddress"))
        op = RGW_POL_OP_NOT_IP_ADDRESS;
      else
        throw JSONDecoder::err("Invalid field " + opname);

      if (op <= RGW_POL_OP_STR_NOT_LIKE)
        sp = make_shared<RGWBucketPolicyCondStr>(op);
      else if (op <= RGW_POL_OP_NOT_IP_ADDRESS)
        sp = make_shared<RGWBucketPolicyCondIP>(op);
      sp->decode_json(jo);
      condition.push_back(sp);
    }
  }
}

RGWBucketPolicy::RGWBucketPolicy(struct req_state *rs, const string *bucketname) {
  s = rs;
  bucket_name = bucketname ? *bucketname : s->bucket_name;
}

int RGWBucketPolicy::decode(bufferlist::iterator& bl, RGWRados *store) {
  DECODE_START(2, bl);
  if (struct_v == 1) {    // upgrade
    bool valid = false;
    int ret = upgrade_from_v1(bl, store, valid);
    if (ret < 0) {
      ldout(store->ctx(), 0) << "upgrade bucket policy of " << bucket_name << " error " << ret << dendl;
      if (!valid) return ret;
    }
    break;
  }
  ::decode(bucket_name, bl);
  ::decode(id, bl);
  ::decode(version, bl);
  ::decode(statement, bl);
  DECODE_FINISH(bl);
  return 0;
}

void RGWBucketPolicy::dump(Formatter *f) const {
  if (!version.empty())
    encode_json("Version", version, f);
  if (!id.empty())
    encode_json("Id", id, f);

  f->open_array_section("Statement");
  for (auto iter = statement.begin(); iter != statement.end(); ++iter) {
    f->open_object_section("");
    iter->dump(f, bucket_name);
    f->close_section();
  }
  f->close_section();
}

void RGWBucketPolicy::decode_json(JSONObj *obj) {
  if (!obj->is_object())
    throw JSONDecoder::err("Invalid bucket policy");

  JSONDecoder::decode_json("Version", version, obj);
  if (!version.empty() && version.compare("2008-10-17") && version.compare("2012-10-17"))
    JS_DECODE_ERR("Version");

  JSONDecoder::decode_json("Id", id, obj);

  JSONObjIter iter = obj->find_first("Statement");
  if (iter.end()) STATEMENT_ERR;
  JSONObj *jo = *iter;
  if (!jo->is_array()) STATEMENT_ERR;
  statement.clear();
  for (iter = jo->find_first(); !iter.end(); ++iter) {
    jo = *iter;
    if (!jo->is_object()) STATEMENT_ERR;
    RGWPolicyStatement v;
    v.decode_json(jo, bucket_name);
    statement.push_back(v);
  }
  if (statement.empty()) STATEMENT_ERR;
}

RGWPolicyEffect RGWBucketPolicy::verify_permission() {
  return verify_permission(s->user, s->op_type, s->object.name);
}

RGWPolicyEffect RGWBucketPolicy::verify_permission(RGWUserInfo *user, int op_type,
    const string& objname) {
  RGWPolicyEffect ret = RGW_POLICY_UNKNOWN;
  bool is_auth = rgw_user_is_authenticated(*user);
  for (auto iter = statement.begin(); iter != statement.end(); ++iter) {
    ret = iter->check(user, is_auth, op_type, objname, s);
    if (ret != RGW_POLICY_UNKNOWN) break;
  }
  return ret;
}

string RGWBucketPolicy::tojson() {
  JSONFormatter jf(false);
  encode_json("", *this, &jf);
  stringstream os;
  jf.flush(os);
  return os.str();
}

int RGWBucketPolicy::upgrade_from_v1(bufferlist::iterator& bl, RGWRados *store, bool& valid) {
  assert(store);
  assert(s);

  string js;
  try {
    ::decode(js, bl);
  } catch (buffer::error& err) {
    return -EIO;
  }

  JSONParser parser;
  if (!parser.parse(js.c_str(), js.size()))
    return -ERR_MALFORMED_POLICY;

  try {
    decode_json(&parser);
  } catch (JSONDecoder::err& e) {
    return -ERR_MALFORMED_POLICY;
  }
  valid = true;

  bufferlist polbl;
  encode(polbl);

  RGWObjectCtx& obj_ctx = *static_cast<RGWObjectCtx *>(s->obj_ctx);
  RGWBucketInfo bucket_info;
  map<string, bufferlist> bucket_attrs;
  int ret = store->get_bucket_info(obj_ctx, "", bucket_name, bucket_info, NULL, &bucket_attrs);
  if (ret < 0) {
    ldout(store->ctx(), 0) << "get_bucket_info(bucket_name=" << bucket_name << ") error " << ret << dendl;
    return ret;
  }

  rgw_obj obj;
  store->get_bucket_instance_obj(bucket_info.bucket, obj);
  store->set_atomic(s->obj_ctx, obj);

  bucket_attrs[RGW_ATTR_POLICY] = polbl;
  return rgw_bucket_set_attrs(store, bucket_info, bucket_attrs, &bucket_info.objv_tracker);
}

bool rgw_auth_id_is_bucket_owner(struct req_state * const s, const rgw_user *owner) {
  string uid;
  if (!owner) {
    owner = &s->bucket_owner.get_id();
  }
  owner->to_str(uid);
  return (!uid.empty() && uid.compare(s->auth_id) == 0);
}
