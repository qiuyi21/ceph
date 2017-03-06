// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_bucket_policy_s3.h"
#include "rgw_common.h"
#include "rgw_user.h"

#define dout_subsys ceph_subsys_rgw

#define RESOURCE_PREFIX "arn:aws:s3:::"

class WildStr {
  string *ws;
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

  void increase() {
    cur++;
    readchar();
  }

  char get() { return ch; }

public:
  WildStr(const string& str, size_t pos = 0, size_t n = string::npos) {
    ws = new string(str, pos, n);
    cur = NULL;
    ch = '\0';
    escape = false;
  }

  ~WildStr() { delete ws; }

  WildStr& parse(const RGWUserInfo *user) {
    size_t idx, pos = 0;
    string sub("${aws:userid}");
    while ((idx = ws->find(sub, pos)) != string::npos) {
      ws->replace(idx, sub.length(), user->user_id.id);
      pos = idx + sub.length();
    }
    return *this;
  }

  int compare(const char *str) {
    cur = ws->c_str();
    readchar();

    const char *cp = NULL, *mp = NULL;

    while (*str && (this->get() != '*' || escape)) {
      if (this->get() != *str && (this->get() != '?' || escape)) return 1;
      this->increase();
      str++;
    }

    while (*str) {
      if (this->get() == '*' && !escape) {
        this->increase();
        if (!this->get()) return 0;
        mp = cur;
        cp = str + 1;
      } else if (this->get() == *str || (this->get() == '?' && !escape)) {
        this->increase();
        str++;
      } else {
        cur = mp;
        str = cp++;
      }
    }

    while (this->get() == '*' && !escape) this->increase();
    return (this->get() ? -1 : 0);
  }

  int compare(const string& str) { return this->compare(str.c_str()); }

  const char *c_str() { return ws->c_str(); }
};

static inline bool match_resource(const RGWUserInfo *user,
    const string& bucketname, const string& objname, const string& res) {
  size_t slen = sizeof(RESOURCE_PREFIX) - 1;
  if (res.length() < slen + 2) return false;

  WildStr wild(res, slen);
  string str(bucketname);
  str.append("/").append(objname);
  bool ok = !wild.parse(user).compare(str);

  dout(20) << "bucket policy resource \"" << str << "\" " << (ok ? "" : "not ") << "match \"" << wild.c_str() << "\"" << dendl;

  return ok;
}

static bool is_valid_action(const string& act) {
  const char *ss[] = { "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
      "s3:ListMultipartUploadParts", "s3:AbortMultipartUpload", NULL };
  int i = 0;
  do {
    if (!act.compare(ss[i])) return true;
  } while (ss[++i]);
  dout(15) << "bucket policy action not support \"" << act << "\"" << dendl;
  return false;
}

static inline bool match_action(RGWOpType op_type, const string& act) {
  bool ok = false;

  switch (op_type) {
  case RGW_OP_GET_OBJ:
    ok = !act.compare("s3:GetObject");
    break;
  case RGW_OP_PUT_OBJ:
  case RGW_OP_POST_OBJ:
  case RGW_OP_INIT_MULTIPART:
  case RGW_OP_COMPLETE_MULTIPART:
    ok = !act.compare("s3:PutObject");
    break;
  case RGW_OP_DELETE_OBJ:
    ok = !act.compare("s3:DeleteObject");
    break;
  case RGW_OP_LIST_MULTIPART:
    ok = !act.compare("s3:ListMultipartUploadParts");
    break;
  case RGW_OP_ABORT_MULTIPART:
    ok = !act.compare("s3:AbortMultipartUpload");
    break;
  default:
    break;
  }

  if (ok)
    dout(20) << "bucket policy action match \"" << act << "\"" << dendl;

  return ok;
}

static inline bool match_principal(const RGWUserInfo *user, const string& rule, bool isAuth) {
  if (!isAuth) {    // anonymous user
    int i = rule.length() - 1;
    const char *s = rule.c_str();
    for (; i >= 0; i--) {
      if (s[i] != '*') return false;
    }
  }

  WildStr wild(rule);
  bool ok = !wild.parse(user).compare(user->user_id.id);

  if (ok)
    dout(20) << "bucket policy principal \"" << user->user_id.id << "\" match \"" << rule << "\"" << dendl;

  return ok;
}

RGWPolicyEffect RGWBucketPolicy::verify_permission(struct RGWUserInfo *user,
    int op_type, const string& bucketname, const struct rgw_obj_key& object) {
  if (!parser) {
    parser = new JSONParser;
    if (!parser->parse(policy.c_str(), policy.length()))
      return RGW_POLICY_UNKNOWN;
  } else if (!parser->is_success())
    return RGW_POLICY_UNKNOWN;

  JSONObjIter iter = parser->find_first("Statement");
  if (iter.end()) return RGW_POLICY_UNKNOWN;

  bool match;
  bool isAuth = rgw_user_is_authenticated(*user);

  for (iter = (*iter)->find_first(); !iter.end(); ++iter) {
    JSONObj *statement = *iter;

    JSONObjIter iter2 = statement->find_first("Action");
    if (iter2.end()) continue;
    JSONObj *obj = *iter2;
    switch (obj->get_data_type()) {
    case str_type:
      if (!match_action((RGWOpType)op_type, obj->get_data())) continue;
      break;
    case array_type:
      match = false;
      for (iter2 = obj->find_first(); !iter2.end(); ++iter2) {
        obj = *iter2;
        if (match_action((RGWOpType)op_type, obj->get_data())) {
          match = true;
          break;
        }
      }
      if (!match) continue;
      break;
    default:
      break;
    }

    iter2 = statement->find_first("Resource");
    if (iter2.end()) continue;
    obj = *iter2;
    switch (obj->get_data_type()) {
    case str_type:
      if (!match_resource(user, bucketname, object.name, obj->get_data())) continue;
      break;
    case array_type:
      match = false;
      for (iter2 = obj->find_first(); !iter2.end(); ++iter2) {
        obj = *iter2;
        if (match_resource(user, bucketname, object.name, obj->get_data())) {
          match = true;
          break;
        }
      }
      if (!match) continue;
      break;
    default:
      break;
    }

    iter2 = statement->find_first("Principal");
    if (iter2.end()) continue;
    obj = *iter2;
    switch (obj->get_data_type()) {
    case str_type:
      if (!match_principal(user, obj->get_data(), isAuth)) continue;
      break;
    case obj_type:
      iter2 = obj->find_first("AWS");
      if (iter2.end()) continue;
      obj = *iter2;
      switch (obj->get_data_type()) {
      case str_type:
        if (!match_principal(user, obj->get_data(), isAuth)) continue;
        break;
      case array_type:
        match = false;
        for (iter2 = obj->find_first(); !iter2.end(); ++iter2) {
          obj = *iter2;
          if (match_principal(user, obj->get_data(), isAuth)) {
            match = true;
            break;
          }
        }
        if (!match) continue;
        break;
      default:
        break;
      }
      break;
    default:
        break;
    }

    iter2 = statement->find_first("Effect");
    if (!iter2.end() && !(*iter2)->get_data().compare("Allow"))
      return RGW_POLICY_ALLOW;
    return RGW_POLICY_DENY;
  }

  return RGW_POLICY_UNKNOWN;
}

RGWPolicyEffect RGWBucketPolicy::verify_permission(const struct req_state *s) {
  return this->verify_permission(s->user, s->op_type, s->bucket_name, s->object);
}

static inline bool check_statement_arn(const string& arn,
    const string& bucket_name) {
  size_t slen = sizeof(RESOURCE_PREFIX) - 1;
  if (arn.length() < slen + 2 || arn.compare(0, slen, RESOURCE_PREFIX))
    return false;

  size_t idx = arn.find('/', slen);
  if (idx == string::npos || arn.compare(slen, idx - slen, bucket_name))
    return false;

  return true;
}

static bool check_policy_statement(JSONObj *obj, const string& bucketname) {
  string key;
  uint8_t flag = 0;
  JSONObj *obj2;
  JSONObjIter iter = obj->find_first();
  JSONObjIter iter2;

  for (; !iter.end(); ++iter) {
    obj = *iter;
    key = obj->get_name();

    if (!key.compare("Sid")) {
      if (obj->get_data_type() != str_type) return false;

    } else if (!key.compare("Effect")) {
      if (obj->get_data_type() != str_type
          || (obj->get_data().compare("Allow")
              && obj->get_data().compare("Deny")))
        return false;
      flag |= 1;

    } else if (!key.compare("Action")) {
      switch (obj->get_data_type()) {
      case str_type:
        if (!is_valid_action(obj->get_data())) return false;
        break;
      case array_type:
        iter2 = obj->find_first();
        for (obj = NULL; !iter2.end(); ++iter2) {
          obj = *iter2;
          if (obj->get_data_type() != str_type || !is_valid_action(obj->get_data()))
            return false;
        }
        if (!obj) return false;
        break;
      default:
        return false;
      }
      flag |= 2;

    } else if (!key.compare("Principal")) {
      switch (obj->get_data_type()) {
      case str_type:
        if (obj->get_data().compare("*")) return false;
        break;
      case obj_type:
        obj2 = NULL;
        for (iter2 = obj->find_first(); !iter2.end(); ++iter2) {
          obj = *iter2;
          if (obj->get_name().compare("AWS") || obj2) return false;
          obj2 = obj;
        }
        if (!obj2) return false;

        switch (obj2->get_data_type()) {
        case str_type:
          if (obj2->get_data().length() < 1) return false;
          break;
        case array_type:
          for (iter2 = obj2->find_first(); !iter2.end(); ++iter2) {
            obj = *iter2;
            if (obj->get_data_type() != str_type || obj->get_data().length() < 1)
              return false;
          }
          break;
        default:
          return false;
        }
        break;
      default:
        return false;
      }
      flag |= 4;

    } else if (!key.compare("Resource")) {
      switch (obj->get_data_type()) {
      case str_type:
        if (!check_statement_arn(obj->get_data(), bucketname)) {
          dout(15) << "bucket policy resource \"" << obj->get_data() << "\" is invalid" << dendl;
          return false;
        }
        break;
      case array_type:
        iter2 = obj->find_first();
        for (obj = NULL; !iter2.end(); ++iter2) {
          obj = *iter2;
          if (obj->get_data_type() != str_type
              || !check_statement_arn(obj->get_data(), bucketname)) {
            dout(15) << "bucket policy resource \"" << obj->get_data() << "\" is invalid" << dendl;
            return false;
          }
        }
        if (!obj) return false;
        break;
      default:
        return false;
      }
      flag |= 8;

    } else {
      return false;
    }
  }

  return (flag == 15);
}

bool RGWBucketPolicy::is_valid_json(const string& str_json, const string& bucketname) {
  if (str_json.empty()) return false;

  JSONParser parser;
  if (!parser.parse(str_json.c_str(), str_json.length()) || !parser.is_object())
    return false;

  string key;
  JSONObj *obj, *statement = NULL;
  JSONObjIter iter = parser.find_first();

  for(; !iter.end(); ++iter) {
    obj = *iter;
    key = obj->get_name();

    if (!key.compare("Id")) {
      if (obj->get_data_type() != str_type) return false;

    } else if (!key.compare("Version")) {
      if (obj->get_data_type() != str_type
          || (obj->get_data().compare("2008-10-17")
              && obj->get_data().compare("2012-10-17"))) {
        dout(15) << "bucket policy version \"" << obj->get_data() << "\" is invalid" << dendl;
        return false;
      }

    } else if (!key.compare("Statement")) {
      if (!obj->is_array() || statement) return false;
      statement = obj;

    } else {
      return false;
    }
  }

  if (!statement) return false;

  obj = NULL;
  for (iter = statement->find_first(); !iter.end(); ++iter) {
    obj = *iter;
    if (!obj->is_object() || !check_policy_statement(obj, bucketname))
      return false;
  }

  return obj ? true : false;
}
