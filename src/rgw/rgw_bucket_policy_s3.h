// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_BUCKET_POLICY_H
#define CEPH_RGW_BUCKET_POLICY_H

#include <list>
#include <string>

#include "common/ceph_json.h"

enum RGWPolicyEffect {
  RGW_POLICY_UNKNOWN,
  RGW_POLICY_ALLOW,
  RGW_POLICY_DENY
};

class RGWBucketPolicy {
  string policy;
  JSONParser *parser;

public:
  RGWBucketPolicy() { parser = NULL; }
  RGWBucketPolicy(char *json) {
    policy = json;
    parser = NULL;
  }
  ~RGWBucketPolicy() {
    if (parser) delete parser;
  }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(policy, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START_LEGACY_COMPAT_LEN(1, 1, 1, bl);
    ::decode(policy, bl);
    DECODE_FINISH(bl);

    if (parser) {
      delete parser;
      parser = NULL;
    }
  }

  bool empty() { return policy.empty(); }
  string tojson() { return policy; }
  RGWPolicyEffect verify_permission(struct RGWUserInfo *user, int op_type,
      const string& bucketname, const struct rgw_obj_key& object);
  RGWPolicyEffect verify_permission(const struct req_state *s);
  static bool is_valid_json(const string& str_json, const string& bucketname);
};

#endif
