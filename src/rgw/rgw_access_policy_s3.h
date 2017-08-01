// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_RGW_ACCESS_POLICY_H
#define CEPH_RGW_ACCESS_POLICY_H

#define ACCESS_POLICY_PREFIX "access_policy."

class RGWIpPolicy {
  uint32_t ipaddr;
  uint32_t mask;
  uint16_t order;
  __u8 effect;

public:
  bool operator<(const RGWIpPolicy& o) const {
    int r = order - o.order;
    if (!r) {
      r = ipaddr - o.ipaddr;
      if (!r) {
        r = mask - o.mask;
        if (!r)
          r = o.effect - effect;
      }
    }
    return r < 0;
  }

  __u8 get_effect() const { return effect; }
  bool match(uint32_t ip) const { return (ip & mask) == ipaddr; }

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(ipaddr, bl);
    ::encode(mask, bl);
    ::encode(order, bl);
    ::encode(effect, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    ::decode(ipaddr, bl);
    ::decode(mask, bl);
    ::decode(order, bl);
    ::decode(effect, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWIpPolicy)

class RGWAccessPolicy {
  vector<RGWIpPolicy> ipaddresses;

  bool is_allow(uint32_t ip);

public:
  int init(RGWRados *store);
  void sort() { std::sort(ipaddresses.begin(), ipaddresses.end()); }
  int check(struct req_state *s);

  void encode(bufferlist& bl) const {
    ENCODE_START(1, 1, bl);
    ::encode(ipaddresses, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(1, bl);
    ::decode(ipaddresses, bl);
    DECODE_FINISH(bl);
  }

  void dump(Formatter *f) const;
  void decode_json(JSONObj *obj);
};
WRITE_CLASS_ENCODER(RGWAccessPolicy)

class RGWOp_AccessPolicy_Get: public RGWRESTOp {
  RGWAccessPolicy pol;

public:
  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("accpol", RGW_CAP_READ);
  }

  void execute() {
    http_ret = pol.init(store);
    if (http_ret == -ENOENT) {
      http_ret = -ERR_NOT_FOUND;
      s->err.message = "Access policy does not exist";
    }
  }

  virtual void send_response();
  virtual const string name() { return "get_access_policy"; }
};

class RGWOp_AccessPolicy_Set: public RGWRESTOp {
public:
  int check_caps(RGWUserCaps& caps) {
    return caps.check_cap("accpol", RGW_CAP_WRITE);
  }

  void execute();
  virtual const string name() { return "set_access_policy"; }
};

#endif
