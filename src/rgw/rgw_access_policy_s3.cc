// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "rgw_common.h"
#include "rgw_rest.h"
#include "common/errno.h"
#include "rgw_access_policy_s3.h"

#define dout_subsys ceph_subsys_rgw

void RGWOp_AccessPolicy_Get::send_response() {
  set_req_state_err(s, http_ret);
  dump_errno(s);

  if (http_ret < 0) {
    end_header(s);
    return;
  }

  encode_json("", pol, s->formatter);
  end_header(s, NULL, "application/json", s->formatter->get_len());
  flusher.flush();
}

void RGWOp_AccessPolicy_Set::execute() {
  auto cct = store->ctx();
  RGWAccessPolicy pol;
  bool empty;

  http_ret = rgw_rest_get_json_input(cct, s, pol, 20480, &empty);
  if (http_ret < 0 && !empty) {
    if (http_ret == -ERANGE) http_ret = -ERR_TOO_LARGE;
    ldout(cct, 15) << __PRETTY_FUNCTION__ << ": decode access policy error " << http_ret << dendl;
    return;
  }

  auto zg = store->get_zonegroup();
  string pool_name = zg.get_pool_name(cct);
  rgw_bucket pool(pool_name.c_str());
  string oid = ACCESS_POLICY_PREFIX + zg.get_id();

  if (empty) {
    rgw_obj obj(pool, oid);
    http_ret = store->delete_system_obj(obj);
    if (http_ret < 0) {
      if (http_ret == -ENOENT) {
        http_ret = 0;
      } else {
        lderr(cct) << __PRETTY_FUNCTION__ << ": delete_system_obj() return error " << http_ret << dendl;
      }
    }
    return;
  }

  pol.sort();

  bufferlist bl;
  ::encode(pol, bl);
  http_ret = rgw_put_system_obj(store, pool, oid, bl.c_str(), bl.length(), false, NULL, real_time(), NULL);
  if (http_ret < 0) {
    lderr(cct) << __PRETTY_FUNCTION__ << ": rgw_put_system_obj() return error " << http_ret << dendl;
  }
}

void RGWIpPolicy::dump(Formatter *f) const {
  char buf[24];
  uint32_t n = mask;
  __u8 i;
  for (i = 0; i < 32 && !(n & 1); i++, n >>= 1) ;
  buf[0] = '\0';
  snprintf(buf, sizeof(buf), "%hhu.%hhu.%hhu.%hhu/%hhu", ipaddr >> 24, ipaddr >> 16, ipaddr >> 8, ipaddr,
      32 - i);
  encode_json("cidr", (const char *) buf, f);
  encode_json("order", (unsigned) order, f);
  encode_json("effect", effect == RGW_POLICY_ALLOW ? "allow" : "deny", f);
}

void RGWIpPolicy::decode_json(JSONObj *obj) {
  string s;
  JSONDecoder::decode_json("cidr", s, obj, true);
  size_t idx = s.find('/');
  mask = (uint32_t) -1;
  if (idx != string::npos) {
    int i = stoi(s.substr(idx + 1));
    if (i < 0 || i > 32)
      throw JSONDecoder::err("bad field cidr");
    s = s.substr(0, idx);
    for (i = 32 - i; i > 0; i--)
      mask <<= 1;
  }
  struct in_addr ia;
  if (inet_pton(AF_INET, s.c_str(), &ia) != 1)
    throw JSONDecoder::err("bad field cidr");
  ipaddr = htonl(ia.s_addr) & mask;

  uint32_t n;
  JSONDecoder::decode_json("order", n, obj, true);
  order = (uint16_t) n;

  JSONDecoder::decode_json("effect", s, obj, true);
  effect = strcasecmp(s.c_str(), "allow") ? RGW_POLICY_DENY : RGW_POLICY_ALLOW;
}

int RGWAccessPolicy::init(RGWRados *store) {
  auto cct = store->ctx();

  auto zg = store->get_zonegroup();
  string pool_name = zg.get_pool_name(cct);
  rgw_bucket pool(pool_name.c_str());
  string oid = ACCESS_POLICY_PREFIX + zg.get_id();

  bufferlist bl;
  RGWObjectCtx obj_ctx(store);
  int ret = rgw_get_system_obj(store, obj_ctx, pool, oid, bl, NULL, NULL);
  if (ret < 0) {
    if (ret != -ENOENT) {
      lderr(cct) << __PRETTY_FUNCTION__ << ": failed reading object from " << pool << ":" << oid << ": " << cpp_strerror(-ret) << dendl;
    }
    return ret;
  }

  bufferlist::iterator biter = bl.begin();
  try {
    ::decode(*this, biter);
  } catch (buffer::error& err) {
    lderr(cct) << __PRETTY_FUNCTION__ << ": decode access policy error" << dendl;
    return -EIO;
  }
  return 0;
}

bool RGWAccessPolicy::is_allow(uint32_t ip) {
  for (auto iter = ipaddresses.begin(); iter != ipaddresses.end(); ++iter) {
    if (iter->match(ip))
      return iter->get_effect() == RGW_POLICY_ALLOW;
  }
  return false;
}

int RGWAccessPolicy::check(struct req_state *s) {
  if (ipaddresses.empty()) return 0;

  struct in_addr ia;
  const char *pc = s->info.env->get("HTTP_X_FORWARDED_FOR");
  if (pc && *pc) {
    if (inet_pton(AF_INET, pc, &ia) != 1) {
      ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": invalid IPv4 " << pc << " in X_Forwarded_For" << dendl;
      goto deny;
    }
    if ((__u8) ia.s_addr != 127 && !is_allow(htonl(ia.s_addr))) {
      ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": policy not allow IPv4 " << pc << " in X_Forwarded_For" << dendl;
      goto deny;
    }
  }

  pc = s->info.env->get("REMOTE_ADDR");
  if (!pc || !pc[0]) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": no REMOTE_ADDR" << dendl;
    goto deny;
  }
  if (inet_pton(AF_INET, pc, &ia) != 1) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": invalid IPv4 " << pc << " in REMOTE_ADDR" << dendl;
    goto deny;
  }
  if ((__u8) ia.s_addr != 127 && !is_allow(htonl(ia.s_addr))) {
    ldout(s->cct, 20) << __PRETTY_FUNCTION__ << ": policy not allow IPv4 " << pc << " in REMOTE_ADDR" << dendl;
    goto deny;
  }

  return 0;
deny:
  s->err.message = "Does not conform to IP policies";
  return -EACCES;
}

void RGWAccessPolicy::dump(Formatter *f) const {
  encode_json("ipAddresses", ipaddresses, f);
}

void RGWAccessPolicy::decode_json(JSONObj *obj) {
  JSONDecoder::decode_json("ipAddresses", ipaddresses, obj, true);
}
