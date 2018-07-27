#ifndef RGW_NOTIFICATION_H
#define RGW_NOTIFICATION_H

#include <queue>
#include <mutex>
#include <condition_variable>

#include "rgw_common.h"

template<typename T>
class Queue {
private:
  std::queue<T> q;
  std::mutex m;
  std::condition_variable cond;

public:
  Queue() = default;
  Queue(const Queue&) = delete;
  Queue& operator=(const Queue&) = delete;

  T pop() {
    std::unique_lock<std::mutex> mlock(m);
    while (q.empty()) {
      cond.wait(mlock);
    }
    auto val = q.front();
    q.pop();
    return val;
  }

  void pop(T& item) {
    item = pop();
  }

  void pop_all(std::vector<T>& vec) {
    std::unique_lock<std::mutex> mlock(m);
    for (auto l = q.size(); l > 0; l--) {
      vec.push_back(q.front());
      q.pop();
    }
  }

  void push(const T& item) {
    std::unique_lock<std::mutex> mlock(m);
    q.push(item);
    mlock.unlock();
    cond.notify_one();
  }
};

struct FilterRule {
  std::string name;
  std::string value;

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    ::encode(name, bl);
    ::encode(value, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    ::decode(name, bl);
    ::decode(value, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;

  bool match(const std::string& objKey) const;
};
WRITE_CLASS_ENCODER(FilterRule)

struct NotificationTarget {
  std::string id;
  std::vector<FilterRule> filters;
  std::string target_arn;
  std::vector<std::string> events;

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    ::encode(id, bl);
    ::encode(filters, bl);
    ::encode(target_arn, bl);
    ::encode(events, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    ::decode(id, bl);
    ::decode(filters, bl);
    ::decode(target_arn, bl);
    ::decode(events, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;
};
WRITE_CLASS_ENCODER(NotificationTarget)

struct RGWBucketNotificationConf {
  std::vector<NotificationTarget> targets;

  void encode(bufferlist& bl) const {
    ENCODE_START(2, 1, bl);
    ::encode(targets, bl);
    ENCODE_FINISH(bl);
  }

  void decode(bufferlist::iterator& bl) {
    DECODE_START(2, bl);
    ::decode(targets, bl);
    DECODE_FINISH(bl);
  }

  void decode_xml(XMLObj *obj);
  void dump_xml(Formatter *f) const;

  bool match_event(const std::string& objKey, RGWOpType op, std::string& evtName, std::string& targetArn,
      std::string& cfgId);
};
WRITE_CLASS_ENCODER(RGWBucketNotificationConf)

struct NotificationEvent {
  std::string eventName;
  struct timespec eventTime;
  std::string configurationId;
  std::string bucketName;
  std::string objectKey;
  uint64_t objectSize;
  std::string objectETag;
  std::string objectVersionId;
  std::string functionArn;
};

bool verify_lambda_function(const std::string& functionArn, const RGWAccessKey& acckey);
void push_notification_event(NotificationEvent *evt);

#endif /* RGW_NOTIFICATION_H */
