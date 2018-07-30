#include <boost/thread/thread.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/post.hpp>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/utils/logging/FormattedLogSystem.h>
#include <aws/core/utils/Outcome.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/lambda/LambdaClient.h>
#include <aws/lambda/model/InvokeRequest.h>

#include "ceph_ver.h"
#include "rgw_notification.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_rgw
#define ALLOCATIONTAG "RGW_NOTIFICATION"

static Queue<NotificationEvent *> m_qevent;
static boost::thread *thd_consumer = nullptr;
static std::mutex thd_mutex;
static Aws::SDKOptions m_sdkopt;
static Aws::Lambda::LambdaClient *m_lambda = nullptr;

template<class T>
static void encode_xml(const char *name, const std::vector<T>& val, Formatter *f) {
  f->open_object_section(name);
  for (auto iter = val.begin(); iter != val.end(); iter++) {
    iter->dump_xml(f);
  }
  f->close_section();
}

class AwssdkLogger: public Aws::Utils::Logging::FormattedLogSystem {
public:
  using Base = Aws::Utils::Logging::FormattedLogSystem;
  AwssdkLogger(Aws::Utils::Logging::LogLevel logLevel) : Base(logLevel) {}
  ~AwssdkLogger() {}

protected:
  void ProcessFormattedStatement(Aws::String&& statement) override {
    dout(0) << statement << dendl;
  }
};

void FilterRule::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("Name", name, obj, true);
  RGWXMLDecoder::decode_xml("Value", value, obj, true);
  if ((name.compare("prefix") && name.compare("suffix")) || value.empty()) {
    throw RGWXMLDecoder::err("invalid FilterRule");
  }
}

void FilterRule::dump_xml(Formatter *f) const {
  if (!name.empty() && !value.empty()) {
    f->open_object_section("FilterRule");
    encode_xml("Name", name, f);
    encode_xml("Value", value, f);
    f->close_section();
  }
}

bool FilterRule::match(const std::string& objKey) const {
  if (!name.compare("prefix")) {
    return !objKey.compare(0, value.size(), value);
  } else if (!name.compare("suffix")) {
    if (objKey.size() >= value.size()) {
      return !objKey.compare(objKey.size() - value.size(), value.size(), value);
    }
  }
  return false;
}

void NotificationTarget::decode_xml(XMLObj *obj) {
  RGWXMLDecoder::decode_xml("Id", id, obj, true);
  RGWXMLDecoder::decode_xml("CloudFunction", target_arn, obj, true);
  if (target_arn.compare(0, 15, "arn:aws:lambda:")) {
    throw RGWXMLDecoder::err("invalid CloudFunction");
  }

  XMLObjIter iter;
  XMLObj *o = obj->find_first("Filter");
  if (o && (o = o->find_first("S3Key"))) {
    iter = o->find("FilterRule");
    while ((o = iter.get_next())) {
      FilterRule fr;
      fr.decode_xml(o);
      filters.push_back(fr);
    }
  }

  iter = obj->find("Event");
  while ((o = iter.get_next())) {
    auto val = o->get_data();
    if (!val.empty()) {
      events.push_back(val);
    }
  }
}

void NotificationTarget::dump_xml(Formatter *f) const {
  if (!id.empty()) {
    encode_xml("Id", id, f);
  }
  if (!filters.empty()) {
    f->open_object_section("Filter");
    encode_xml("S3Key", filters, f);
    f->close_section();
  }
  if (!target_arn.empty()) {
    encode_xml("CloudFunction", target_arn, f);
  }
  for (auto iter = events.begin(); iter != events.end(); iter++) {
    encode_xml("Event", *iter, f);
  }
}

void RGWBucketNotificationConf::decode_xml(XMLObj *obj) {
  do_decode_xml_obj(targets, "CloudFunctionConfiguration", obj);
}

void RGWBucketNotificationConf::dump_xml(Formatter *f) const {
  if (!targets.empty()) {
    encode_xml("CloudFunctionConfiguration", targets, f);
  }
}

inline static std::string get_event_name(const std::string& evt, RGWOpType op) {
  if (!evt.compare(0, 17, "s3:ObjectCreated:")) {
    if (!evt.compare(17, std::string::npos, "Put")) {
      if (op == RGW_OP_PUT_OBJ) {
        return evt.substr(3);
      }
    } else if (!evt.compare(17, std::string::npos, "*")) {
      switch (op) {
      case RGW_OP_PUT_OBJ:
        return "ObjectCreated:Put";
      case RGW_OP_POST_OBJ:
        return "ObjectCreated:Post";
      case RGW_OP_COPY_OBJ:
        return "ObjectCreated:Copy";
      case RGW_OP_COMPLETE_MULTIPART:
        return "ObjectCreated:CompleteMultipartUpload";
      default:;
      }
    } else if (!evt.compare(17, std::string::npos, "Post")) {
      if (op == RGW_OP_POST_OBJ) {
        return evt.substr(3);
      }
    } else if (!evt.compare(17, std::string::npos, "Copy")) {
      if (op == RGW_OP_COPY_OBJ) {
        return evt.substr(3);
      }
    } else if (!evt.compare(17, std::string::npos, "CompleteMultipartUpload")) {
      if (op == RGW_OP_COMPLETE_MULTIPART) {
        return evt.substr(3);
      }
    }
  } else if (!evt.compare(0, 17, "s3:ObjectRemoved:")) {
    if (!evt.compare(17, std::string::npos, "Delete")) {
      if (op == RGW_OP_DELETE_OBJ || op == RGW_OP_DELETE_MULTI_OBJ) {
        return evt.substr(3);
      }
    } else if (!evt.compare(17, std::string::npos, "*")) {
      if (op == RGW_OP_DELETE_OBJ || op == RGW_OP_DELETE_MULTI_OBJ) {
        return "ObjectRemoved:Delete";
      }
    }
  }

  return "";
}

bool RGWBucketNotificationConf::match_event(const std::string& objKey, RGWOpType op, std::string& evtName,
    std::string& targetArn, std::string& cfgId) {
  for (auto ti = targets.begin(); ti != targets.end(); ti++) {
    if (ti->target_arn.empty()) {
      continue;
    }

    evtName.clear();
    for (auto ei = ti->events.begin(); ei != ti->events.end(); ei++) {
      evtName = get_event_name(*ei, op);
      if (!evtName.empty()) {
        break;
      }
    }
    if (evtName.empty()) {
      continue;
    }

    bool ok = true;
    for (auto fi = ti->filters.begin(); fi != ti->filters.end(); fi++) {
      if (!fi->match(objKey)) {
        ok = false;
        break;
      }
    }
    if (ok) {
      targetArn = ti->target_arn;
      cfgId = ti->id;
      return true;
    }
  }

  return false;
}

static Aws::Lambda::LambdaClient *get_lambda_client(const RGWAccessKey *acckey) {
  if (m_lambda) {
    return m_lambda;
  }
  std::unique_lock<std::mutex> mlock(thd_mutex);
  if (m_lambda) {
    return m_lambda;
  }

  Aws::Client::ClientConfiguration cfg;
  cfg.scheme = Aws::Http::Scheme::HTTP;
  cfg.verifySSL = false;
  cfg.userAgent = "rgw/" CEPH_GIT_NICE_VER;
  cfg.maxConnections = 1024;
  cfg.connectTimeoutMs = 10000;
  cfg.requestTimeoutMs = 30000;

  std::string url = g_conf->rgw_lambda_server_url;
  if (url.empty()) {
    dout(15) << "lambda: no config rgw_lambda_server_url" << dendl;
    return nullptr;
  }
  std::size_t i = url.find("://");
  if (i != std::string::npos) {
    if (!url.compare(0, i, "https")) {
      cfg.scheme = Aws::Http::Scheme::HTTPS;
    }
    url = url.substr(i + 3);
  }
  i = url.find('/');
  if (i != std::string::npos) {
    url = url.substr(0, i);
  }
  cfg.endpointOverride = url;

  Aws::Auth::AWSCredentials cred;
  if (acckey) {
    cred.SetAWSAccessKeyId(acckey->id);
    cred.SetAWSSecretKey(acckey->key);
  } else {
    cred.SetAWSAccessKeyId(g_conf->rgw_lambda_access_key);
    cred.SetAWSSecretKey(g_conf->rgw_lambda_secret_key);
  }

  m_sdkopt.loggingOptions.logLevel = (Aws::Utils::Logging::LogLevel) g_conf->rgw_aws_sdk_log_level;
  m_sdkopt.loggingOptions.logger_create_fn = []() {
    return Aws::MakeShared<AwssdkLogger>(ALLOCATIONTAG, m_sdkopt.loggingOptions.logLevel);
  };
  Aws::InitAPI(m_sdkopt);

  m_lambda = new Aws::Lambda::LambdaClient(cred, cfg);
  return m_lambda;
}

bool verify_lambda_function(const std::string& functionArn, const RGWAccessKey& acckey) {
  auto client = get_lambda_client(&acckey);
  if (!client) {
    return false;
  }

  std::shared_ptr<Aws::IOStream> payload = Aws::MakeShared<Aws::StringStream>(ALLOCATIONTAG);
  *payload << "{}";

  Aws::Lambda::Model::InvokeRequest invokeRequest;
  invokeRequest.SetFunctionName(functionArn);
  invokeRequest.SetInvocationType(Aws::Lambda::Model::InvocationType::DryRun);
  invokeRequest.SetLogType(Aws::Lambda::Model::LogType::Tail);
  invokeRequest.SetBody(payload);

  auto response = client->Invoke(invokeRequest);
  if (!response.IsSuccess()) {
    auto &ae = response.GetError();
    dout(20) << "lambda: DryRun " << functionArn << " error: (" << ae.GetExceptionName() << ") "
        << ae.GetMessage() << dendl;
    return false;
  }
  return true;
}

// https://docs.aws.amazon.com/lambda/latest/dg/with-s3-example-upload-deployment-pkg.html
inline static std::shared_ptr<Aws::IOStream> create_invoke_payload(const std::vector<NotificationEvent *> *events) {
  std::shared_ptr<Aws::IOStream> payload = Aws::MakeShared<Aws::StringStream>(ALLOCATIONTAG);
  Aws::Utils::Array<Aws::Utils::Json::JsonValue> arr(events->size());
  int i = 0;

  for (auto iter = events->begin(); iter != events->end(); iter++) {
    auto evt = *iter;
    Aws::Utils::Json::JsonValue& record = arr[i++];

    record.WithString("eventVersion", "2.0");
    record.WithString("eventSource", "aws:s3");
    struct tm tim;
    if (gmtime_r(&evt->eventTime.tv_sec, &tim)) {
      char buf[32];
      buf[0] = '\0';
      size_t n = strftime(buf, sizeof(buf), "%FT%T", &tim);
      snprintf(buf + n, sizeof(buf) - n, ".%03ldZ", evt->eventTime.tv_nsec / 1000000);
      record.WithString("eventTime", buf);
    }
    record.WithString("eventName", evt->eventName);
    if (!evt->userId.empty()) {
      record.WithObject("userIdentity", Aws::Utils::Json::JsonValue().WithString("principalId", evt->userId));
    }

    Aws::Utils::Json::JsonValue s3, bucket, obj;
    bucket.WithString("name", evt->bucketName);
    if (!evt->ownerId.empty()) {
      bucket.WithObject("ownerIdentity", Aws::Utils::Json::JsonValue().WithString("principalId", evt->ownerId));
    }

    obj.WithString("key", evt->objectKey);
    obj.WithInt64("size", evt->objectSize);
    obj.WithString("eTag", evt->objectETag);
    if (!evt->objectVersionId.empty()) {
      obj.WithString("versionId", evt->objectVersionId);
    }
    s3.WithString("s3SchemaVersion", "1.0");
    if (!evt->configurationId.empty()) {
      s3.WithString("configurationId", evt->configurationId);
    }
    s3.WithObject("bucket", bucket);
    s3.WithObject("object", obj);

    record.WithObject("s3", s3);
  }

  Aws::Utils::Json::JsonValue js;
  js.WithArray("Records", arr);
  auto jss = js.WriteCompact();

  dout(20) << "lambda: invoke " << events->at(0)->functionArn << " body: " << jss << dendl;

  *payload << jss;
  return payload;
}

static void exec_lambda(std::shared_ptr<std::vector<NotificationEvent *>> events) {
  auto client = get_lambda_client(nullptr);
  if (!client) {
    return;
  }

  const std::string& functionArn = events->at(0)->functionArn;
  bool isDebug = (Aws::Utils::Logging::LogLevel) g_conf->rgw_aws_sdk_log_level >= Aws::Utils::Logging::LogLevel::Debug;
  Aws::Lambda::Model::InvokeRequest invokeRequest;
  invokeRequest.SetFunctionName(functionArn);
  if (isDebug) {
    invokeRequest.SetInvocationType(Aws::Lambda::Model::InvocationType::RequestResponse);
    invokeRequest.SetLogType(Aws::Lambda::Model::LogType::Tail);
  } else {
    invokeRequest.SetInvocationType(Aws::Lambda::Model::InvocationType::Event);
    invokeRequest.SetLogType(Aws::Lambda::Model::LogType::None);
  }
  invokeRequest.SetBody(create_invoke_payload(events.get()));

  auto response = client->Invoke(invokeRequest);
  if (response.IsSuccess()) {
    if (isDebug) {
      auto &result = response.GetResult();
      Aws::IOStream& payload = result.GetPayload();
      Aws::String functionResult;
      std::getline(payload, functionResult);
      dout(20) << "lambda: invoke " << functionArn << " result: " << functionResult << dendl;

      auto byteLogResult = Aws::Utils::HashingUtils::Base64Decode(result.GetLogResult());
      Aws::StringStream logResult;
      for (unsigned i = 0; i < byteLogResult.GetLength(); i++)
        logResult << byteLogResult.GetItem(i);
      dout(20) << "lambda: invoke " << functionArn << " log result: " << logResult.str() << dendl;
    } else {
      dout(20) << "lambda: invoke " << functionArn << dendl;
    }
  } else {
    auto &ae = response.GetError();
    dout(20) << "lambda: invoke " << functionArn << " error: (" << ae.GetExceptionName() << ") "
        << ae.GetMessage() << dendl;
  }
}

static void event_consumer() {
  boost::asio::thread_pool pool(std::max<std::size_t>(g_conf->rgw_notification_event_threads, 1));
  typedef std::vector<NotificationEvent *> eventlist;
  eventlist events;

  for (;;) {
    auto item = m_qevent.pop();
    events.clear();
    events.push_back(item);
    usleep(400000); // 400ms
    m_qevent.pop_all(events);

    std::map<std::string, std::shared_ptr<eventlist>> evtmap;
    for (auto i = events.begin(); i != events.end(); i++) {
      auto iter = evtmap.find((*i)->functionArn);
      if (iter == evtmap.end()) {
        std::shared_ptr<eventlist> val(new eventlist, [](eventlist *p) {
          for (auto pi = p->begin(); pi != p->end(); pi++) {
            delete *pi;
          }
          delete p;
        });
        val->push_back(*i);
        evtmap.insert(std::pair<std::string, std::shared_ptr<eventlist>>((*i)->functionArn, val));
      } else {
        (*iter).second->push_back(*i);
      }
    }

    for (auto iter = evtmap.begin(); iter != evtmap.end(); iter++) {
      boost::asio::post(pool, boost::bind(exec_lambda, (*iter).second));
    }
  }
}

void push_notification_event(NotificationEvent *evt) {
  if (clock_gettime(CLOCK_REALTIME, &evt->eventTime)) {
    struct timeval tv;
    if (gettimeofday(&tv, NULL)) {
      memset(&evt->eventTime, 0, sizeof(evt->eventTime));
      evt->eventTime.tv_sec = time(NULL);
    } else {
      evt->eventTime.tv_sec = tv.tv_sec;
      evt->eventTime.tv_nsec = tv.tv_usec * 1000;
    }
  }

  dout(20) << "new notification event: " << evt->eventName << ", time=" << evt->eventTime
      << ", cfgId=" << evt->configurationId << ", bucket=" << evt->bucketName
      << ", objKey=" << evt->objectKey << ", objSize=" << evt->objectSize
      << ", etag=" << evt->objectETag << ", versionId=" << evt->objectVersionId
      << ", functionArn=" << evt->functionArn << dendl;

  if (!thd_consumer) {
    std::unique_lock<std::mutex> mlock(thd_mutex);
    if (!thd_consumer) {
      thd_consumer = new boost::thread(&event_consumer);
    }
  }

  m_qevent.push(evt);
}
