#include "submission/network.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/gen_stats.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/securebits.h>
#include <linux/sockios.h>
#include <locale>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace turtle::submission {
namespace {
using namespace std::chrono_literals;
using Args = std::vector<std::string>;
using Clock = std::chrono::steady_clock;
using Stop = const volatile std::sig_atomic_t *;
constexpr const char *device = "turt0";
constexpr const char *peer_device = "turt1";
constexpr unsigned handle = 1 << 16;
constexpr std::uint32_t queue_limit = 10000;
constexpr std::uint32_t max_probability = std::numeric_limits<std::uint32_t>::max();

class Fd {
public:
  explicit Fd(int fd = -1) : fd_(fd) {}
  ~Fd() { if (fd_ >= 0) close(fd_); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  Fd(Fd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  Fd &operator=(Fd &&other) noexcept {
    std::swap(fd_, other.fd_);
    return *this;
  }
  int get() const { return fd_; }
private:
  int fd_;
};

void check(bool success, const char *operation) {
  if (!success)
    throw std::runtime_error(std::string(operation) + ": " + std::strerror(errno));
}

void require(bool success, const char *message) {
  if (!success)
    throw std::runtime_error(message);
}

void check_stop(Stop stop) {
  require(!stop || !*stop, "network setup interrupted");
}

void enter_namespace(int fd) {
  check(setns(fd, CLONE_NEWNET) == 0, "enter private network namespace");
}

struct Result {
  int code = -1;
  std::string output;
};

// No command receives a shell string. Enforce a deadline even if a helper
// stops responding, and kill it on abnormal parent exit.
Result helper(Stop stop, const std::function<int()> &action, int fd,
              std::chrono::seconds timeout = 5s) {
  check_stop(stop);
  int fds[2];
  check(pipe2(fds, O_CLOEXEC) == 0, "open network helper pipe");
  Fd input(fds[0]), output(fds[1]);
  const auto owner = getpid();
  const auto pid = fork();
  check(pid >= 0, "fork network helper");
  if (pid == 0) {
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != owner)
      _exit(125);
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    if (dup2(output.get(), STDOUT_FILENO) < 0 ||
        dup2(output.get(), STDERR_FILENO) < 0)
      _exit(125);
    try {
      if (fd >= 0)
        enter_namespace(fd);
      _exit(action());
    } catch (const std::exception &e) {
      dprintf(STDERR_FILENO, "%s\n", e.what());
      _exit(125);
    }
  }
  output = Fd{};
  try {
    Result result;
    const auto deadline = Clock::now() + timeout;
    int status = 0;
    bool eof = false;
    for (;;) {
      check_stop(stop);
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
          deadline - Clock::now()).count();
      require(left > 0, "network helper timed out");
      pollfd event{input.get(), POLLIN, 0};
      if (!eof) {
        const auto ready = poll(&event, 1, static_cast<int>(std::min<long long>(left, 100)));
        if (ready < 0 && errno == EINTR)
          continue;
        check(ready >= 0, "poll network helper");
        if (ready == 0)
          continue;
        std::array<char, 4096> bytes;
        const auto n = read(input.get(), bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR)
          continue;
        check(n >= 0, "read network helper");
        if (n > 0) {
          result.output.append(bytes.data(), static_cast<std::size_t>(n));
          require(result.output.size() <= 65536, "network helper output exceeds limit");
          continue;
        }
        eof = true;
      }
      const auto waited = waitpid(pid, &status, WNOHANG);
      if (waited == pid) {
        result.code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        return result;
      }
      if (waited < 0 && errno != EINTR)
        check(false, "wait for network helper");
      std::this_thread::sleep_for(1ms);
    }
  } catch (...) {
    kill(pid, SIGKILL);
    while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
    throw;
  }
}

Fd new_namespace(Stop stop) {
  int pair[2];
  check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) == 0,
        "open namespace transfer socket");
  Fd parent(pair[0]), child(pair[1]);
  const auto result = helper(stop, [&] {
    if (unshare(CLONE_NEWNET) != 0)
      check(false, "create private network namespace");
    Fd ns(open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC));
    check(ns.get() >= 0, "open private network namespace");
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    char byte = 'N';
    iovec io{&byte, 1};
    msghdr message{};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof control;
    auto *c = CMSG_FIRSTHDR(&message);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    const int fd = ns.get();
    std::memcpy(CMSG_DATA(c), &fd, sizeof fd);
    check(sendmsg(child.get(), &message, MSG_NOSIGNAL) == 1,
          "transfer private network namespace");
    return 0;
  }, -1);
  if (result.code != 0)
    throw std::runtime_error(result.output.empty() ? "namespace helper failed" : result.output);
  alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
  char byte = 0;
  iovec io{&byte, 1};
  msghdr message{};
  message.msg_iov = &io;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof control;
  check(recvmsg(parent.get(), &message, MSG_CMSG_CLOEXEC | MSG_DONTWAIT) == 1,
        "receive private network namespace");
  auto *c = CMSG_FIRSTHDR(&message);
  require(byte == 'N' && !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
              c && c->cmsg_len == CMSG_LEN(sizeof(int)) &&
              c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS,
          "invalid namespace transfer");
  int fd;
  std::memcpy(&fd, CMSG_DATA(c), sizeof fd);
  return Fd(fd);
}

Result command(Stop stop, int ns, Args args, std::chrono::seconds timeout = 5s,
               int inherit = -1) {
  return helper(stop, [&] {
    if (inherit >= 0)
      check(fcntl(inherit, F_SETFD, 0) == 0, "pass peer namespace to ip");
    check(setenv("LC_ALL", "C", 1) == 0 &&
              setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) == 0,
          "set network helper environment");
    std::vector<char *> argv;
    for (auto &arg : args)
      argv.push_back(arg.data());
    argv.push_back(nullptr);
    execvp(argv[0], argv.data());
    check(false, argv[0]);
    return 125;
  }, ns, timeout);
}

std::string run(Stop stop, int ns, Args args, int inherit = -1) {
  const auto result = command(stop, ns, args, 5s, inherit);
  if (result.code == 0)
    return result.output;
  std::string invocation;
  for (const auto &arg : args)
    invocation += " " + arg;
  throw std::runtime_error("network command failed:" + invocation + ": " + result.output);
}

std::string prepare_device(Stop stop, int ns) {
  const auto result = helper(stop, [] {
    Fd fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    check(fd.get() >= 0, "open offload control socket");
    ifreq request{};
    std::strncpy(request.ifr_name, device, sizeof request.ifr_name - 1);
    for (const auto &[set, get] : {std::pair{ETHTOOL_STSO, ETHTOOL_GTSO},
                                  std::pair{ETHTOOL_SGSO, ETHTOOL_GGSO},
                                  std::pair{ETHTOOL_SGRO, ETHTOOL_GGRO}}) {
      ethtool_value setting{static_cast<__u32>(set), 0};
      request.ifr_data = reinterpret_cast<char *>(&setting);
      check(ioctl(fd.get(), SIOCETHTOOL, &request) == 0, "disable veth offload");
      setting = {static_cast<__u32>(get), 1};
      check(ioctl(fd.get(), SIOCETHTOOL, &request) == 0, "read veth offload");
      require(setting.data == 0, "veth offload still enabled");
    }
    check(ioctl(fd.get(), SIOCGIFHWADDR, &request) == 0, "read veth MAC address");
    require(request.ifr_hwaddr.sa_family == ARPHRD_ETHER, "veth device is not Ethernet");
    const auto *mac =
        reinterpret_cast<const unsigned char *>(request.ifr_hwaddr.sa_data);
    dprintf(STDOUT_FILENO, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
  }, ns);
  if (result.code != 0 || result.output.size() != 17)
    throw std::runtime_error("veth device configuration: " + result.output);
  return result.output;
}

std::string decimal(double number, int places = 10) {
  std::ostringstream out;
  out.imbue(std::locale::classic());
  out << std::fixed << std::setprecision(places) << number;
  return out.str();
}

std::string number(double value) {
  char buffer[40];
  const auto converted =
      std::to_chars(std::begin(buffer), std::end(buffer), value);
  require(converted.ec == std::errc{}, "number does not fit in CSV");
  return {buffer, converted.ptr};
}

struct Qdisc {
  std::int64_t delay_ns = 0;
  std::uint32_t loss = 0;
  std::uint64_t sent = 0;
  std::uint32_t drops = 0, backlog_packets = 0;
};

const rtattr *attribute(const void *start, std::size_t length, unsigned type) {
  const auto *a = static_cast<const rtattr *>(start);
  while (RTA_OK(a, length)) {
    if ((a->rta_type & NLA_TYPE_MASK) == type)
      return a;
    const auto step = static_cast<std::size_t>(RTA_ALIGN(a->rta_len));
    if (step > length)
      break;
    a = RTA_NEXT(a, length);
  }
  return nullptr;
}

template <typename T> T read_value(const rtattr *a) {
  require(a && RTA_PAYLOAD(a) >= sizeof(T), "missing or short qdisc attribute");
  T v{};
  std::memcpy(&v, RTA_DATA(a), sizeof v);
  return v;
}

Qdisc parse_netem(const nlmsghdr *message, std::int64_t expected_delay,
                  double expected_loss) {
  const auto *info = static_cast<const tcmsg *>(NLMSG_DATA(message));
  require(info->tcm_handle == handle, "unexpected veth qdisc handle");
  const auto *attrs = TCA_RTA(info);
  const auto length = TCA_PAYLOAD(message);
  const auto *kind = attribute(attrs, length, TCA_KIND);
  require(kind && RTA_PAYLOAD(kind) == sizeof("netem") &&
              std::memcmp(RTA_DATA(kind), "netem", sizeof("netem")) == 0,
          "veth root qdisc is not netem");
  const auto *options = attribute(attrs, length, TCA_OPTIONS);
  const auto base = read_value<tc_netem_qopt>(options);
  const auto *extra = static_cast<const char *>(RTA_DATA(options)) + RTA_ALIGN(sizeof base);
  const auto extra_len = RTA_PAYLOAD(options) - RTA_ALIGN(sizeof base);
  const auto *latency = attribute(extra, extra_len, TCA_NETEM_LATENCY64);
  Qdisc q;
  if (latency)
    q.delay_ns = read_value<std::int64_t>(latency);
  else
    require(expected_delay == 0 && base.latency == 0, "kernel does not expose exact applied delay");
  const auto *correlation = attribute(extra, extra_len, TCA_NETEM_CORR);
  if (correlation)
    require(read_value<tc_netem_corr>(correlation).loss_corr == 0, "netem loss is correlated");
  require(!attribute(extra, extra_len, TCA_NETEM_LOSS), "netem loss is not random");
  const auto *jitter = attribute(extra, extra_len, TCA_NETEM_JITTER64);
  const auto *ecn = attribute(extra, extra_len, TCA_NETEM_ECN);
  const auto *rate = attribute(extra, extra_len, TCA_NETEM_RATE);
  const auto *reorder = attribute(extra, extra_len, TCA_NETEM_REORDER);
  const auto *corrupt = attribute(extra, extra_len, TCA_NETEM_CORRUPT);
  require(base.gap == 0 && base.duplicate == 0 && base.jitter == 0 &&
              (!jitter || read_value<std::int64_t>(jitter) == 0) &&
              (!ecn || read_value<std::uint32_t>(ecn) == 0) &&
              (!rate || read_value<tc_netem_rate>(rate).rate == 0) &&
              !attribute(extra, extra_len, TCA_NETEM_RATE64) &&
              (!reorder || read_value<tc_netem_reorder>(reorder).probability == 0) &&
              (!corrupt || read_value<tc_netem_corrupt>(corrupt).probability == 0) &&
              !attribute(extra, extra_len, TCA_NETEM_SLOT),
          "veth qdisc has unexpected impairments");
  q.loss = base.loss;
  const double target = expected_loss * max_probability / 100.0;
  require(q.delay_ns == expected_delay && base.limit == queue_limit &&
              (expected_loss == 0.0 ? q.loss == 0 :
               expected_loss == 100.0 ? q.loss == max_probability :
               q.loss != 0 && std::abs(q.loss - target) <= 1.0),
          "kernel netem settings do not match the request");

  const auto *stats = attribute(attrs, length, TCA_STATS2);
  require(stats, "kernel did not report qdisc statistics");
  const auto *fields = RTA_DATA(stats);
  const auto sizes = RTA_PAYLOAD(stats);
  const auto *long_packets = attribute(fields, sizes, TCA_STATS_PKT64);
  const auto *basic = attribute(fields, sizes, TCA_STATS_BASIC);
  if (long_packets) {
    q.sent = read_value<std::uint64_t>(long_packets);
  } else {
    // The wire payload need not contain trailing padding of gnet_stats_basic.
    require(basic && RTA_PAYLOAD(basic) >= 12, "kernel did not report sent packet count");
    std::uint32_t short_packets;
    std::memcpy(&short_packets, static_cast<const char *>(RTA_DATA(basic)) + 8,
                sizeof short_packets);
    q.sent = short_packets;
  }
  const auto queue = read_value<gnet_stats_queue>(attribute(fields, sizes, TCA_STATS_QUEUE));
  q.drops = queue.drops;
  q.backlog_packets = queue.qlen;
  return q;
}

Qdisc inspect_netem(std::int64_t expected_delay, double expected_loss) {
  const auto ifindex = if_nametoindex(device);
  check(ifindex != 0, "find veth device");
  Fd fd(socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE));
  check(fd.get() >= 0, "open qdisc readback socket");
  const timeval timeout{2, 0};
  check(setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) == 0,
        "set qdisc readback timeout");
  struct { nlmsghdr header; tcmsg info; } request{};
  request.header.nlmsg_len = NLMSG_LENGTH(sizeof(tcmsg));
  request.header.nlmsg_type = RTM_GETQDISC;
  request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  request.header.nlmsg_seq = 1;
  request.info.tcm_family = AF_UNSPEC;
  request.info.tcm_ifindex = static_cast<int>(ifindex);
  sockaddr_nl kernel{};
  kernel.nl_family = AF_NETLINK;
  check(sendto(fd.get(), &request, request.header.nlmsg_len, 0,
               reinterpret_cast<sockaddr *>(&kernel), sizeof kernel) ==
            request.header.nlmsg_len,
        "request qdisc readback");
  Qdisc q;
  bool found = false;
  for (int receive_count = 0; receive_count < 32; ++receive_count) {
    alignas(nlmsghdr) std::array<char, 32768> buffer;
    sockaddr_nl sender{};
    iovec data{buffer.data(), buffer.size()};
    msghdr input{};
    input.msg_name = &sender;
    input.msg_namelen = sizeof sender;
    input.msg_iov = &data;
    input.msg_iovlen = 1;
    auto length = recvmsg(fd.get(), &input, 0);
    if (length < 0 && errno == EINTR)
      continue;
    check(length >= 0, "receive qdisc readback");
    require(length != 0 && !(input.msg_flags & MSG_TRUNC) && sender.nl_pid == 0,
            "invalid qdisc readback");
    for (auto *m = reinterpret_cast<nlmsghdr *>(buffer.data()); NLMSG_OK(m, length);
         m = NLMSG_NEXT(m, length)) {
      require(m->nlmsg_seq == 1 && !(m->nlmsg_flags & NLM_F_DUMP_INTR),
              "inconsistent qdisc dump");
      if (m->nlmsg_type == NLMSG_DONE) {
        if (m->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) {
          int error;
          std::memcpy(&error, NLMSG_DATA(m), sizeof error);
          require(error == 0, "qdisc dump failed");
        }
        require(found, "veth root qdisc missing");
        return q;
      }
      require(m->nlmsg_type == RTM_NEWQDISC && m->nlmsg_len >= NLMSG_LENGTH(sizeof(tcmsg)),
              "unexpected qdisc dump reply");
      const auto *info = static_cast<const tcmsg *>(NLMSG_DATA(m));
      if (info->tcm_ifindex != static_cast<int>(ifindex) || info->tcm_parent != TC_H_ROOT)
        continue;
      require(!found, "multiple veth root qdiscs");
      q = parse_netem(m, expected_delay, expected_loss);
      found = true;
    }
  }
  throw std::runtime_error("qdisc dump did not terminate");
}

Qdisc snapshot(Stop stop, int ns, std::int64_t expected_delay, double expected_loss) {
  Qdisc q;
  const auto result = helper(stop, [&] {
    const auto readback = inspect_netem(expected_delay, expected_loss);
    dprintf(STDOUT_FILENO, "%lld %u %llu %u %u\n",
            static_cast<long long>(readback.delay_ns), readback.loss,
            static_cast<unsigned long long>(readback.sent), readback.drops,
            readback.backlog_packets);
    return 0;
  }, ns);
  if (result.code != 0)
    throw std::runtime_error("qdisc readback: " + result.output);
  std::istringstream row(result.output);
  require(bool(row >> q.delay_ns >> q.loss >> q.sent >> q.drops >> q.backlog_packets),
          "missing qdisc helper output");
  return q;
}

struct Probe {
  double rtt_avg_ms = 0;
  unsigned replies = 0;
  std::string status = "probe_failed";
};

Probe probe(Stop stop, int ns, const char *remote, double rtt_ms, std::ostream &log) {
  const auto wait = static_cast<int>(std::ceil(rtt_ms / 1000)) + 1;
  const auto result = command(stop, ns, {"ping", "-n", "-q", "-c", "3", "-i", "0.2",
                                   "-W", std::to_string(wait), "-w",
                                   std::to_string(wait + 2), remote},
                              std::chrono::seconds(wait + 4));
  log << "ping " << remote << " (exit " << result.code << ")\n" << result.output;
  Probe p;
  const auto field = result.output.find(" packets transmitted, ");
  if (field == std::string::npos)
    return p;
  std::istringstream counts(result.output.substr(field + std::strlen(" packets transmitted, ")));
  std::string received;
  if (!(counts >> p.replies >> received) || received != "received,")
    return p;
  if (p.replies == 0 && result.code == 1) {
    p.status = "no_replies";
    return p;
  }
  const auto timing = result.output.find("min/avg/max/");
  if (p.replies == 0 || timing == std::string::npos || result.code > 1 || result.code < 0)
    return p;
  const auto assignment = result.output.find(" = ", timing);
  if (assignment == std::string::npos)
    return p;
  std::istringstream rtt(result.output.substr(assignment + 3));
  rtt.imbue(std::locale::classic());
  double min = 0;
  char slash = 0;
  if ((rtt >> min >> slash >> p.rtt_avg_ms) && slash == '/' &&
      std::isfinite(p.rtt_avg_ms) && p.rtt_avg_ms >= 0)
    p.status = "available";
  return p;
}

} // namespace

struct Network::State {
  std::filesystem::path dir;
  double requested_rtt_ms, requested_loss_pct;
  Stop stop;
  std::int64_t delay_ns;
  std::array<Fd, 2> ns;
  std::array<Qdisc, 2> applied{}, before{}, after{};
  std::array<Probe, 2> probes{};
  std::string counter_status = "not_started";

  State(const std::filesystem::path &path, double rtt, double loss, Stop cancel)
      : dir(path), requested_rtt_ms(rtt), requested_loss_pct(loss), stop(cancel) {
    require(std::isfinite(rtt) && rtt >= 0 && rtt <= 10000,
            "additional RTT must be between 0 and 10000 ms");
    require(std::isfinite(loss) && loss >= 0 && loss <= 100,
            "packet loss must be between 0 and 100 percent");
    delay_ns = std::llround(rtt * 500000.0);
    ns[0] = new_namespace(stop);
    ns[1] = new_namespace(stop);
  }

  std::array<Qdisc, 2> readback() const {
    return {snapshot(stop, ns[0].get(), delay_ns, requested_loss_pct),
            snapshot(stop, ns[1].get(), delay_ns, requested_loss_pct)};
  }

  void log(const std::string &message) const {
    std::ofstream out(dir / "network.log", std::ios::app);
    out << message << '\n';
  }

  void save() const {
    const auto partial = dir / "network.csv.partial";
    std::ofstream out(partial);
    out.exceptions(std::ios::badbit | std::ios::failbit);
    out.imbue(std::locale::classic());
    out << "direction,requested_rtt_ms,requested_loss_pct,applied_delay_ms,"
           "applied_loss_pct,observed_rtt_avg_ms,rtt_replies,sample_sent_packets,"
           "sample_dropped_packets,rtt_status,sample_counter_status\n";
    for (unsigned i = 0; i < ns.size(); ++i) {
      const auto &p = probes[i];
      const auto &q = applied[i];
      out << (i ? "server_to_client" : "client_to_server") << ','
          << number(requested_rtt_ms) << ',' << number(requested_loss_pct) << ','
          << number(q.delay_ns / 1000000.0) << ','
          << number(q.loss * 100.0 / max_probability) << ',';
      if (p.status == "available")
        out << number(p.rtt_avg_ms);
      out << ',';
      if (p.status != "probe_failed")
        out << p.replies;
      out << ',';
      if (counter_status == "available")
        out << after[i].sent - before[i].sent << ',' << after[i].drops - before[i].drops;
      else
        out << ',';
      out << ',' << p.status << ',' << counter_status << '\n';
    }
    out.close();
    std::filesystem::rename(partial, dir / "network.csv");
  }

  // Don't charge packets still queued from warm-up to the measured interval.
  // A queue that never drains is missing counter evidence, not zero drops.
  std::array<Qdisc, 2> drain() const {
    const auto deadline = Clock::now() + 200ms + std::chrono::nanoseconds(delay_ns);
    do {
      auto current = readback();
      if (!current[0].backlog_packets && !current[1].backlog_packets)
        return current;
      std::this_thread::sleep_for(10ms);
    } while (Clock::now() < deadline);
    throw std::runtime_error("veth qdisc did not drain before counter snapshot");
  }
};

Network::Network(const std::filesystem::path &case_dir, double additional_rtt_ms,
                 double loss_pct, Stop stop)
    : state_(std::make_unique<State>(case_dir, additional_rtt_ms, loss_pct, stop)) {
  auto &s = *state_;
  const int client = s.ns[0].get(), server = s.ns[1].get();
  run(stop, client, {"ip", "link", "add", "dev", device, "type", "veth", "peer", "name",
               peer_device, "netns", "/proc/self/fd/" + std::to_string(server)}, server);
  run(stop, server, {"ip", "link", "set", "dev", peer_device, "name", device});
  const std::array addresses{client_ip, server_ip};
  const std::array macs{prepare_device(stop, client), prepare_device(stop, server)};
  for (unsigned i = 0; i < s.ns.size(); ++i) {
    const int fd = s.ns[i].get();
    run(stop, fd, {"ip", "-4", "addr", "add", std::string(addresses[i]) + "/30",
                   "dev", device});
    run(stop, fd, {"tc", "qdisc", "add", "dev", device, "root", "handle", "1:", "netem",
             "limit", std::to_string(queue_limit), "delay",
             std::to_string(s.delay_ns) + "ns", "loss", "random", decimal(loss_pct) + "%"});
    run(stop, fd, {"ip", "link", "set", "dev", device, "addrgenmode", "none", "up"});
    // A private static link has no neighbor discovery workload; in particular,
    // the first ping must not measure ARP retries as if they were path RTT.
    run(stop, fd, {"ip", "-4", "neigh", "replace", addresses[1 - i], "lladdr",
                   macs[1 - i], "nud", "permanent", "dev", device});
  }
  s.applied = s.readback();
  std::ofstream log(s.dir / "network.log");
  log.exceptions(std::ios::badbit | std::ios::failbit);
  for (unsigned i = 0; i < s.ns.size(); ++i) {
    struct stat ns_info{};
    const int fd = s.ns[i].get();
    check(fstat(fd, &ns_info) == 0, "identify private network namespace");
    log << (i == 0 ? "client" : "server") << " net:[" << ns_info.st_ino
        << "], TSO/GSO/GRO disabled\n"
        << run(stop, fd, {"ip", "-d", "link", "show", "dev", device})
        << run(stop, fd, {"ip", "-4", "-o", "addr", "show", "dev", device})
        << run(stop, fd, {"ip", "-4", "neigh", "show", "dev", device});
  }
  for (unsigned i = 0; i < s.ns.size(); ++i)
    try {
      s.probes[i] = probe(stop, s.ns[i].get(), i == 0 ? server_ip : client_ip,
                          additional_rtt_ms, log);
    } catch (const std::runtime_error &e) {
      check_stop(stop);
      log << "RTT probe unavailable: " << e.what() << '\n';
    }
  log.close();
  s.save();
}

Network::~Network() = default;

void Network::enter(bool server) const {
  enter_namespace(state_->ns[server].get());
  check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "set no-new-privileges for role");
  check(prctl(PR_SET_SECUREBITS, SECBIT_NOROOT | SECBIT_NOROOT_LOCKED) == 0,
        "disable root capability grants for role");
  for (unsigned cap = 0;; ++cap) {
    const int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (present < 0 && errno == EINVAL)
      break;
    check(present >= 0, "read role capability bounding set");
    if (present)
      check(prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0,
            "drop role capability from bounding set");
  }
  __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
  __user_cap_data_struct capabilities[2]{};
  check(syscall(SYS_capset, &header, capabilities) == 0, "drop role capabilities");
}

void Network::begin_samples() {
  auto &s = *state_;
  require(s.counter_status == "not_started", "sample window already started");
  try {
    s.before = s.drain();
    s.counter_status = "incomplete";
  } catch (const std::runtime_error &e) {
    s.log(e.what());
    s.counter_status = "start_snapshot_failed";
  }
  s.save();
}

void Network::finish_samples() {
  auto &s = *state_;
  if (s.counter_status != "incomplete")
    return;
  try {
    s.after = s.drain();
    s.counter_status = "available";
    for (unsigned i = 0; i < s.ns.size(); ++i) {
      if (s.after[i].sent < s.before[i].sent || s.after[i].drops < s.before[i].drops) {
        s.counter_status = "counter_reset_or_wrap";
        s.log("netem packet counters moved backwards");
      }
    }
  } catch (const std::runtime_error &e) {
    s.log(e.what());
    s.counter_status = "end_snapshot_failed";
  }
  s.save();
}

const std::string &Network::sample_counter_status() const {
  return state_->counter_status;
}

bool Network::probes_valid() const {
  return std::all_of(state_->probes.begin(), state_->probes.end(),
                     [](const Probe &p) { return p.status != "probe_failed"; });
}

} // namespace turtle::submission
