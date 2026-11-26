#include "submission/case_rows.hpp"
#include "submission/children.hpp"
#include <algorithm>
#include <cmath>
#include <iostream>
#include <sys/stat.h>

namespace {
using namespace turtle::submission;
using std::string;

void issue_credentials(const fs::path &build, const fs::path &dir) {
  const pid_t parent = getpid();
  pid_t pid = fork();
  syscheck(pid >= 0, "start certificate issuer");
  if (!pid) {
    try {
      own_parent(parent);
      syscheck(setpgid(0,0) == 0, "isolate certificate issuer");
      syscheck(close_range(3, ~0U, 0) == 0, "close inherited descriptors");
      signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
      exec_args({(build / "runtime/turtle-issue-test-leaves.sh").string(),dir.string()});
    } catch (const std::exception &e) { std::fprintf(stderr, "%s\n", e.what()); }
    _exit(126);
  }
  // The child also calls setpgid before exec, so both sides of the fork race
  // agree on ownership. A stop never targets our caller's process group.
  setpgid(pid,pid);
  int status = 0;
  auto until = deadline();
  for (;;) {
    auto child = waitpid(pid, &status, WNOHANG);
    if (child == pid) break;
    if (child < 0 && errno != EINTR) syscheck(false, "wait for certificate issuer");
    if (interrupted || Clock::now() >= until) {
      kill(-pid, SIGKILL); kill(pid, SIGKILL);
      while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
      check_stop();
      throw std::runtime_error("certificate issuer timed out");
    }
    usleep(10000);
  }
  check_stop();
  evidence(WIFEXITED(status) && WEXITSTATUS(status) == 0, "test certificate generation failed");
}
Fields select(const string &arg, const string &all, const Fields &options) {
  if (arg == all) return options;
  evidence(std::find(options.begin(),options.end(),arg) != options.end(), "invalid selector: " + arg);
  return {arg};
}
string connection_id() {
  std::ifstream in("/proc/sys/kernel/random/uuid");
  string id;
  evidence(bool(in >> id) && id.size() == 36 && id.find_first_not_of("0123456789abcdef-") == id.npos,
           "could not allocate connection ID");
  return id;
}
std::vector<fs::path> libraries(const fs::path &build) {
  std::ifstream in(build / "expected-libs.txt");
  string prefix = fs::canonical(build / "prefix").string() + "/";
  std::vector<fs::path> paths;
  for (string s; std::getline(in,s);) {
    auto path = fs::canonical(s);
    evidence(path.string().starts_with(prefix), "link record points outside submitted prefix");
    paths.push_back(path);
  }
  evidence(in.eof() && !paths.empty(), "missing submitted library link records");
  return paths;
}

struct Run {
  fs::path build, root, credentials;
  unsigned warmups, repetitions;
  double rtt, loss;
  std::vector<fs::path> libs;
  std::ofstream cases, results;

  Run(fs::path b, fs::path r, fs::path cred, unsigned w, unsigned n, double delay, double drop)
      : build(std::move(b)), root(std::move(r)), credentials(std::move(cred)), warmups(w), repetitions(n),
        rtt(delay), loss(drop), libs(libraries(build)), cases(root / "cases.csv"), results(root / "results.csv") {
    write_row(cases,{"auth","scenario","measured_role","state","requested_samples","attempted_samples","task_successes",
                     "verified_samples","wall_samples","cycle_samples","reason","case_dir"});
    write_row(results,result_columns);
  }
  Fields args(bool server, const Case &c, const fs::path &dir) const {
    string name = server ? "server" : "client";
    return {(build / "bin" / name).string(),Network::server_ip,"4433",dir.string(),
            name == c.role ? "measured" : "peer",c.scenario,c.auth,credentials.string()};
  }
  bool run_case(const Case &c) {
    const auto path = fs::path("runs") / c.name(), dir = root / path;
    fs::create_directories(dir);
    Summary summary;
    CaseRows rows(dir);
    bool network_ok = false;
    try {
      Network link(dir,rtt,loss,&interrupted);
      RoleProcess server(link,true,args(true,c,dir),dir / "server.stderr");
      server.expect("READY",deadline());
      RoleProcess client(link,false,args(false,c,dir),dir / "client.stderr");
      client.expect("READY",deadline());
      auto attempt = [&](bool warm, unsigned i) {
        check_stop();
        string id = connection_id();
        Result row;
        bool available = true;
        try {
          auto until = deadline();
          server.send("RUN " + id); client.send("RUN " + id);
          auto s = server.read_line(until), cl = client.read_line(until);
          evidence((s == "ARMED" || s == "DONE") && (cl == "ARMED" || cl == "DONE"), "invalid preparation reply");
          bool ready = s == "ARMED" && cl == "ARMED";
          if (s == "ARMED") server.send(ready ? "GO" : "ABORT");
          if (cl == "ARMED") client.send(ready ? "GO" : "ABORT");
          if (s == "ARMED") server.expect("DONE",until);
          if (cl == "ARMED") client.expect("DONE",until);
          row = assess(c,dir,id,build,libs,client.pid(),server.pid());
        } catch (const std::exception &e) {
          row.state = "failed"; row.reason = e.what();
          available = false;
        }
        rows.append({c.auth,c.scenario,c.role,warm ? "warmup" : "sample",std::to_string(i),id,row.state,
                           row.task_success,row.wall,row.wall_status,row.cycles,row.pmu_status,row.pmu_reason,row.reason,
                           row.start,row.end,row.end_event,std::to_string(client.pid()),std::to_string(server.pid()),
                           path.string(),(path/"client.stderr").string(),(path/"server.stderr").string(),""});
        check_stop();
        if (!available) throw std::runtime_error(row.reason);
        return row.task_success == "1";
      };
      bool warmed = true;
      for (unsigned i=1; i<=warmups; ++i)
        if (!attempt(true,i)) { warmed = false; break; }
      if (warmed) {
        link.begin_samples();
        if (link.sample_counter_status() == "incomplete") {
          try {
            for (unsigned i=1; i<=repetitions; ++i) attempt(false,i);
          } catch (...) {
            if (!interrupted) {
              link.finish_samples();
              network_ok = link.sample_counter_status() == "available" && link.probes_valid();
            }
            throw;
          }
          link.finish_samples();
        }
        network_ok = link.sample_counter_status() == "available" && link.probes_valid();
        if (!network_ok) summary.issue("insufficient_evidence","network observation incomplete; see network.csv and network.log");
      }
      client.finish(); server.finish();
    } catch (const std::exception &e) {
      summary.state = "failed"; summary.reason = e.what();
    }
    rows.publish(results,summary,network_ok);
    write_row(cases,{c.auth,c.scenario,c.role,summary.state,std::to_string(repetitions),std::to_string(summary.attempted),
                     std::to_string(summary.successes),std::to_string(summary.verified),std::to_string(summary.wall),
                     std::to_string(summary.cycles),summary.reason,path.string()});
    cases.flush(); evidence(bool(cases), "could not flush case summary");
    std::cout << c.name() << ": " << summary.state;
    if (!summary.reason.empty()) std::cout << " (" << summary.reason << ')';
    std::cout << std::endl;
    check_stop();
    return summary.state == "passed";
  }
};
int run(int argc, char **argv) {
  if (argc != 11) throw std::runtime_error("internal job: expected build, output, role, scenario, auth, warmups, attempts, credentials, RTT and loss");
  const auto build = fs::canonical(argv[1]), root = fs::canonical(argv[2]);
  auto roles = select(argv[3],"both",{"client","server"}), scenarios = select(argv[4],"all",{"S0","S1","S2","S3","S4"}),
       auths = select(argv[5],"both",{"server","mtls"});
  auto warm = number<unsigned>(argv[6]), samples = number<unsigned>(argv[7]);
  auto rtt = number<double>(argv[9]), loss = number<double>(argv[10]);
  evidence(warm >= 1 && samples >= 1 && warm <= 100000 && samples <= 100000 &&
           std::isfinite(rtt) && rtt >= 0 && rtt <= 10000 && std::isfinite(loss) && loss >= 0 && loss <= 100,
           "invalid run conditions");
  fs::path credentials = argv[8];
  if (credentials.empty()) { credentials = root / "credentials"; issue_credentials(build,credentials); }
  credentials = fs::canonical(credentials);
  for (auto name : {"ca.crt","server.crt","server.key"})
    evidence(fs::is_regular_file(credentials/name),string("missing credential: ") + name);
  if (auths.size() > 1 || auths.front() == "mtls")
    for (auto name : {"client.crt","client.key"})
      evidence(fs::is_regular_file(credentials/name),string("missing mutual TLS credential: ") + name);
  const char *receipt = std::getenv("TURTLE_BUILD_ID");
  string digest = receipt ? receipt : "";
  evidence(digest.empty() || (digest.size() == 64 && digest.find_first_not_of("0123456789abcdef") == digest.npos),
           "invalid build receipt identity");
  std::ofstream info(root / "build.csv");
  write_row(info,{"build_dir","receipt_sha256","link_evidence","client_map","server_map"});
  write_row(info,{build.string(),digest,(build/"link-evidence.txt").string(),
                  (build/"client.map").string(),(build/"server.map").string()});
  info.close(); evidence(bool(info), "could not write build association");
  Run job(build,root,credentials,warm,samples,rtt,loss);
  bool ok = true;
  for (const auto &auth : auths) for (const auto &scenario : scenarios) for (const auto &role : roles)
    if (!job.run_case({auth,scenario,role})) ok = false;
  job.cases.close(); job.results.close();
  evidence(job.cases && job.results, "could not finish run CSV files");
  return ok ? 0 : 1;
}
}
int main(int argc, char **argv) {
  using namespace turtle::submission;
  umask(0077);
  struct sigaction act{}; act.sa_handler = stop; sigemptyset(&act.sa_mask);
  if (sigaction(SIGTERM,&act,nullptr) || sigaction(SIGINT,&act,nullptr) || signal(SIGPIPE,SIG_IGN) == SIG_ERR) return 1;
  try { return run(argc,argv); }
  catch (const std::exception &e) {
    std::cerr << "TURTLE: " << e.what() << '\n';
    return interrupted ? 128 + interrupted : 1;
  }
}
