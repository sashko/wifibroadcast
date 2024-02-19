//
// Created by consti10 on 20.12.20.
//

#ifndef WIFIBROADCAST_SCHEDULINGHELPER_H
#define WIFIBROADCAST_SCHEDULINGHELPER_H

#include <pthread.h>
#include <sys/resource.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <sstream>

namespace SchedulingHelper {

static int get_current_thread_priority(){
  int which = PRIO_PROCESS;
  id_t pid = (id_t) getpid();
  int priority = getpriority(which, pid);
  return priority;
}

static void print_current_thread_priority(const std::string& name) {
  const auto priority=get_current_thread_priority();
  std::stringstream ss;
  ss<<name<<" has priority: "<<priority;
  std::cout<<ss.str()<<std::endl;
}

// this thread should run as close to realtime as possible
static void set_thread_params_max_realtime(const std::string& tag="") {
  pthread_t target=pthread_self();
  int policy = SCHED_FIFO;
  sched_param param{};
  param.sched_priority = sched_get_priority_max(policy);
  auto result = pthread_setschedparam(target, policy, &param);
  if (result != 0) {
    std::stringstream ss;
    ss<<"Cannot setThreadParamsMaxRealtime "<<result;
    std::cerr<<ss.str()<<std::endl;
  }else{
    std::stringstream ss;
    ss<<"Changed prio ";
    if(!tag.empty()){
      ss<<"for "<<tag<<" ";
    }
    ss<<"to SCHED_FIFO:"<<param.sched_priority;
    std::cout<<ss.str()<<std::endl;
  }
}

static bool check_root() {
  const auto uid = getuid();
  const bool root = uid ? false : true;
  return root;
}

}
#endif //WIFIBROADCAST_SCHEDULINGHELPER_H
