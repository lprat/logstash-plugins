#!/bin/bash
#contact: lionel.prat9@gmail.com
#check env $GIT_UPDATE_LOGSTASH_FIR == PATH for define if update configuration logstash by GIT (PATH == path of git clone)
#get GIT information $GIT_UPDATE_LOGSTASH_FIR_URL
#valid path not empty
GIT_UPDATE_LOGSTASH_FIR="/opt/logstash-instance-x"
GIT_UPDATE_LOGSTASH_FIR_URL=https://mylocal.git/logstash-conf_instance-1.git
if [ -n "$GIT_UPDATE_LOGSTASH_FIR" ]; then
  #valid path
  if [[ "$GIT_UPDATE_LOGSTASH_FIR" =~ ^(/[^/ ]*)+/?$ ]]; then
    #first time
    if [ ! -f "$GIT_UPDATE_LOGSTASH_FIR/.git" ]; then
      if [ ! -d "$GIT_UPDATE_LOGSTASH_FIR" ]; then
        mkdir -p $GIT_UPDATE_LOGSTASH_FIR
      fi
      if [ -n "$GIT_UPDATE_LOGSTASH_FIR_URL" ]; then
        git clone $GIT_UPDATE_LOGSTASH_FIR_URL $GIT_UPDATE_LOGSTASH_FIR
      else
        exit -1
      fi
    fi
    #else time
    if [ -d "$GIT_UPDATE_LOGSTASH_FIR/.git" ]; then
      cd $GIT_UPDATE_LOGSTASH_FIR && git pull
    fi
  fi
fi
