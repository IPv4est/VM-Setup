#!/bin/bash
# SOC Stack - Clean Start/Stop

case "$1" in
  start)
    echo "--- Powering UP SOC Stack ---"
    
    # Ensure Logstash can read its secrets
    sudo chown logstash:logstash /etc/logstash/logstash.keystore 2>/dev/null
    sudo chmod 600 /etc/logstash/logstash.keystore 2>/dev/null

    echo "[1/3] Starting Elasticsearch..."
    sudo systemctl start elasticsearch
    
    # Smart wait: Only proceeds when the API is actually listening
    echo -n "[...] Waiting for Database"
    until curl -k -s https://localhost:9200 > /dev/null; do
      echo -n "."
      sleep 2
    done
    echo -e "\n[+] Elasticsearch is ONLINE"

    echo "[2/3] Starting Kibana..."
    sudo systemctl start kibana

    echo "[3/3] Starting Logstash..."
    sudo systemctl start logstash
    
    echo "--- Stack is UP and Healthy ---"
    ;;

  stop)
    echo "--- Powering DOWN SOC Stack ---"
    # Stop in REVERSE order: protects the database from abrupt disconnects
    echo "[1/3] Stopping Logstash..."
    sudo systemctl stop logstash
    
    echo "[2/3] Stopping Kibana..."
    sudo systemctl stop kibana
    
    echo "[3/3] Stopping Elasticsearch..."
    sudo systemctl stop elasticsearch
    
    echo "--- Stack is DOWN Cleanly ---"
    ;;

  status)
    for s in elasticsearch kibana logstash; do
       echo "$s: $(systemctl is-active $s)"
    done
    ;;

  *)
    echo "Usage: $0 {start|stop|status}"
    exit 1
    ;;
esac
