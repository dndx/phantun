#!/bin/sh

#
# TODO: add ipv6 support
#

info() {
  local green='\e[0;32m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${green}[${time}] [INFO]: ${clear}%s\n" "$*"
}

warn() {
  local yellow='\e[1;33m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${yellow}[${time}] [WARN]: ${clear}%s\n" "$*" >&2
}

error() {
  local red='\e[0;31m'
  local clear='\e[0m'
  local time=$(date '+%Y-%m-%d %T')
  printf "${red}[${time}] [ERROR]: ${clear}%s\n" "$*" >&2
}

_get_default_iface() {
  ip -4 route show default | awk -F 'dev' '{print $2}' | awk '{print $1}'
}

_get_addr_by_iface() {
  ip -4 addr show dev "$1" | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | head -1
}

#_get_peer_by_iface() {
#  ip -4 addr show dev "$1" | grep -w "inet" | awk '{print $4}' | awk -F '/' '{print $1}' | head -1
#}

_check_rule_by_comment() {
  iptables-save | grep -q "$1"
}

_is_server_mode() {
  [ "$1" = "phantun-server" ]
}

_is_ipv4_only() {
  case "$@" in
    *-4*|*--ipv4-only*)
      return 0
      ;;
    *\ -4*|*\ --ipv4-only*)
      return 0
      ;;
  esac
  return 1
}

_get_tun_from_args() {
  local tun=$(echo "$@" | awk -F '--tun' '{print $2}' | awk '{print $1}')
  echo ${tun:=tun0}
}

_get_peer_from_args() {
  local peer=$(echo "$@" | awk -F '--tun-peer' '{print $2}' | awk '{print $1}')
  _is_server_mode "$1" && echo ${peer:=192.168.201.2} || echo ${peer:=192.168.200.2}
}

_get_port_from_args() {
  echo "$@" | awk -F '-l|--local' '{print $2}' | awk '{print $1}'
}

_stop_process() {
  kill $(pidof phantun-server phantun-client)
  info "terminate phantun process."
}

_revoke_iptables() {
  local tun=$(_get_tun_from_args "$@")
  local port=$(_get_port_from_args "$@")
  local comment="phantun_${tun}_${port}"
  iptables-save | grep -v "${comment}" | iptables-restore
  info "remove iptables rule: [${comment}]."
}

apply_sysctl() {
  info "apply sysctl: $(sysctl -w net.ipv4.ip_forward=1)"
  _is_ipv4_only "$@" || info "apply sysctl: $(sysctl -w net.ipv6.conf.all.forwarding=1)"
}

apply_iptables() {
  local interface=$(_get_default_iface)
  local address=$(_get_addr_by_iface "${interface}")
  local tun=$(_get_tun_from_args "$@")
  local peer=$(_get_peer_from_args "$@")
  local port=$(_get_port_from_args "$@")
  local comment="phantun_${tun}_${port}"

  if _check_rule_by_comment "${comment}"; then
    warn "iptables rule already exist, maybe needs to check."
  else
    iptables -A FORWARD -i $tun -j ACCEPT -m comment --comment "${comment}"
    iptables -A FORWARD -o $tun -j ACCEPT -m comment --comment "${comment}"
    if _is_server_mode "$1"; then
      info "add iptables DNAT rule: [${comment}]: ${interface} -> ${tun}, ${address} -> ${peer}"
      iptables -t nat -A PREROUTING -p tcp -i $interface --dport $port -j DNAT --to-destination $peer \
        -m comment --comment "${comment}" || error "iptables DNAT rule add failed."
    else
      info "add iptables SNAT rule: [${comment}]: ${tun} -> ${interface}, ${peer} -> ${address}"
      iptables -t nat -A POSTROUTING -s $peer -o $interface -j SNAT --to-source $address \
        -m comment --comment "${comment}" || error "iptables SNAT rule add failed."
    fi
  fi
}

graceful_stop() {
  warn "caught SIGTERM or SIGINT signal, graceful stopping..."
  _stop_process
  _revoke_iptables "$@"
}

start_phantun() {
  trap 'graceful_stop "$@"' SIGTERM SIGINT
  apply_sysctl "$@"
  apply_iptables "$@"
  "$@" &
  wait
}

start_phantun "$@"
