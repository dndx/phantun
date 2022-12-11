#!/bin/sh

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

_get_default6_iface() {
  ip -6 route show default | awk -F 'dev' '{print $2}' | awk '{print $1}'
}

_get_addr_by_iface() {
  ip -4 addr show dev "$1" | grep -w "inet" | awk '{print $2}' | awk -F '/' '{print $1}' | head -1
}

_get_addr6_by_iface() {
  ip -6 addr show dev "$1" | grep -w "inet6" | awk '{print $2}' | awk -F '/' '{print $1}' | head -1
}

_check_rule_by_comment() {
  iptables-save | grep -q "$1"
}

_check_rule6_by_comment() {
  ip6tables-save | grep -q "$1"
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

_get_peer6_from_args() {
  local peer=$(echo "$@" | awk -F '--tun-peer6' '{print $2}' | awk '{print $1}')
  _is_server_mode "$1" && echo ${peer:=fcc9::2} || echo ${peer:=fcc8::2}
}

_get_port_from_args() {
  local value=$(echo "$@" | awk -F '-l|--local' '{print $2}' | awk '{print $1}')
  _is_server_mode "$1" && echo $value || echo $value | awk -F ':' '{print $2}'
}

_stop_process() {
  kill $(pidof phantun-server phantun-client)
  info "terminate phantun process."
}

_revoke_iptables() {
  local tun=$(_get_tun_from_args "$@")
  local port=$(_get_port_from_args "$@")
  local comment="phantun_${tun}_${port}"
  iptables-save | grep -v "${comment}" | iptables-restore -w 10
  info "remove iptables rule: [${comment}]"
}

_revoke_ip6tables() {
  ! _is_ipv4_only "$@" || return
  local tun=$(_get_tun_from_args "$@")
  local port=$(_get_port_from_args "$@")
  local comment="phantun_${tun}_${port}"
  ip6tables-save | grep -v "${comment}" | ip6tables-restore -w 10
  info "remove ip6tables rule: [${comment}]"
}

apply_sysctl() {
  info "apply sysctl: $(sysctl -w net.ipv4.ip_forward=1)"
  ! _is_ipv4_only "$@" || return
  info "apply sysctl: $(sysctl -w net.ipv6.conf.all.forwarding=1)"
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
    iptables -w 10 -A FORWARD -i $tun -j ACCEPT -m comment --comment "${comment}"
    iptables -w 10 -A FORWARD -o $tun -j ACCEPT -m comment --comment "${comment}"
    if _is_server_mode "$1"; then
      info "add iptables DNAT rule: [${comment}]: ${interface} -> ${tun}, ${address} -> ${peer}"
      iptables -w 10 -t nat -A PREROUTING -p tcp -i $interface --dport $port -j DNAT --to-destination $peer \
        -m comment --comment "${comment}" || error "iptables DNAT rule add failed."
    else
      info "add iptables SNAT rule: [${comment}]: ${tun} -> ${interface}, ${peer} -> ${address}"
      iptables -w 10 -t nat -A POSTROUTING -s $peer -o $interface -j SNAT --to-source $address \
        -m comment --comment "${comment}" || error "iptables SNAT rule add failed."
    fi
  fi
}

apply_ip6tables() {
  ! _is_ipv4_only "$@" || return

  local interface=$(_get_default6_iface)
  local address=$(_get_addr6_by_iface "${interface}")
  local tun=$(_get_tun_from_args "$@")
  local peer=$(_get_peer6_from_args "$@")
  local port=$(_get_port_from_args "$@")
  local comment="phantun_${tun}_${port}"

  if _check_rule6_by_comment "${comment}"; then
    warn "ip6tables rule already exist, maybe needs to check."
  else
    ip6tables -w 10 -A FORWARD -i $tun -j ACCEPT -m comment --comment "${comment}"
    ip6tables -w 10 -A FORWARD -o $tun -j ACCEPT -m comment --comment "${comment}"
    if _is_server_mode "$1"; then
      info "add ip6tables DNAT rule: [${comment}]: ${interface} -> ${tun}, ${address} -> ${peer}"
      ip6tables -w 10 -t nat -A PREROUTING -p tcp -i $interface --dport $port -j DNAT --to-destination $peer \
        -m comment --comment "${comment}" || error "ip6tables DNAT rule add failed."
    else
      info "add ip6tables SNAT rule: [${comment}]: ${tun} -> ${interface}, ${peer} -> ${address}"
      ip6tables -w 10 -t nat -A POSTROUTING -s $peer -o $interface -j SNAT --to-source $address \
        -m comment --comment "${comment}" || error "ip6tables SNAT rule add failed."
    fi
  fi
}

graceful_stop() {
  warn "caught SIGTERM or SIGINT signal, graceful stopping..."
  _stop_process
  _revoke_iptables "$@"
  _revoke_ip6tables "$@"
}

start_phantun() {
  trap 'graceful_stop "$@"' SIGTERM SIGINT
  apply_sysctl "$@"
  apply_iptables "$@"
  apply_ip6tables "$@"
  "$@" &
  wait
}

start_phantun "$@"
