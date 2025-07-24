#  Networking & TLS
import socket
import ssl

#  Time & Date
import datetime
from datetime import timezone # type: ignore

#  Platform & Identity
import uuid
import platform
import hashlib

#  WHOIS Intelligence
from ipwhois import IPWhois

#   Verdict

try:
    from NXTP_core.verdict_engine import assess_verdict
except ModuleNotFoundError:
    import sys
    import os
    # Try parent/NXTP_core
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'NXTP_core')))
    try:
        from verdict_engine import assess_verdict
    except ModuleNotFoundError:
        # Try parent directory (if verdict_engine.py is there)
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
        try:
            from verdict_engine import assess_verdict
        except ModuleNotFoundError:
            print("ERROR: Could not import 'assess_verdict' from any known location.")
            print("Make sure 'verdict_engine.py' exists in 'NXTP_core' or the parent directory.")
            sys.exit(1)

import json
import os

# Service has generator

def evaluate_risk(ip, tls_info, whois_info):
    trust_score = 100
    reasons = []

    if 'Error' in whois_info:
        trust_score -= 15
        reasons.append("WHOIS/ASN lookup failed")

    if whois_info.get('Country') in {'RU', 'KP', 'IL'}:
        trust_score -= 15
        reasons.append(f"Volatile region {whois_info['Country']}")

   
    rdns_name = resolve_rdns(ip)
    if not rdns_name:
        trust_score -= 10
        reasons.append("No reverse DNS")
    elif any(x in rdns_name for x in ("cloudflare", "amazonaws", "azure")):
        trust_score -= 5
        reasons.append(f"Cloud-hosted node detected via RDNS: {rdns_name}")

    trust_score = max(trust_score, 0)
    risk_score = 100 - trust_score

    return trust_score, reasons, risk_score

def generate_service_hash(hostname, asn, ports):
    raw = f"{hostname}-{asn}-{sorted(ports)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]

def log_session_to_json(packet, verdict_data, log_path="nxtp_log.json"):
    session_entry = {
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "target": packet.get("node_id", "unkown"),
        "ip_address": packet.get("ip", "unkown"),
        "tls": packet.get("tls_summary", {}),
        "asn": packet.get("asn", "unknown"),
        "declared_ports": packet.get("declared_ports", []),
        "service_hash": packet.get("service_hash", ""),
        "intent_tag": packet.get("intent_tag", ""),
        "os_fingerprint": packet.get("os_hint", ""),
        "trust_score": verdict_data.get("trust_score", 0),
        "risk_score": verdict_data.get("risk_score", 0),
        "trust_level": verdict_data.get("trust_level", ""),
        "verdict": verdict_data.get("verdict", ""),
        "advisory_flags": verdict_data.get("reasons", [])
    }
    
    if not os.path.exists(log_path):
        with open(log_path, "w") as f:
            json.dump([session_entry], f, indent=4)
    else:
        with open(log_path, "r+") as f:
            logs = json.load(f)
            logs.append(session_entry)
            f.seek(0)
            json.dump(logs, f, indent=4)



def fetch_tlscertificate(target, port=443):
    context = ssl.create_default_context()
    cert_data = {}

    try:
        with socket.create_connection((target, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

                cert_data['Issued To'] = dict(x[0] for x in cert ['subject']).get('commonName', 'N/A')
                cert_data['Issuer'] = dict(x[0] for x in cert['issuer']).get('commonName', 'N/A')
                cert_data['Valid Until'] = cert['notAfter']

                expires = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                cert_data['Days Left'] = (expires - datetime.datetime.now(timezone.utc)).days              
    except Exception as e:
        cert_data['Error'] = f"TLS fetch failed: {e}"

    return cert_data

def fetch_whois_asn(ip):
    result = {}
    try:
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap()
        result['ASN'] = rdap.get('asn')
        result['Org'] = rdap.get('network', {}).get('name')
        result['Country'] = rdap.get('network', {}).get('country')
    except Exception as e:
        result['Error'] = f"WHOIS/ASN fetch failed: {e}"
    return result


def scan_ports(ip, ports, timeout=1):
    open_ports = []

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except:
            pass #port is closed, filtered, or blocked
    
    return open_ports

def build_greet_packet(target, declared_ports, tls_info, whois_info):
    service_hash = generate_service_hash(target, whois_info.get('ASN', 'Unknown'), declared_ports)
    ip_address = socket.gethostbyname(target)
    return {
        "type": "NXTP_INITIAL_GREET",
        "version": "NXTP/1.0",
        "node_id": uuid.uuid4().hex[:12],
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "declared_ports": declared_ports,
        "service_hash": service_hash,
        "tls_summary": {
            "issued_to": tls_info.get('Issued To',  'N/A'),
            "issuer": tls_info.get('Issuer', 'N/A'),
            "days_left": tls_info.get('Days Left', -1)
        },
        "asn": whois_info.get('ASN', 'Unknown'),
        "os_hint": platform.system() + "-" + platform.release(),
        "intent_tag": "https-web=service"
    }



def main():
    target = input("Enter domain name or IP to evaluate: ").strip()
    ip = socket.gethostbyname(target)
    
    tls_info = fetch_tlscertificate(target)
    whois_info = fetch_whois_asn(ip)

    trust_score, flags, risk_score = evaluate_risk(ip, tls_info, whois_info)
    flags_list = [f.upper().replace(" ", "_") for f in flags]

    hostname = resolve_rdns(ip)
    if not hostname:
        hostname = "unresolved"
        flags_list.append("NO_REVERSE_DNS")
    elif any(c in hostname for c in ["amazonaws", "cloudflare", "digitalocean"]):
        flags_list.append("CLOUD_RDNS")

    if not whois_info.get("Org"):
        flags_list.append("ANONYMOUS_ASN")

    country = whois_info.get("Country")
    if country and country in {"RU", "KP", "IR"}:
        flags_list.append(f"GEO_RISK_ZONE_{country}")

    verdict_data = assess_verdict(
        flags_list,
        whois_info.get("ASN", ""),
        hostname,
        whois_info.get("Org", "")
    )

    greet_packet = build_greet_packet(target, [443], tls_info, whois_info)
    print("="*20, "NXTP INTIAL GREET", "="*20)
    print(f"Node ID        : {greet_packet['node_id']}")
    print(f"Timestamp      : {greet_packet['timestamp']}")
    print(f"OS Fingerprint : {greet_packet['os_hint']}")
    print(f"Intent Tag     : {greet_packet['intent_tag']}")
    print(f"Service Hash   : {greet_packet['service_hash']}")
    print()
    print(f"Declared Ports : {greet_packet['declared_ports']}")
    print(f"ASN            : {greet_packet['asn']}")
    print("--- TLS Summary ---")
    tls = greet_packet['tls_summary']
    print(f"   Issued To   : {tls.get('issued_to')}")
    print(f"   Issuer      : {tls.get('issuer')}")
    print(f"   Days Left   : {tls.get('days_left')}")
    print("="*22, "Verdict", "="*22)
    print(f"Verdict        : {verdict_data['verdict']}")
    print(f"Score          : {verdict_data.get('score', verdict_data.get('risk_score', 0))}")
    reasons = verdict_data.get('reasons', [])
    print(f"Reasons        : {', '.join(reasons) if reasons else 'None'}")
    print("="*54)
    
    
    declared = greet_packet["declared_ports"]
    additional = [21, 22, 23, 25, 53, 80, 110, 137, 138, 139, 445, 3306, 8080]
    scan_targets = sorted(set(declared + additional))
    observed = scan_ports(ip, scan_targets)

    unexpected = [p for p in observed if p not in declared]
    missing = [p for p in declared if p not in observed]

    print("\n Port Compliance Check")
    print(f"Declared Ports   : {declared}")
    print(f"Observed Open    : {observed}")
    print(f"Unexpected Ports : {unexpected if unexpected else 'None'}")
    print(f"Missing Declared : {missing if missing else 'None'}")

    port_flags = []
    if unexpected:
        port_flags.append("UNDECLARED_PORT_EXPOSURE")
    if missing:
        port_flags.append("DECLARED_PORT_INACTIVE")

    # Log session
    log_session_to_json(
        greet_packet,
        build_response_packet(
            greet_packet["node_id"],
            trust_score,
            risk_score,
            verdict_data
        )
    )
    # End of log_session_to_json call

    # Broadcast if hostile
    if verdict_data["verdict"] == "HOSTILE":
        broadcast_flagged_host(
            ip=ip,
            asn=whois_info.get("ASN", "unknown"),
            verdict=verdict_data["verdict"],
            reason=verdict_data["reasons"][0] if verdict_data["reasons"] else "Unknown threat"
        )
        print("ALERT: HOSTILE verdict broadcasted to intel_queue.json")

def resolve_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

if __name__ == "__main__":
    main()



def build_response_packet(node_id, trust_score, risk_score, verdict_data):
    return {
        "node_id": node_id,
        "trust_score": trust_score,
        "risk_score": risk_score,
        "trust_level": verdict_data.get("trust_level", ""),
        "verdict": verdict_data.get("verdict", ""),
        "reasons": verdict_data.get("reasons", [])
    }

def broadcast_flagged_host(ip, asn, verdict, reason, queue_path="intel_queue.json"):
    entry = {
        "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "asn": asn,
        "verdict": verdict,
        "reason": reason
    }
    if not os.path.exists(queue_path):
        with open(queue_path, "w") as f:
            json.dump([entry], f, indent=4)
    else:
        with open(queue_path, "r+") as f:
            try:
                signals = json.load(f)
            except Exception:
                signals = []
            signals.append(entry)
            f.seek(0)
            f.truncate()
            json.dump(signals, f, indent=4)

def intel_scoreboost(ip, queue_path="intel_queue.json"):
    if not os.path.exists(queue_path):
        return 0
    
    with open(queue_path, "r") as f:
        try:
            signals = json.load(f)
        except json.JSONDecodeError:
            return 0 # avoids crashing if file is corrupted
        
    appearances = sum(1 for signal in signals if signal.get("ip") == ip)
    return appearances * 5  # 5 points added for prior sighting


 
def prune_expired_signals(queue_path="intel_queue.json"):
    if not os.path.exists(queue_path):
        return

    verdict_ttl = {
        "HOSTILE": 168,     # 7 days
        "SUSPICIOUS": 72,   # 3 days
        "TRUSTED": 24       # 1 day
    }

    try:
        with open(queue_path, "r+") as f:
            now = datetime.datetime.now(timezone.utc)
            signals = json.load(f)

            fresh = []
            for signal in signals:
                try:
                    ts = datetime.datetime.fromisoformat(signal["timestamp"])
                    verdict = signal.get("verdict", "SUSPICIOUS")  # fallback
                    ttl_hours = verdict_ttl.get(verdict.upper(), 48)

                    if (now - ts).total_seconds() <= ttl_hours * 3600:
                        fresh.append(signal)
                except Exception:
                    continue

            f.seek(0)
            f.truncate()
            
            json.dump(fresh, f, indent=4)
    except json.JSONDecodeError:
        pass  # optional: log or wipe if corrupted













