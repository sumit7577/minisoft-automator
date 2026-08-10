#!/usr/bin/env python3
import sys, time

try:
    import paramiko
except ImportError:
    import subprocess
    r = subprocess.run([sys.executable, "-m", "pip", "install", "paramiko", "-q",
                        "--break-system-packages"], capture_output=True)
    if r.returncode != 0:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko", "-q"])
    import paramiko

HOST = "45.143.166.108"
PORT = 56777
USER = "root"
PASS = "3ph37xW9M1BaiUMWk7"
LOCAL_MAIN = "/Users/sumitkumar/code/personal/offspring/app/main.py"
REMOTE_MAIN = "/opt/app/app/main.py"

def stream(client, cmd):
    print(f"\n$ {cmd}")
    _, stdout, _ = client.exec_command(cmd, get_pty=True)
    while not stdout.channel.exit_status_ready():
        if stdout.channel.recv_ready():
            print(stdout.channel.recv(4096).decode("utf-8", errors="replace"), end="", flush=True)
        time.sleep(0.1)
    out = stdout.channel.recv(65535)
    if out:
        print(out.decode("utf-8", errors="replace"), end="", flush=True)
    return stdout.channel.recv_exit_status()

def main():
    print(f"Connecting to {HOST}:{PORT}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20)
        print("Connected!")
    except Exception as e:
        print(f"Connection failed: {e}")
        input("\nPress Enter to close...")
        sys.exit(1)

    # Upload the updated main.py
    print(f"\nUploading {LOCAL_MAIN} -> {REMOTE_MAIN}")
    sftp = client.open_sftp()
    sftp.put(LOCAL_MAIN, REMOTE_MAIN)
    sftp.close()
    print("Upload done.")

    # Restart the container (no rebuild needed — files are volume-mounted...
    # but they're not, so we need to restart to pick up the COPY'd file)
    stream(client, "docker restart roadtools-dashboard")
    time.sleep(3)
    stream(client, "docker logs roadtools-dashboard --tail 20")
    stream(client, "docker ps")

    client.close()
    print("\n\nDone! Check http://45.143.166.108:5000")
    input("\nPress Enter to close...")

if __name__ == "__main__":
    main()
