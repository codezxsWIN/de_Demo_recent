import threading

from .servers import ENVIRONMENTS, start

with start():
    print("Local network environments: http://127.0.0.1:8800/", flush=True)
    for item in ENVIRONMENTS:
        print(f"{item['name']}: TCP/{item['port']}; comparison TCP/{item['control']}", flush=True)
    print("Loopback only. Fictional data. No OS/vendor/CVE claims. Ctrl+C to stop.", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
