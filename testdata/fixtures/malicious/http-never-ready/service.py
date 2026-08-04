import signal
import time


running = True


def stop(_signum, _frame):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
print("service-alive-without-listener", flush=True)
while running:
    time.sleep(0.1)
