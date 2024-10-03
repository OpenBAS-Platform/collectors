import time

from collector import OpenBASCrowdStrike

if __name__ == "__main__":
    try:
        collector = OpenBASCrowdStrike()
        collector.start()
    except Exception as err:
        print(err)
        time.sleep(10)
        exit(0)
