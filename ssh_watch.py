import json

with open("ssh-events.jsonl", encoding="utf-8") as logs:
    accept_log = 0
    fail_log = 0
    failed_by_user_ip = {}
    for line in logs:
        events = json.loads(line)
        log = events["MESSAGE"]
        if 'Accepted' in events["MESSAGE"]:
            accept_log += 1
            list1 = events["MESSAGE"].split()
            user, ip = list1[3], list1[5]
            key = (user, ip)
            failed_by_user_ip[key] = failed_by_user_ip.get(key, 0)
            time = events["SYSLOG_TIMESTAMP"]
            if failed_by_user_ip[key] > 1:
                print("[ALERT] Successful SSH login after", failed_by_user_ip[key], "failed attempts")
            else:
                print("[INFO] Successful SSH login after", failed_by_user_ip[key], "failed attempts")
            print("Time:", time)
            print("User", user)
            print("From IP:", ip)
        if 'Failed' in events["MESSAGE"]:
            fail_log += 1
            list1 = events["MESSAGE"].split()
            user, ip = list1[3], list1[5]
            key = (user, ip)
            failed_by_user_ip[key] = failed_by_user_ip.get(key, 0) + 1
            time = events["SYSLOG_TIMESTAMP"]
            if failed_by_user_ip[key] > 1:
                print("[ALERT] Unsuccessful SSH login")
            else:
                print("[INFO] Unsuccessful SSH login")
            print("Time:", time)
            print("User", user)
            print("From IP", ip)

