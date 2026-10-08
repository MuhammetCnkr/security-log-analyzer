from datetime import datetime

def main():
    detect_suspicius_ip()





def detect_suspicius_ip():
    logs = read_logs_from_file()
    ip_by_time = {}
    for log in logs:
        current_ip = log["ip"]
        current_time = log["time"]
        if current_ip not in ip_by_time.keys():
            ip_by_time[current_ip] = []
        ip_by_time[current_ip].append(current_time)


    silinecek_ips = []
    for i,j in ip_by_time.items():
        if len(j) < 5:
            silinecek_ips.append(i)
    for i in silinecek_ips:
        silinen = ip_by_time.pop(i)

    suspicious_list = []
    for one_ip in ip_by_time:
        length = len(ip_by_time[one_ip])
        for second_counter in range(4,length):
            first_counter = second_counter - 4
            zaman_str1 = ip_by_time[one_ip][first_counter]
            zaman_str2 = ip_by_time[one_ip][second_counter]
            format_sablonu = "%Y-%m-%d %H:%M:%S"
            t1 = datetime.strptime(zaman_str1, format_sablonu)
            t2 = datetime.strptime(zaman_str2, format_sablonu)
            fark = t2 - t1
            saniye_farki = fark.total_seconds()

            if saniye_farki <= 30:
                suspicious_list.append(one_ip)
                break

    print("Brute Force Şüphelileri : ",", ".join(suspicious_list))

def show_username():
    entered_username = input("Enter username: ")
    logs = read_logs_from_file()

    failed_logins = 0
    successful_logins = 0

    for log in logs:
        if log["user"] == entered_username:
            if log["event"] == "LOGIN_FAILED":
                failed_logins += 1
            else:
                successful_logins += 1

    total_attempts = failed_logins + successful_logins

    print(f"""
    Username Analysis
    ------------------------------
    Total attempts:       {total_attempts}
    Successful logins:    {successful_logins}
    Failed logins:        {failed_logins}
    """)

def show_ip():

    entered_ip = input("Enter IP: ")
    logs = read_logs_from_file()

    failed_logins = 0
    successful_logins = 0
    ips_usernames = []

    for log in logs:
        if log["ip"] == entered_ip:
            if log["user"] not in ips_usernames:
                ips_usernames.append(log["user"])
            if log["event"] == "LOGIN_FAILED":
                failed_logins += 1
            else:
                successful_logins += 1

    total_attempts = failed_logins + successful_logins
    unique_usernames = len(ips_usernames)

    print(f"""
    IP Analysis
    ------------------------------
    Total attempts:       {total_attempts}
    Successful logins:    {successful_logins}
    Failed logins:        {failed_logins}
    Unique usernames:     {unique_usernames}
    """)

def show_log():
    logs = read_logs_from_file()
    for log in logs:
        for item_log in log.values():
            print(item_log, end=" | ")
        print()

def read_logs_from_file():
    logs = []
    with open("./sample_logs/security.log", "r") as file:
        for content in file:
            item = content.split(" | ")
            logs_dict = {}
            logs_dict["time"] = item[0]
            logs_dict["ip"] = item[1]
            logs_dict["event"] = item[2]
            logs_dict["user"] = item[3][:-1]
            logs.append(logs_dict)
    return logs

def select_option():
    while True:
        try:
            user_choice = int(input("""
            =================================
            1. Load log file
            2. Show all logs
            3. Search by IP
            4. Search by username
            5. Show statistics
            6. Detect suspicious IPs
            7. Generate report
            8. Exit
            =================================

            Select an option: """))
        except ValueError as err:
            print(f"Please Enter valid input: {err}")
        else:
            if user_choice in list(range(1,9)):
                return user_choice
            print("Please Enter number in valid range")

main()
