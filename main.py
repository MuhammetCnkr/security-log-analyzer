

log_list = []
with open("./sample_logs/security.log", "r") as file:
    for content in file:
        item_content = content.split(" | ")
        log_dict = {}
        log_dict["time"] = item_content[0]
        log_dict["ip"] = item_content[1]
        log_dict["event"] = item_content[2]
        log_dict["user"] = item_content[3][:-1]
        log_list.append(log_dict)

