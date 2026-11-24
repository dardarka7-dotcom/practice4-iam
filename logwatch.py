"""ПР. Анализ журнала входов auth_log.csv."""

from datetime import datetime, timedelta

from store import FMT, compare, load_json, read_csv


def bruteforce(log, attempts, minutes):
    """Задание 6.1. Отсортированный список IP-адресов с подбором пароля."""
    fails_by_ip = {}
    for row in log:
        if row["result"] == "fail":
            dt = datetime.strptime(row["time"], FMT)
            fails_by_ip.setdefault(row["ip"], []).append(dt)

    suspects = []
    window = timedelta(minutes=minutes)
    for ip, times in fails_by_ip.items():
        times.sort()
        for i in range(len(times) - attempts + 1):
            if times[i + attempts - 1] - times[i] <= window:
                suspects.append(ip)
                break
    return sorted(suspects)


def off_hours(log, start, end):
    """Задание 6.2. Успешные входы в нерабочее время."""
    res = []
    for row in log:
        if row["result"] == "success":
            dt = datetime.strptime(row["time"], FMT)
            if dt.hour < start or dt.hour >= end:
                res.append(row)
    return res


def disabled_logins(log, accounts):
    """Задание 6.3. Успешные входы в отключённые учётные записи."""
    disabled_map = {
        a["login"]: a["disabled_at"]
        for a in accounts
        if a["disabled_at"] != ""
    }
    res = []
    for row in log:
        if row["result"] == "success" and row["login"] in disabled_map:
            login_date = row["time"].split()[0]
            if login_date >= disabled_map[row["login"]]:
                res.append(row)
    return res


if __name__ == "__main__":
    cfg, log, acc = (
        load_json("config.json"),
        read_csv("auth_log.csv"),
        read_csv("accounts.csv"),
    )
    bf = cfg["bruteforce"]
    compare(
        {
            "IP-адреса с подбором пароля": len(
                bruteforce(log, bf["attempts"], bf["minutes"])
            ),
            "Входы в нерабочее время": len(off_hours(log, *cfg["work_hours"])),
            "Входы в отключённые учётные записи": len(disabled_logins(log, acc)),
        }
    )