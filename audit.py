"""ПР. Аудит учётных записей и прав доступа."""

import sys
from datetime import date

from iam import effective_permissions, new_hires
from store import compare, load_json, read_csv, today


def enabled(account):
    """Учётная запись включена, если поле disabled_at пустое."""
    return account["disabled_at"] == ""


def active_accounts(employees, accounts):
    """Пары (учётная запись, сотрудник) для включённых учётных записей
    сотрудников со статусом active. Используйте в заданиях 4.3-4.5."""
    active = {e["emp_id"]: e for e in employees if e["status"] == "active"}
    return [
        (a, active[a["emp_id"]])
        for a in accounts
        if enabled(a) and a["emp_id"] in active
    ]


def fired_enabled(employees, accounts):
    """Пример готовой проверки: включённые учётные записи уволенных сотрудников."""
    fired = {e["emp_id"] for e in employees if e["status"] == "fired"}
    return [a["login"] for a in accounts if enabled(a) and a["emp_id"] in fired]


def orphans(employees, accounts):
    """Задание 4.2. Логины включённых учётных записей без сотрудника в hr.csv."""
    all_emp_ids = {e["emp_id"] for e in employees}
    return [
        a["login"] for a in accounts
        if enabled(a) and (not a["emp_id"] or a["emp_id"] not in all_emp_ids)
    ]


def inactive(employees, accounts, today_, days):
    """Задание 4.3. Логины из active_accounts(), не входившие БОЛЬШЕ days дней."""
    res = []
    for acc, _ in active_accounts(employees, accounts):
        if acc["last_login"]:
            last = date.fromisoformat(acc["last_login"])
            if (today_ - last).days > days:
                res.append(acc["login"])
    return res


def excess_rights(employees, accounts, grants, roles):
    """Задание 4.4. Список пар (login, permission) сверх ролевой модели."""
    user_pos = {
        acc["login"]: emp["position"]
        for acc, emp in active_accounts(employees, accounts)
    }
    res = []
    for g in grants:
        lg = g["login"]
        if lg in user_pos:
            allowed = set(effective_permissions(user_pos[lg], roles))
            if g["permission"] not in allowed:
                res.append((lg, g["permission"]))
    return res


def sod_conflicts(employees, accounts, grants, roles):
    """Задание 4.5. Список троек (login, право1, право2) конфликтов SoD."""
    active_logins = {acc["login"] for acc, _ in active_accounts(employees, accounts)}
    user_perms = {lg: set() for lg in active_logins}
    for g in grants:
        if g["login"] in user_perms:
            user_perms[g["login"]].add(g["permission"])

    res = []
    for lg in sorted(active_logins):
        perms = user_perms[lg]
        for p1, p2 in roles["sod_conflicts"]:
            if p1 in perms and p2 in perms:
                res.append((lg, p1, p2))
    return res


def run_audit():
    cfg, roles = load_json("config.json"), load_json("roles.json")
    emp, acc, gr = read_csv("hr.csv"), read_csv("accounts.csv"), read_csv("grants.csv")
    days = cfg["inactive_days"]
    return {
        "Новые сотрудники без учётной записи": len(new_hires(emp, acc)),
        "Уволенные с активной учётной записью": len(fired_enabled(emp, acc)),
        "Учётные записи без сотрудника": len(orphans(emp, acc)),
        f"Неактивные более {days} дней": len(inactive(emp, acc, today(), days)),
        "Лишние права (пар логин-право)": len(excess_rights(emp, acc, gr, roles)),
        "Сотрудники с конфликтом SoD": len(
            {c[0] for c in sod_conflicts(emp, acc, gr, roles)}
        ),
    }


if __name__ == "__main__":
    compare(run_audit(), after_fix="--after-fix" in sys.argv)