"""ПР. Учётные записи: логины, пароли, ролевая модель."""

import csv
import secrets
import string

from store import load_json, log_action, read_csv, today, write_csv

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "kh", "ц": "ts",
    "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
    "я": "ya", "ә": "a", "ғ": "g", "қ": "k", "ң": "n", "ө": "o", "ұ": "u", "ү": "u",
    "һ": "h", "і": "i",
}
COMMON_PASSWORDS = {
    "password", "qwerty", "123456", "12345678", "admin",
    "welcome", "p@ssw0rd", "qwerty123", "iloveyou", "1q2w3e4r",
}


def translit(text):
    """Задание 1. Переводит текст в латиницу по таблице TRANSLIT."""
    res = []
    for ch in text.lower():
        if ch in TRANSLIT:
            res.append(TRANSLIT[ch])
        elif ("a" <= ch <= "z") or ("0" <= ch <= "9"):
            res.append(ch)
    return "".join(res)


def make_login(fullname, existing):
    """Задание 1. Логин = транслит первой буквы имени + "." + транслит фамилии."""
    parts = fullname.strip().split()
    surname = translit(parts[0])
    first_letter = translit(parts[1][0])
    base = f"{first_letter}.{surname}"

    if base not in existing:
        return base

    num = 2
    while f"{base}{num}" in existing:
        num += 1
    return f"{base}{num}"


def new_hires(employees, accounts):
    """Задание 1. Сотрудники со статусом active, у которых нет учётной записи."""
    existing_ids = {a["emp_id"] for a in accounts if a["emp_id"]}
    return [
        e for e in employees
        if e["status"] == "active" and e["emp_id"] not in existing_ids
    ]


def check_password(password, login, policy):
    """Задание 2. Возвращает список кодов нарушений."""
    errors = []

    if len(password) < policy["min_length"]:
        errors.append("LENGTH")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_other = any(not c.isalnum() for c in password)
    classes = sum([has_lower, has_upper, has_digit, has_other])
    if classes < policy["min_classes"]:
        errors.append("CLASSES")

    if "." in login:
        surname_part = login.split(".", 1)[1].rstrip("0123456789")
        if len(surname_part) >= 3 and surname_part.lower() in password.lower():
            errors.append("LOGIN")

    if password.lower() in COMMON_PASSWORDS:
        errors.append("COMMON")

    return errors


def generate_password(policy):
    """Задание 2. Случайный пароль длиной max(policy["min_length"], 12) из 4 классов."""
    length = max(policy["min_length"], 12)
    lowers = string.ascii_lowercase
    uppers = string.ascii_uppercase
    digits = string.digits
    symbols = "!@#$%^&*_-+=?"

    pw_chars = [
        secrets.choice(lowers),
        secrets.choice(uppers),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    all_chars = lowers + uppers + digits + symbols
    for _ in range(length - 4):
        pw_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(pw_chars)
    return "".join(pw_chars)


def effective_permissions(position, roles):
    """Задание 3. Отсортированный список прав должности (без повторов)."""
    perms = set()
    for role_name in roles["positions"].get(position, []):
        perms.update(roles["roles"].get(role_name, []))
    return sorted(perms)


def write_role_matrix(roles, path="role_matrix.csv"):
    """Задание 3. CSV-матрица ролей."""
    all_perms = sorted({p for plist in roles["roles"].values() for p in plist})
    rows = []
    for pos in roles["positions"]:
        pos_perms = set(effective_permissions(pos, roles))
        row = {"position": pos}
        for p in all_perms:
            row[p] = "+" if p in pos_perms else ""
        rows.append(row)

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["position"] + all_perms)
        writer.writeheader()
        writer.writerows(rows)


def create_account(emp, accounts, grants, roles, policy):
    """Задание 3. Создаёт учётную запись сотрудника emp."""
    existing_logins = {a["login"] for a in accounts}
    login = make_login(emp["fullname"], existing_logins)
    password = generate_password(policy)

    accounts.append({
        "login": login,
        "emp_id": emp["emp_id"],
        "created": today().isoformat(),
        "last_login": "",
        "disabled_at": "",
    })

    for perm in effective_permissions(emp["position"], roles):
        grants.append({"login": login, "permission": perm})

    log_action("create", login, f"{emp['fullname']}, {emp['position']}")
    return login, password


if __name__ == "__main__":
    cfg, roles = load_json("config.json"), load_json("roles.json")
    employees, accounts, grants = (
        read_csv("hr.csv"),
        read_csv("accounts.csv"),
        read_csv("grants.csv"),
    )
    write_role_matrix(roles)
    for emp in new_hires(employees, accounts):
        login, pw = create_account(emp, accounts, grants, roles, cfg["password_policy"])
        print(f"{emp['emp_id']}  {emp['fullname']:<25} {login:<16} {pw}")
    write_csv("accounts.csv", accounts)
    write_csv("grants.csv", grants)