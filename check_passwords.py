"""Проверка 1000 сгенерированных паролей."""

from iam import check_password, generate_password
from store import load_json

if __name__ == "__main__":
    policy = load_json("config.json")["password_policy"]
    bad = 0
    sample = ""
    for i in range(1000):
        pw = generate_password(policy)
        if i == 0:
            sample = pw
        if check_password(pw, "x.test", policy):
            bad += 1

    print(f"Политика варианта: {policy}")
    print(f"Пример пароля: {sample}")
    print(f"Паролей с нарушениями: {bad} из 1000")