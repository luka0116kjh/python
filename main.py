import os
import json
import base64
import hashlib
import hmac
import getpass

DB_FILE = "users.json"
ITERATIONS = 200_000

def load_db() -> dict:
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, ValueError):
        return {}

def save_db(db: dict) -> None:
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)

def pbkdf2_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS)

def encode_b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def decode_b64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def is_strong_password(pw: str) -> tuple[bool, str]:
    if len(pw) < 8:
        return False, "비밀번호는 8자 이상이어야 합니다."
    if not any(c.islower() for c in pw):
        return False, "소문자를 1개 이상 포함하세요."
    if not any(c.isupper() for c in pw):
        return False, "대문자를 1개 이상 포함하세요."
    if not any(c.isdigit() for c in pw):
        return False, "숫자를 1개 이상 포함하세요."
    if not any(c in "!@#$%^&*()-_=+[]{};:,.?/" for c in pw):
        return False, "특수문자를 1개 이상 포함하세요."
    return True, "OK"

def register(db: dict) -> None:
    username = input("새 아이디: ").strip()
    if not username:
        print("아이디는 비어있을 수 없습니다.")
        return
    if username in db:
        print("이미 존재하는 아이디입니다.")
        return

    pw = getpass.getpass("새 비밀번호: ")
    ok, msg = is_strong_password(pw)
    if not ok:
        print(msg)
        return

    pw2 = getpass.getpass("비밀번호 확인: ")
    if pw != pw2:
        print("비밀번호가 일치하지 않습니다.")
        return

    salt = os.urandom(16)
    digest = pbkdf2_hash(pw, salt)

    db[username] = {
        "salt": encode_b64(salt),
        "hash": encode_b64(digest),
        "iterations": ITERATIONS,
    }
    save_db(db)
    print("회원가입 완료!")

def login(db: dict) -> None:
    username = input("아이디: ").strip()
    if username not in db:
        print("아이디 또는 비밀번호가 올바르지 않습니다.")
        return

    pw = getpass.getpass("비밀번호: ")
    rec = db[username]
    salt = decode_b64(rec["salt"])
    iterations = int(rec.get("iterations", ITERATIONS))

    test_digest = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iterations)
    real_digest = decode_b64(rec["hash"])

    if hmac.compare_digest(test_digest, real_digest):
        print(f"로그인 성공! 환영합니다, {username} 님.")
    else:
        print("아이디 또는 비밀번호가 올바르지 않습니다.")

def main():
    db = load_db()
    while True:
        print("\n1) 회원가입  2) 로그인  3) 종료")
        choice = input("선택: ").strip()

        if choice == "1":
            register(db)
            db = load_db()  
        elif choice == "2":
            db = load_db()
            login(db)
        elif choice == "3":
            print("종료합니다.")
            break
        else:
            print("1~3 중에서 선택하세요.")

if __name__ == "__main__":
    main()
