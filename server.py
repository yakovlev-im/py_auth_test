# FastAPI server
import base64
import hmac
import hashlib
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response


app = FastAPI()

SECRET_KEY = "106565ef259e225eeb442b405972b224bcbef4bbb0892b92c1bd99193588c1af"
PASSWORD_SALT = "7692c18c0cd44df965e69e6ca14c969fbfccbc8ecfbd14bd03bc301a9ae1c189"


def sign_data(data: str) -> str:
    """Возвращает подписанные данные data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username


def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256(
        (password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]["password"].lower()
    return password_hash == stored_password_hash


users = {
    "umgans@yandex.ru": {
        "name": "Nikolay",
        "password": "6fe9421e398ae75f982e4f09313f01b8e26a59d69c10d29f821d24ed3f6d66cc",
        "balance": 100_000
    },
    "test@user.ru": {
        "name": "Alex",
        "password": "9dbb63c2538a0ba808e16872f40c541689bd74a667bb115e89c0e8e928cddd1e",
        "balance": 30_000
    }
}


@app.get("/")
def index_page(
    username: Optional[str] = Cookie(None)
):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()

    if not username:
        return Response(login_page, media_type="text/html")

    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response

    return Response(f"Привет, {users[valid_username]['name']}", media_type="text/html")


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Я вас не знаю"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}! <br> Ваш баланс: {user['balance']}"
        }),
        media_type="text/html")

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
