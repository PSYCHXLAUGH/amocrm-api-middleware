import hashlib
import hmac
import json
import requests
from datetime import datetime
from .._segments import OAuthV4Segment

class AmojoApiManager:
    def __init__(self, secret, account_id, segment: OAuthV4Segment):
        self.secret = secret
        self.account_id = account_id
        self.base_url = OAuthV4Segment.get_amojo_url()
        self.method = "POST"
        self.content_type = "application/json"
        self.path = "/v2/origin/custom/f90ba33d-c9d9-44da-b76c-c349b0ecbe41/connect"

    def generate_signature(self, body):
        # Генерация строки для подписи
        date = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
        request_body = json.dumps(body)
        check_sum = hashlib.md5(request_body.encode('utf-8')).hexdigest()

        # Строка для HMAC подписи
        signature_string = "\n".join([
            self.method.upper(),
            check_sum,
            self.content_type,
            date,
            self.path,
        ])

        # Генерация подписи
        signature = hmac.new(
            self.secret.encode('utf-8'),
            signature_string.encode('utf-8'),
            hashlib.sha1
        ).hexdigest()

        return signature, date, check_sum

    def send_request(self, title):
        body = {
            "account_id": self.account_id,
            "title": title,
            "hook_api_version": "v2"
        }

        # Генерация подписи и заголовков
        signature, date, check_sum = self.generate_signature(body)

        headers = {
            "Date": date,
            "Content-Type": self.content_type,
            "Content-MD5": check_sum.lower(),
            "X-Signature": signature.lower()
        }

        # Отправка POST-запроса
        url = self.base_url + self.path
        response = requests.post(url, json=body, headers=headers)

        # Проверка ответа
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "status_code": response.status_code,
                "response": response.text
            }