import base64
import json
from datetime import datetime
from typing import Optional


class OAuthV4Helper:

    @staticmethod
    def decode_jwt(token: str) -> dict:
        """
        Декодирует JWT токен без проверки подписи и возвращает полезную нагрузку.

        Параметры:
            token (str): JWT токен, который нужно расшифровать.

        Возвращаемое значение:
            dict: Данные (payload) из JWT токена.

        Исключения:
            ValueError: Если токен имеет некорректный формат.
        """
        try:
            # Разделяем токен на три части (header, payload, signature)
            _, payload_b64, _ = token.split(".")

            # Декодируем base64url строку в байты, затем в строку JSON
            payload_json = base64.urlsafe_b64decode(payload_b64 + "==").decode("utf-8")

            # Преобразуем JSON в Python объект (словарь)
            return json.loads(payload_json)

        except ValueError as e:
            raise ValueError(f"Ошибка декодирования JWT токена: {e}")

    @staticmethod
    def compare_and_decode_timestamp(timestamp: int) -> bool:
        """
        Декодирует временную метку (timestamp) в строку формата 'YYYY-MM-DD HH:MM:SS'
        и сравнивает её с текущим временем.

        Параметры:
            timestamp (int): Временная метка (количество секунд с 1 января 1970 года).

        Возвращаемое значение:
            bool: True, если временная метка меньше текущего времени, иначе False.
        """
        # Преобразуем временную метку в объект datetime
        decoded_time = datetime.utcfromtimestamp(timestamp)

        # Форматируем объект datetime в строку
        decoded_time_str = decoded_time.strftime('%Y-%m-%d %H:%M:%S')

        # Получаем текущее время в формате UTC
        current_time_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        # Сравниваем временную метку с текущим временем
        return decoded_time_str < current_time_str

    def is_token_expired(self, token: str) -> Optional[bool]:
        """
        Проверяет, истек ли срок действия токена.
        """
        if not token:
            return None

        jwt = OAuthV4Helper.decode_jwt(token)
        jwt_exp = jwt.get('exp')
        if jwt_exp is None:
            return None
        return OAuthV4Helper.compare_and_decode_timestamp(jwt_exp)


# # Пример использования:
# token = "your.jwt.token"
# helper = OAuthV4Helper()
# print(helper.is_token_expired(token))
