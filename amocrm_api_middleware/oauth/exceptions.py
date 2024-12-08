from typing import Optional, Dict, Any, Type

class OAuthError(Exception):
    """Основная ошибка при взаимодействии с OAuth 2.0.

    Все специфичные ошибки, связанные с OAuth, наследуются от этой ошибки.
    """
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}

class OAuthTokenNotFoundError(OAuthError):
    """Ошибка при отсутствии токена.

    Возникает, когда токен не найден в запросе, либо пользователь не авторизован.
    """
    def __init__(self, message: str = "OAuth token not found", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthLongTermTokenExpired(OAuthError):
    """Ошибка при истечении срока действия долгосрочного токена.

    Этот токен обычно используется для длительных сессий, и он истекает после определенного времени.
    """
    def __init__(self, message: str = "Long-term OAuth token has expired", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthAccessTokenExpired(OAuthError):
    """Ошибка при истечении срока действия access-токена.

    Этот токен используется для авторизации и может истечь в течение короткого времени.
    """
    def __init__(self, message: str = "Access token has expired", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthInvalidRequestError(OAuthError):
    """Ошибка, возникающая при неправильном запросе к OAuth серверу.

    Это может включать случаи, когда запрос не содержит необходимых параметров
    или когда параметры запроса неверны.
    """
    def __init__(self, message: str = "Invalid OAuth request", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthInvalidTokenError(OAuthError):
    """Ошибка, возникающая при некорректном или истекшем токене.

    Это может быть связано с истечением срока действия токена или его недействительностью.
    """
    def __init__(self, message: str = "Invalid or expired OAuth token", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthAuthorizationError(OAuthError):
    """Ошибка, связанная с ошибкой авторизации.

    Это может произойти, если аутентификация не удалась из-за неправильных данных (например, неправильный `client_id` или `client_secret`).
    """
    def __init__(self, message: str = "Authorization failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthTokenExchangeError(OAuthError):
    """Ошибка при обмене кода авторизации на токен.

    Этот тип ошибки возникает, если запрос на получение токена OAuth не удался.
    """
    def __init__(self, message: str = "OAuth token exchange failed", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthConnectionError(OAuthError):
    """Ошибка соединения с OAuth сервером.

    Это может происходить из-за проблем с сетевым соединением или временной недоступностью сервера.
    """
    def __init__(self, message: str = "Connection error with OAuth server", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)

class OAuthScopeError(OAuthError):
    """Ошибка, связанная с недостаточными правами доступа (scope).

    Возникает, когда запрашиваемый scope не соответствует нужным правам для выполнения операции.
    """
    def __init__(self, message: str = "Insufficient scope for this request", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, details)


class EXCEPTION_MAP:
    # Словарь для маппинга кода ответа на исключение
    __exception_map: Dict[int, Type[OAuthError]] = {
        400: OAuthTokenNotFoundError,
        401: OAuthAuthorizationError,
        403: OAuthAccessTokenExpired,
        404: OAuthTokenNotFoundError,
    }

    @staticmethod
    def handle_exception(response_code: int) -> OAuthError:
        """Обрабатывает исключение по коду ответа."""
        exception_class = EXCEPTION_MAP.__exception_map.get(response_code)
        if exception_class:
            return exception_class(f"Error occurred with status code: {response_code}")
        else:
            # Если код не найден, генерируем общее исключение
            return OAuthError(f"Unexpected error with status code: {response_code}")