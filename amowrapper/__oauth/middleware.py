from .client import OAuthV4Client
from .exceptions import OAuthLongTermTokenExpired, OAuthAccessTokenExpired
from .exceptions import OAuthTokenNotFoundError
from ..__helpers import OAuthV4Helper

class OAuthMiddleware:
    """
    Middleware для работы с OAuth: проверка токенов и обновление токена, если нужно.

    Этот класс выполняет несколько важных функций:
    - Проверяет, доступен ли токен доступа.
    - Обновляет токен, если он просрочен или отсутствует.
    - Обеспечивает выполнение аутентифицированных запросов с использованием OAuth-токена.

    Атрибуты:
        oauth_client (OAuthClient): Экземпляр клиента OAuth, который будет использоваться для выполнения запросов.
    """

    def __init__(self, oauth_client: OAuthV4Client): # TODO сделать проверку того, какой класс здесь передается. Например fileuploadmanger
        """
        Инициализация middleware с клиентом OAuth.

        Параметры:
            oauth_client (OAuthClient): Экземпляр клиента OAuth, используемый для выполнения запросов.
        """
        self._oauth_client = oauth_client

    def _ensure_authenticated(self) -> None:
        """
        Проверка токена и обновление его, если необходимо.

        Этот метод выполняет проверку наличия и валидности токена доступа. Если токен отсутствует
        или недействителен, возбуждается исключение OAuthError.

        Исключения:
            OAuthError: Если токен доступа отсутствует или недействителен.
        """

        # Проверяем наличие токенов
        if not self._oauth_client.access_token and not self._oauth_client.longlive_token:
            raise OAuthTokenNotFoundError("credentials not found")

        # Функция для проверки истечения срока действия токенов.

        if self._oauth_client.longlive_token and OAuthV4Helper.is_token_expired(self._oauth_client.longlive_token):
            raise OAuthLongTermTokenExpired("long-term token has expired.")


        if self._oauth_client.access_token and self._oauth_client.is_token_expired(self._oauth_client.access_token):
            raise OAuthAccessTokenExpired("access token has expired.")


    def make_v4_authenticated_request(self, endpoint: str, method: str = "GET", data: dict = None):
        """
        Выполнение запросов с проверкой на авторизацию.

        Этот метод сначала проверяет, есть ли действующий токен доступа, а затем выполняет запрос
        к указанному эндпоинту с использованием этого токена. Если токен просрочен, он будет обновлен.

        Параметры:
            endpoint (str): URL-адрес эндпоинта, к которому будет выполнен запрос.
            Method (str, optional): HTTP-метод запроса (например, "GET", "POST"). По умолчанию используется "GET".
            Data (dict, optional): Данные, которые могут быть отправлены в теле запроса (например, для метода "POST").

        Возвращаемое значение:
            Результат запроса, полученный от клиента OAuth.

        Исключения:
            OAuthError: Если токен невалиден или недействителен.
        """
        self._ensure_authenticated()
        return self._oauth_client._make_v4_authenticated_request(endpoint, method, data)

    def make_amojo_authenticated_request(self): # TODO: Отправка сообщений
        pass


    def make_drive_authenticated_request(self): # TODO: Отправка файла
        pass