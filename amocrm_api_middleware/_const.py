class AMOCRM_V4_CONST:
    """Класс с константами для работы с API AmoCRM."""

    @staticmethod
    def V4_BASE_SUBDOMAIN_URL() -> str:
        """Генерация базового URL для AmoCRM API."""
        return 'https://amocrm.ru'

    def V4_BASE_URL() -> str:
        """Генерация базового URL для AmoCRM API."""
        return 'https://amocrm.ru'

    @staticmethod
    def MAKE_V4_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация полного URL для AmoCRM API с учетом конечной точки."""
        return f'{base_url}/{endpoint}'

    @staticmethod
    def MAKE_AMOJO_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация URL для API Amojo (пока не реализовано)."""
        return f'{base_url}/amojo/{endpoint}'  # Пример реализации, зависит от дальнейших деталей

    @staticmethod
    def MAKE_DRIVE_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация URL для API Drive (пока не реализовано)."""
        return f'{base_url}/drive/{endpoint}'  # Пример реализации, зависит от дальнейших деталей


class KOMMO_V4_CONST:
    """Класс с константами для работы с API Kommo."""

    @staticmethod
    def V4_BASE_URL() -> str:
        """Генерация базового URL для Kommo API."""
        return f'https://kommo.com'

    @staticmethod
    def MAKE_V4_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация полного URL для Kommo API с учетом конечной точки."""
        return f'{base_url}/{endpoint}'

    @staticmethod
    def MAKE_AMOJO_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация URL для API Amojo (пока не реализовано)."""
        return f'{base_url}/amojo/{endpoint}'  # Пример реализации, зависит от дальнейших деталей

    @staticmethod
    def MAKE_DRIVE_ENDPOINT(base_url: str, endpoint: str) -> str:
        """Генерация URL для API Drive (пока не реализовано)."""
        return f'{base_url}/drive/{endpoint}'  # Пример реализации, зависит от дальнейших деталей


class SegmentHandler:
    """Обработчик сегментов, отвечающий за выбор правильных константных классов для различных сегментов."""

    SEGMENTS = {'kommo': KOMMO_V4_CONST, 'amocrm': AMOCRM_V4_CONST}

    @staticmethod
    def handle_segment(segment: str):
        """
        Получение константного класса для соответствующего сегмента.

        :param segment: строка, представляющая сегмент (например, 'kommo' или 'amocrm').
        :return: класс констант для соответствующего сегмента.
        :raises OAuthError: если сегмент не найден.
        """
        try:
            return SegmentHandler.SEGMENTS[segment]
        except KeyError:
            raise OAuthError(f"Segment '{segment}' not found.")
