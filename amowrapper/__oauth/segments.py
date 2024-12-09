from .._const import KOMMO_V4_CONST, AMOCRM_V4_CONST
from ..__helpers import OAuthV4SegmentHelper

class OAuthV4Segment:
    """Фасад для работы с различными API (AmoCRM, Kommo)."""

    def __init__(self,
                 subdomain: str,
                 segment
    ):
        """
        Инициализация фасада.

        :param segment: строка, представляющая сегмент ('amocrm' или 'kommo').
        :param subdomain: поддомен для формирования базового URL.
        """
        self._segment = OAuthV4Segment(subdomain, segment)

    def get_base_domain_url(self) -> str:
        """Возвращает базовый URL для API сегмента."""
        return self._segment.V4_BASE_URL()

    def get_base_url(self) -> str:
        """Возвращает базовый URL для API сегмента."""
        return self._segment.V4_BASE_URL()

    def get_full_url(self, endpoint: str) -> str:
        """Возвращает полный URL для конечной точки в выбранном сегменте."""
        base_url = self.get_base_domain_url()
        return self._segment.MAKE_V4_ENDPOINT(base_url, endpoint)

    def get_amojo_url(self, endpoint: str) -> str:
        """Возвращает URL для Amojo API (пока не реализовано)."""
        base_url = self.get_base_url()
        return self._segment.MAKE_AMOJO_ENDPOINT(base_url, endpoint)

    def get_drive_url(self, endpoint: str) -> str:
        """Возвращает URL для Drive API (пока не реализовано)."""
        base_url = self.get_base_url()
        return self._segment.MAKE_DRIVE_ENDPOINT(base_url, endpoint)
