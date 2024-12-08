from .._const import KOMMO_V4_CONST, AMOCRM_V4_CONST
from exceptions import UnknownSegmentError
from typing import Dict

class OAuthV4SegmentHelper:
    """Обработчик сегментов, отвечающий за выбор правильных константных классов для различных сегментов."""

    SEGMENTS: Dict[str, object] = {
        'kommo': KOMMO_V4_CONST,
        'amocrm': AMOCRM_V4_CONST
    }

    @staticmethod
    def handle_segment(segment: str):
        """
        Получение константного класса для соответствующего сегмента.

        :param segment: строка, представляющая сегмент (например, 'kommo' или 'amocrm').
        :return: класс констант для соответствующего сегмента.
        :raises OAuthError: если сегмент не найден.
        """
        try:
            return OAuthSegmentHelper.SEGMENTS[segment]
        except KeyError:
            raise UnknownSegmentError(
                message=f"Segment '{segment}' not found.",
                details={vars(segment)} # for debug
            )
