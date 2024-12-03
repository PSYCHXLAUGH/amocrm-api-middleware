class WebhookSignatureError(Exception):
    """Ошибка при проверке подписи webhook."""
    pass

class WebhookParseError(Exception):
    """Ошибка при парсинге данных webhook."""
    pass