from loguru import logger
import requests

class FileUploadManager:
    def __init__(self, config: OAuthConfig, max_part_size: int = 131072):
        """
        Инициализация FileUploader.

        :param config: TODO дописать
        :param max_part_size: Максимальный размер части файла для загрузки (по умолчанию 131072 байт)
        """
        self.config: OAuthConfig = config
        self.max_part_size = max_part_size

    def create_session(self, file_name: str, file_size: int) -> str:
        """
        Создает сессию для загрузки файла на сервер.
        """
        url = "https://drive-b.amocrm.ru/v1.0/sessions"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.access_token}'
        }
        payload = json.dumps({
            "file_name": file_name,
            "file_size": file_size,
            "content_type": 'image/jpeg'
        })

        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()  # Выбрасываем ошибку при плохом статусе
        return response.json()['upload_url']

    def upload_chunk(self, file_chunk: bytes, upload_url: str) -> str:
        """
        Загружает одну часть файла на сервер.
        """
        headers = {
            'Content-Type': 'image/jpeg',
            'Authorization': f'Bearer {self.access_token}'
        }

        response = requests.post(upload_url, headers=headers, data=file_chunk)
        response.raise_for_status()  # Выбрасываем ошибку при плохом статусе
        logger.info("Загружена часть файла")
        logger.debug(response.json())

        return response.json().get('next_url')

    def upload_file_in_parts(self, file_path: str):
        """
        Читает файл частями (генератор).
        """
        file_size = os.path.getsize(file_path)
        logger.info(f"Размер файла: {file_size} байт")

        with open(file_path, 'rb') as file:
            while chunk := file.read(self.max_part_size):
                yield chunk

    def upload_file(self, file_path: str, file_name: str):
        """
        Загружает файл на сервер частями.
        """
        # Создаем сессию для загрузки файла
        upload_url = self.create_session(file_name=file_name, file_size=os.path.getsize(file_path))

        # Загружаем файл частями
        for part in self.upload_file_in_parts(file_path):
            upload_url = self.upload_chunk(file_chunk=part, upload_url=upload_url)
