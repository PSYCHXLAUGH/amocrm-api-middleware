import os
from dataclasses import dataclass


@dataclass
class WidgetConfig:
    """
    OAuth 2.0 Configuration class for integrating with the amoCRM API.

    This class is used to store the parameters required for authentication
    and interaction with the amoCRM API via OAuth 2.0.
    It allows specifying parameters such as `client_id`, `client_secret`,
    and `redirect_uri` for authentication and token retrieval.
    These parameters can be supplied explicitly or through environment variables.

    Attributes:
        client_id (str): The OAuth client ID required for authentication with the amoCRM API.
                         This can be passed via the environment variable `AMOCRM_CLIENT_ID`
                         if not provided explicitly.
        client_secret (str): The OAuth client secret used for authentication with the amoCRM API.
                             This can be passed via the environment variable `AMOCRM_CLIENT_SECRET`
                             if not provided explicitly.
        redirect_uri (str): The URL to which the user will be redirected after successful authentication.
                             This can be passed via the environment variable `AMOCRM_REDIRECT_URI`
                             if not provided explicitly.
        segment (str): kommo or amoCRM
    """

    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""