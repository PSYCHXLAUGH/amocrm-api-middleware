from client import OAuthV4ApiClient
from urllib3 import urlen

class OAuthButtonV4Manager:
    def __init__(self, OAuthV4ApiClient: OAuthV4ApiClient):
        self.config = OAuthV4ApiClient


    def get_authorization_url(self, state: Optional[str] = None, mode: Optional[str] = None) -> str:
        """
        Generates the URL to obtain the authorization code.

        :param state: (Optional[str]) An optional parameter that will be included in the request.
        :param mode: (Optional[str]) An optional parameter that will be included in the request if `state` is not provided.

        :return: (str) The generated URL for authorization.
        """
        params = {
            "client_id": self.config.client_id,
            "state": state,
            "mode": mode
        }

        # Filter out None values from the parameters
        params = {key: value for key, value in params.items() if value is not None}

        return f'{self.segment.get_base_url()}{urlencode(params)}'
