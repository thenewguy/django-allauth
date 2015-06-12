from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter,
                                                          OAuth2LoginView,
                                                          OAuth2CallbackView)
from django.core.exceptions import ImproperlyConfigured
from .provider import ADFSOAuth2Provider
from urlparse import urlunsplit

try:
    import jwt
except ImportError:
    JWT_AVAILABLE = False
    import json
else:
    JWT_AVAILABLE = True

class ADFSOAuth2Adapter(OAuth2Adapter):
    provider_id = ADFSOAuth2Provider.id
    
    def get_required_setting(self, key):
        value = self.get_provider().get_settings().get(key, "")
        if not value:
            raise ImproperlyConfigured("ADFS OAuth2 provider setting '%s' must be specified." % key)
        return value
    
    @property
    def scheme(self):
        """
            i.e. 'http' or 'https'
        """
        return self.get_required_setting("scheme")
    
    @property
    def host(self):
        """
            e.g. sso.internal.example.com or sso.example.com:8443
        """
        return self.get_required_setting("host")
    
    def construct_redirect_url(self, path):
        parts = (
            self.scheme,
            self.host,
            path,
            "",
            "",
        )
        return urlunsplit(parts)
    
    @property
    def access_token_url(self):
        return self.construct_redirect_url("/adfs/oauth2/token")
    
    @property
    def authorize_url(self):
        return self.construct_redirect_url("/adfs/oauth2/authorize")

    def complete_login(self, request, app, token, **kwargs):
        verify_token = self.get_provider().get_settings().get("verify_token", True)
        
        if JWT_AVAILABLE:
            payload = jwt.decode(token.token, verify=verify_token)
            
        else:
            if verify_token:
                raise ImproperlyConfigured("ADFS OAuth2 cannot verify tokens without the `PyJWT` and `cryptography` packages.  If you're system doesn't allow installing `cryptography` like on Google App Engine, you can install `PyCrypto` for RSA signatures and `ecdsa` for ECDSA signatures.  It is not recommended to disable token verification.  However, it can be disabled by setting 'verify_token' to False.")
            
            encoded_data = token.token.split(".")[1]
            data = encoded_data.decode("base64")
            payload = json.loads(data)
        
        return self.get_provider().sociallogin_from_response(
            request,
            payload
        )

oauth_login = OAuth2LoginView.adapter_view(ADFSOAuth2Adapter)
oauth_callback = OAuth2CallbackView.adapter_view(ADFSOAuth2Adapter)
