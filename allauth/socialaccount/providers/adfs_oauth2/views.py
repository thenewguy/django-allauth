from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter,
                                                          OAuth2LoginView,
                                                          OAuth2CallbackView)
from django.core.exceptions import ImproperlyConfigured
from .provider import ADFSOAuth2Provider
from urlparse import urlunsplit
from .utils import decode_payload_segment, parse_token_payload_segment

try:
    import jwt
except ImportError:
    JWT_AVAILABLE = False
    import json
else:
    JWT_AVAILABLE = True

class ADFSOAuth2Adapter(OAuth2Adapter):
    provider_id = ADFSOAuth2Provider.id
    scheme = "https"
    
    def get_required_setting(self, key):
        value = self.get_provider().get_settings().get(key, "")
        if not value:
            raise ImproperlyConfigured("ADFS OAuth2 provider setting '%s' must be specified." % key)
        return value
    
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
            kwargs = {"verify": verify_token}
            if verify_token:
                # the signature is assumed to be valid because the
                # token was retrieved directly from adfs via https
                kwargs["options"] = {'verify_signature': False}
            payload = jwt.decode(token.token, **kwargs)
            
        else:
            if verify_token:
                raise ImproperlyConfigured("ADFS OAuth2 cannot verify tokens without the `PyJWT` package.")
            
            encoded_data = parse_token_payload_segment(token.token)
            data = decode_payload_segment(encoded_data)
            payload = json.loads(data.decode('utf-8'))
        
        return self.get_provider().sociallogin_from_response(
            request,
            payload
        )

oauth_login = OAuth2LoginView.adapter_view(ADFSOAuth2Adapter)
oauth_callback = OAuth2CallbackView.adapter_view(ADFSOAuth2Adapter)
