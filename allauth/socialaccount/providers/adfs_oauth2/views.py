from allauth.socialaccount.providers.oauth2.views import (OAuth2Adapter,
                                                          OAuth2LoginView,
                                                          OAuth2CallbackView)
from django.core.exceptions import ImproperlyConfigured
from .provider import ADFSOAuth2Provider
from urlparse import urlunsplit
import jwt


class ADFSOAuth2Adapter(OAuth2Adapter):
    provider_id = ADFSOAuth2Provider.id
    
    
    @property
    def scheme(self):
        """
            i.e. 'http' or 'https'
        """
        base = self.get_provider().get_settings().get("scheme", "")
        if not base:
            raise ImproperlyConfigured("ADFS 'scheme' must be specified")
        return base
    
    @property
    def host(self):
        """
            i.e. sso.internal.example.com or sso.example.com:443
        """
        base = self.get_provider().get_settings().get("host", "")
        if not base:
            raise ImproperlyConfigured("ADFS 'host' must be specified")
        return base
    
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
        payload = jwt.decode(token.token, verify=False)
        
        return self.get_provider().sociallogin_from_response(
            request,
            payload
        )


oauth_login = OAuth2LoginView.adapter_view(ADFSOAuth2Adapter)
oauth_callback = OAuth2CallbackView.adapter_view(ADFSOAuth2Adapter)
