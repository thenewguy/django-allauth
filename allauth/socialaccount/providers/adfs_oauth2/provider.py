from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.account.models import EmailAddress
from uuid import UUID

class ADFSOAuth2Account(ProviderAccount):
    pass

class ADFSOAuth2Provider(OAuth2Provider):
    id = 'adfs_oauth2'
    package = 'allauth.socialaccount.providers.adfs_oauth2'
    account_class = ADFSOAuth2Account
    
    @property
    def name(self):
        return self.get_settings().get("name", "ADFS Oauth2")

    def extract_uid(self, data):
        return UUID(bytes_le=data['ppid'].decode("base64")).__str__()

    def extract_common_fields(self, data):
        return dict(
            username = data.get('upn').split("@")[0],
            first_name = data.get('given_name'),
            last_name = data.get('family_name'),
        )
    
    def extract_email_addresses(self, data):
        return [EmailAddress(email=data.get('upn'), verified=True, primary=True)]

providers.registry.register(ADFSOAuth2Provider)
