from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider


class ADFSOAuth2Account(ProviderAccount):
    pass


class ADFSOAuth2Provider(OAuth2Provider):
    id = 'adfs_oauth2'
    name = 'ADFS Oauth2'
    package = 'allauth.socialaccount.providers.adfs_oauth2'
    account_class = ADFSOAuth2Account

    def extract_uid(self, data):
        return data['ppid']

    def extract_common_fields(self, data):
        return dict(name=data.get('unique_name'))

providers.registry.register(ADFSOAuth2Provider)
