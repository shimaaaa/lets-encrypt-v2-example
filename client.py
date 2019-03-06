import json
import base64
import hashlib
from pathlib import Path
from typing import List, Optional
from logging import getLogger, INFO

import requests
from jwcrypto import jwk, jws
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

logger = getLogger(__name__)


class Account:

    def __init__(self):
        self._load_key()
        self._load_config()

    @property
    def key_pem(self) -> str:
        return self._key_pem

    @property
    def key_object(self) -> rsa.RSAPrivateKey:
        return self._key_object

    @property
    def url(self) -> str:
        return self._url

    def _load_key(self):
        account_key_file = Path('account.key')
        if not account_key_file.exists():
            self._generate_key(account_key_file)
        with account_key_file.open() as f:
            self._key_pem = f.read()
        self._key_object = serialization.load_pem_private_key(
            self._key_pem.encode(),
            None,
            default_backend()
        )

    def _generate_key(self, account_key_file: Path):
        with account_key_file.open(mode='w') as f:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(pem.decode())

    def _load_config(self):
        config_file = Path('account.json')
        if not config_file.exists():
            self._url = None
            return
        with config_file.open() as f:
            config = json.load(f)
            self._url = config.get('url', None)

    def set_config(self, config: dict):
        config_file = Path('account.json')
        with config_file.open(mode='w') as f:
            json.dump(config, f)
        self._load_config()


class DnsChallenge:

    def __init__(self, resource: dict):
        self.resource = resource

    @property
    def url(self) -> str:
        return self.resource.get('url')

    @property
    def type(self) -> str:
        return self.resource.get('type')

    @property
    def status(self) -> str:
        return self.resource.get('status')

    @property
    def token(self) -> str:
        return self.resource.get('token')


class Authorization:

    def __init__(self, url: str, resource: dict):
        self.url = url
        self.resource = resource

    @property
    def fqdn(self) -> str:
        return self.resource['identifier']['value']

    @property
    def status(self) -> str:
        return self.resource.get('status')

    @property
    def expires(self) -> str:
        return self.resource.get('expires')

    @property
    def dns_challenge(self) -> Optional[DnsChallenge]:
        for challenge in self.resource.get('challenges'):
            if challenge.get('type') == 'dns-01':
                return DnsChallenge(challenge)
        return None

    @staticmethod
    def fetch(url: str) -> 'Authorization':
        response = requests.get(url)
        return Authorization(url, response.json())


class Order:

    def __init__(self, url: str, resource: dict):
        self.url = url
        self.resource = resource

    @property
    def status(self) -> str:
        return self.resource.get('status')

    @property
    def authorizations(self) -> List[Authorization]:
        return [Authorization.fetch(auth_url) for auth_url in self.resource.get('authorizations')]

    @property
    def finalize(self) -> str:
        return self.resource.get('finalize')

    @property
    def certificate(self) -> str:
        return self.resource.get('certificate')

    @property
    def fqdn_list(self) -> List[str]:
        return [identifier.get('value') for identifier in self.resource.get('identifiers')]

    @property
    def expires(self) -> str:
        return self.resource.get('expires')

    def dump(self, base_path: Path):
        with (base_path / Path('order.json')).open(mode='w') as f:
            resource = self.resource
            resource['url'] = self.url
            json.dump(resource, f)

    @staticmethod
    def load(base_path: Path):
        with (base_path / Path('order.json')).open() as f:
            resource = json.load(f)
            return Order(resource.get('url'), resource)


class LetsEncryptApiClient:

    DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory'
    STAGING_DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'

    def __init__(self, account: Account, **kwargs):
        self._account = account

        is_staging = kwargs.get('is_staging', False)
        if is_staging:
            self._directory_url = self.STAGING_DIRECTORY_URL
        else:
            self._directory_url = kwargs.get('directory_url', self.DIRECTORY_URL)
        self._directory_data = self._get_directory_data()
        self._nonce = self._new_nonce()

    @classmethod
    def _base64(cls, value: bytes):
        return base64.urlsafe_b64encode(value).decode('utf8').rstrip('=')

    def _get_directory_data(self):
        return requests.get(self._directory_url).json()

    def _new_nonce(self):
        url = self._directory_data['newNonce']
        return requests.get(url).headers['Replay-Nonce']

    def _signed_request(self,
                        url: str,
                        payload: dict,
                        kid: str = None) -> requests.Response:
        p = json.dumps(payload)
        account_jwk = jwk.JWK.from_pem(self._account.key_pem.encode())

        protected = {
            'alg': 'RS256',
            'url': url,
            'nonce': self._nonce
        }
        if kid is None:
            protected['jwk'] = json.loads(account_jwk.export_public())
        else:
            protected['kid'] = kid

        jws_token = jws.JWS(p.encode())
        jws_token.add_signature(account_jwk,
                                None,
                                protected=protected,
                                header=None)

        sig = jws_token.serialize()
        response = requests.post(url, data=sig, headers={'Content-Type': 'application/jose+json'})
        reply_nonce = response.headers.get('Replay-Nonce', None)
        if reply_nonce is not None:
            self._nonce = reply_nonce
        return response

    def _base_path(self,
                   fqdn_list: List[str],
                   mkdir: bool = True) -> Path:
        directory = Path(self._base64('__'.join(fqdn_list).encode()))
        if not directory.exists() and mkdir:
            directory.mkdir()
        return directory

    def new_account(self, email: str):
        url = self._directory_data['newAccount']
        payload = {
            'termsOfServiceAgreed': True,
            'contact': [
                f'mailto:{email}'
            ]
        }
        response = self._signed_request(
            url=url,
            payload=payload
        )
        response.raise_for_status()
        config = response.json()
        config['url'] = response.headers.get('Location')
        self._account.set_config(config)

    def new_order(self, fqdn_list: List[str]) -> Order:
        url = self._directory_data['newOrder']
        identifers = [dict(type='dns', value=fqdn) for fqdn in fqdn_list]
        payload = {
            'identifiers': identifers
        }
        response = self._signed_request(
            url=url,
            payload=payload,
            kid=self._account.url
        )
        response.raise_for_status()

        order = Order(
            url=response.headers.get('Location'),
            resource=response.json()
        )
        order.dump(self._base_path(fqdn_list))
        return order

    def fetch_order(self, fqdn_list: List[str]):
        order = Order.load(self._base_path(fqdn_list))
        response = requests.get(order.url)
        order = Order(
            url=response.headers.get('Location'),
            resource=response.json()
        )
        return order

    def challenge_info(self, authorization: Authorization) -> dict:

        dns_challenge = authorization.dns_challenge
        token = dns_challenge.token
        account_jwk = jwk.JWK.from_pem(self._account.key_pem.encode())
        key_authorization = f'{token}.{account_jwk.thumbprint()}'
        return {
            'record_name': f'_acme-challenge.{authorization.fqdn}',
            'record_data': self._base64(hashlib.sha256(key_authorization.encode()).digest())
        }

    def challenge(self, challenge: DnsChallenge):
        url = challenge.url
        payload = {}
        response = self._signed_request(
            url=url,
            payload=payload,
            kid=self._account.url
        )
        response.raise_for_status()

    def issue_cert(self, order: Order):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        base_path = self._base_path(order.fqdn_list)
        with (base_path / Path('key.pem')).open(mode='w') as f:
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            f.write(key.decode())
        common_name = order.fqdn_list[0]
        sans = [x509.DNSName(f) for f in order.fqdn_list[1:]]
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name)
        ])).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False
        ).sign(private_key, hashes.SHA256(), default_backend())
        with (base_path / Path('csr.pem')).open(mode='w') as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM).decode())
        csr_der = self._base64(csr.public_bytes(serialization.Encoding.DER))
        payload = {
            'csr': csr_der
        }
        response = self._signed_request(
            url=order.finalize,
            payload=payload,
            kid=self._account.url
        )
        response.raise_for_status()

    def download_cert(self, order: Order):
        response = requests.get(
            order.certificate
        )
        with (self._base_path(order.fqdn_list) / Path('cert.pem')).open(mode='w') as f:
            f.write(response.text)

def main():
    logger.setLevel(INFO)

    # account = Account()
    # fqdn_list = ['*.example.com']
    # client = LetsEncryptApiClient(account=account, is_staging=True)
    # client.new_account(email='test@example.com')
    # order = client.new_order(fqdn_list)
    # order = client.fetch_order(fqdn_list)
    # authorization = order.authorizations[0]
    # info = client.challenge_info(authorization)
    # print(info)
    # client.challenge(authorization.dns_challenge)
    # client.issue_cert(order)
    # client.download_cert(order)


if __name__ == '__main__':
    main()

