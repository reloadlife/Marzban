import re
from datetime import datetime
from enum import Enum
from typing import Dict, List

from app.models.proxy import ProxySettings, ProxyTypes
from app.utils.jwt import create_subscription_token
from app.utils.share import generate_v2ray_links
from app.xray import INBOUNDS
from config import XRAY_HOSTS, XRAY_SUBSCRIPTION_URL_PREFIX
from pydantic import BaseModel, validator, Field
from xray_api.types.account import Account

USERNAME_REGEXP = re.compile(r'^(?=\w{3,32}\b)[a-zA-Z0-9]+(?:_[a-zA-Z0-9]+)*$')


class UserStatus(str, Enum):
    active = "active"
    disabled = "disabled"
    limited = "limited"
    expired = "expired"


class User(BaseModel):
    proxies: Dict[ProxyTypes, ProxySettings] = {}
    expire: int = None
    data_limit: int = None
    inbounds: Dict[ProxyTypes, List[str]] = {}

    @validator('inbounds')
    def validate_inbounds(cls, v, values, **kwargs):
        if v:
            for proxy_type, tags in v.items():
                if not tags:
                    raise ValueError(f"{proxy_type} inbounds cannot be empty")

                for tag in tags:
                    if not any(i['tag'] == tag for i in INBOUNDS.get(proxy_type, {})):
                        raise ValueError(f"Inbound tag {tag} doesn't exist")
        else:
            v = {}
            for proxy_type in values.get('proxies', {}):
                for inbound in INBOUNDS[proxy_type]:
                    try:
                        v[proxy_type].append(inbound['tag'])
                    except KeyError:
                        v[proxy_type] = [inbound['tag']]
        return v

    @validator('proxies', pre=True, always=True)
    def validate_proxies(cls, v, values, **kwargs):
        if not v:
            raise ValueError("Each user needs at least one proxy")
        return {proxy_type: ProxySettings.from_dict(proxy_type, v.get(proxy_type, {})) for proxy_type in v}

    @validator('username', check_fields=False)
    def validate_username(cls, v):
        if not USERNAME_REGEXP.match(v):
            raise ValueError('Username only can be 3 to 32 characters and contain a-z, 0-9, and underscores in between.')
        return v

    def get_account(self, proxy_type: ProxyTypes) -> Account:
        if not getattr(self, 'username'):
            return

        try:
            attrs = self.proxies[proxy_type].dict(no_obj=True)
        except KeyError:
            raise LookupError(f'User do not have {proxy_type} proxy activated')

        return ProxyTypes(proxy_type).account_model(email=self.username, **attrs)

    def get_excluded_inbounds(self):
        excluded = {proxy_type: [] for proxy_type in self.proxies}
        for proxy_type in self.proxies:
            for inbound in INBOUNDS.get(proxy_type, []):
                if not inbound['tag'] in self.inbounds.get(proxy_type, []):
                    excluded[proxy_type].append(inbound['tag'])

        return excluded


class UserCreate(User):
    username: str

    class Config:
        schema_extra = {
            "example": {
                "username": "user1234",
                "proxies": {
                    "vmess": {
                        "id": "35e4e39c-7d5c-4f4b-8b71-558e4f37ff53"
                    },
                    "vless": {}
                },
                "inbounds": {
                    "vmess": [
                        "VMESS_INBOUND"
                    ],
                    "vless": [
                        "VLESS_INBOUND"
                    ]
                },
                "expire": 0,
                "data_limit": 0
            }
        }


class UserModify(User):
    class Config:
        schema_extra = {
            "example": {
                "proxies": {
                    "vmess": {
                        "id": "35e4e39c-7d5c-4f4b-8b71-558e4f37ff53"
                    },
                    "vless": {}
                },
                "inbounds": {
                    "vmess": [
                        "VMESS_INBOUND"
                    ],
                    "vless": [
                        "VLESS_INBOUND"
                    ]
                },
                "expire": 0,
                "data_limit": 0

            }
        }

    @validator('inbounds')
    def validate_inbounds(cls, v, values, **kwargs):
        if v:
            for proxy_type, tags in v.items():
                if not tags:
                    raise ValueError(f"{proxy_type} inbounds cannot be empty")

                for tag in tags:
                    if not any(i['tag'] == tag for i in INBOUNDS.get(proxy_type, {})):
                        raise ValueError(f"Inbound tag {tag} doesn't exist")
        return v

    @validator('proxies', pre=True, always=True)
    def validate_proxies(cls, v):
        return {proxy_type: ProxySettings.from_dict(proxy_type, v.get(proxy_type, {})) for proxy_type in v}

    def get_excluded_inbounds(self):
        excluded = {proxy_type: [] for proxy_type in self.inbounds}
        for proxy_type in self.inbounds:
            for inbound in INBOUNDS.get(proxy_type, []):
                if not inbound['tag'] in self.inbounds.get(proxy_type, []):
                    excluded[proxy_type].append(inbound['tag'])

        return excluded


class UserResponse(User):
    username: str
    status: UserStatus
    used_traffic: int
    created_at: datetime
    links: List[str] = []
    subscription_url: str = ''
    proxies: dict
    excluded_inbounds: Dict[ProxyTypes, List[str]] = {}

    class Config:
        orm_mode = True

    @validator('links', pre=False, always=True)
    def validate_links(cls, v, values, **kwargs):
        if not v:
            return generate_v2ray_links(values['username'], values.get('proxies', {}), values['inbounds'])
        return v

    @validator('subscription_url', pre=False, always=True)
    def validate_subscription_url(cls, v, values, **kwargs):
        if not v:
            token = create_subscription_token(values['username'])
            return f'{XRAY_SUBSCRIPTION_URL_PREFIX}/sub/{token}'
        return v

    @validator('proxies', pre=True, always=True)
    def validate_proxies(cls, v, values, **kwargs):
        if isinstance(v, list):
            v = {p.type: p.settings for p in v}
        return super().validate_proxies(v, values, **kwargs)
