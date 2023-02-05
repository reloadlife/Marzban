import base64
import copy
import json
import urllib.parse as urlparse
from typing import List, Union
from uuid import UUID

import yaml
from app.xray import INBOUNDS
from config import XRAY_HOSTS


class V2rayShareLink(str):
    @classmethod
    def vmess(cls,
              remark: str,
              address: str,
              port: int,
              id: Union[str, UUID],
              host='',
              net='tcp',
              path='',
              sni='',
              tls=False,
              type=''):
        return "vmess://" + base64.b64encode(json.dumps({
            'add': address,
            'aid': '0',
            'host': host,
            'id': str(id),
            'net': net,
            'path': urlparse.quote(path),
            'port': port,
            'ps': remark,
            'scy': 'auto',
            'sni': sni,
            'tls': 'tls' if tls else '',
            'type': type,
            'v': '2'
        }, sort_keys=True).encode('utf-8')).decode()

    @classmethod
    def vless(cls,
              remark: str,
              address: str,
              port: int,
              id: Union[str, UUID],
              net='ws',
              path='',
              tls=False,
              host='',
              sni='',
              type=''):

        opts = {
            "security": "tls" if tls else "none",
            "type": net,
            "host": host,
            "sni": sni,
            "headerType": type
        }
        if net == 'grpc':
            opts['serviceName'] = urlparse.quote(path)
        else:
            opts['path'] = urlparse.quote(path)

        return "vless://" + \
            f"{id}@{address}:{port}?" + \
            urlparse.urlencode(opts) + f"#{( urlparse.quote(remark))}"

    @classmethod
    def trojan(cls,
               remark: str,
               address: str,
               port: int,
               password: str,
               net='tcp',
               path='',
               tls=False,
               host='',
               sni='',
               type=''):

        opts = {
            "security": "tls" if tls else "none",
            "type": net,
            "host": host,
            "sni": sni,
            "headerType": type
        }
        if net == 'grpc':
            opts['serviceName'] = urlparse.quote(path)
        else:
            opts['path'] = urlparse.quote(path)

        return "trojan://" + \
            f"{urlparse.quote(password, safe=':')}@{address}:{port}?" + \
            urlparse.urlencode(opts) + f"#{urlparse.quote(remark)}"

    @classmethod
    def shadowsocks(cls,
                    remark: str,
                    address: str,
                    port: int,
                    password: str,
                    security='chacha20-ietf-poly1305'):
        return "ss://" + \
            base64.b64encode(f'{security}:{password}'.encode()).decode() + \
            f"@{address}:{port}#{urlparse.quote(remark)}"


class ClashConfiguration(object):
    def __init__(self):
        self.data = {
            'port': 7890,
            'mode': 'Global',
            'proxies': [],
            'proxy-groups': []
        }
        self.proxy_remarks = []

    def to_yaml(self):
        d = copy.deepcopy(self.data)
        d['proxy-groups'].append({'name': '♻️ Automatic',
                                  'type': 'url-test',
                                  'url': 'http://www.gstatic.com/generate_204',
                                  'interval': 300,
                                  'proxies': self.proxy_remarks})
        return yaml.dump(d, allow_unicode=True)

    def __str__(self) -> str:
        return self.to_yaml()

    def __repr__(self) -> str:
        return self.to_yaml()

    def _remark_validation(self, remark):
        if not remark in self.proxy_remarks:
            self.proxy_remarks.append(remark)
            return remark
        c = 2
        while True:
            new = f'{remark} ({c})'
            if not new in self.proxy_remarks:
                self.proxy_remarks.append(new)
                return new
            c += 1

    def add(self, remark: str, host: str, protocol: str, settings: dict, inbound: dict):
        if protocol == 'vmess':
            self.add_vmess(remark=remark,
                           address=host,
                           port=inbound['port'],
                           id=settings['id'],
                           net=inbound['stream']['net'],
                           tls=inbound['stream']['tls'],
                           sni=inbound['stream']['sni'],
                           host=inbound['stream']['host'],
                           path=inbound['stream']['path'])

        if protocol == 'trojan':
            self.add_trojan(remark=remark,
                            address=host,
                            port=inbound['port'],
                            password=settings['password'],
                            net=inbound['stream']['net'],
                            tls=inbound['stream']['tls'],
                            sni=inbound['stream']['sni'],
                            host=inbound['stream']['host'],
                            path=inbound['stream']['path'])

        if protocol == 'shadowsocks':
            self.add_shadowsocks(remark=remark,
                                 address=host,
                                 port=inbound['port'],
                                 password=settings['password'])

    def add_vmess(self,
                  remark: str,
                  address: str,
                  port: int,
                  id: Union[str, UUID],
                  host='',
                  net='tcp',
                  path='',
                  sni='',
                  tls=False):
        remark = self._remark_validation(remark)
        node = {'name': remark,
                'type': 'vmess',
                'server': address,
                'port': port,
                'uuid': id,
                'alterId': 0,
                'cipher': 'auto',
                'udp': True,
                f'{net}-opts': {
                    'path': path
                }}
        if tls is True:
            node.update({'tls': tls,
                         'servername': sni,
                         'network': net})
            node[f'{net}-opts']['headers'] = {'Host': host}
        self.data['proxies'].append(node)

    def add_trojan(self,
                   remark: str,
                   address: str,
                   port: int,
                   password: str,
                   net='tcp',
                   path='',
                   tls=False,
                   host='',
                   sni=''):
        remark = self._remark_validation(remark)
        self.data['proxies'].append({"name": remark,
                                     "type": "trojan",
                                     "server": address,
                                     "port": port,
                                     "password": password,
                                     "network": net,
                                     "udp": True,
                                     'sni': sni if tls else '',
                                     f'{net}-opts': {
                                         'path': path,
                                         'host': host
                                     }})

    def add_shadowsocks(self,
                        remark: str,
                        address: str,
                        port: int,
                        password: str,
                        security='chacha20-ietf-poly1305'):
        remark = self._remark_validation(remark)
        self.data['proxies'].append({'name': remark,
                                     'type': 'ss',
                                     'server': address,
                                     'port': port,
                                     'cipher': security,
                                     'password': password,
                                     'udp': True})


def get_v2ray_link(remark: str, host: str, protocol: str, settings: dict, inbound: dict):
    if protocol == 'vmess':
        return V2rayShareLink.vmess(remark=remark,
                                    address=host,
                                    port=inbound['port'],
                                    id=settings['id'],
                                    net=inbound['stream']['net'],
                                    tls=inbound['stream']['tls'],
                                    sni=inbound['stream']['sni'],
                                    host=inbound['stream']['host'],
                                    path=inbound['stream']['path'],
                                    type=inbound['stream']['header_type'])

    if protocol == 'vless':
        return V2rayShareLink.vless(remark=remark,
                                    address=host,
                                    port=inbound['port'],
                                    id=settings['id'],
                                    net=inbound['stream']['net'],
                                    tls=inbound['stream']['tls'],
                                    sni=inbound['stream']['sni'],
                                    host=inbound['stream']['host'],
                                    path=inbound['stream']['path'],
                                    type=inbound['stream']['header_type'])

    if protocol == 'trojan':
        return V2rayShareLink.trojan(remark=remark,
                                     address=host,
                                     port=inbound['port'],
                                     password=settings['password'],
                                     net=inbound['stream']['net'],
                                     tls=inbound['stream']['tls'],
                                     sni=inbound['stream']['sni'],
                                     host=inbound['stream']['host'],
                                     path=inbound['stream']['path'],
                                     type=inbound['stream']['header_type'])

    if protocol == 'shadowsocks':
        return V2rayShareLink.shadowsocks(remark=remark,
                                          address=host,
                                          port=inbound['port'],
                                          password=settings['password'])


def generate_v2ray_links(username: str, proxies: dict, inbounds: dict) -> list:
    links = []
    for protocol, settings in proxies.items():
        for inbound in filter(lambda i: i['tag'] in inbounds[protocol], INBOUNDS[protocol]):
            for host in XRAY_HOSTS:
                links.append(get_v2ray_link(remark=f"{host['remark']} ({username})",
                                            host=host['hostname'],
                                            protocol=protocol,
                                            settings=settings.dict(),
                                            inbound=inbound))

    return links


def generate_v2ray_subscription(links: list) -> str:
    return base64.b64encode('\n'.join(links).encode()).decode()


def generate_clash_subscription(username: str, proxies: dict, inbounds: dict) -> str:
    conf = ClashConfiguration()
    for protocol, settings in proxies.items():
        for inbound in filter(lambda i: i['tag'] in inbounds[protocol], INBOUNDS[protocol]):
            for host in XRAY_HOSTS:
                conf.add(
                    remark=host['remark'],
                    host=host['hostname'],
                    protocol=protocol,
                    settings=settings.dict(no_obj=True),
                    inbound=inbound
                )
    return conf.to_yaml()
