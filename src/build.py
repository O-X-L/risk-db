from ipaddress import IPv4Address, AddressValueError

from mmdb_writer import MMDBWriter
from netaddr import IPSet
from netaddr.ip import IPNetwork

from config import *
from util import log
from enrich_data import ip_asn_info
from write import write_ip_asn, write_nets


def build_dbs_ip_asn(reports: dict, ptrs: dict, lookup_lists: dict, networks: dict):
    for key, ip_list in {
        'all': reports['all'],
        'med': reports['med'],
        'high': reports['high'],
    }.items():
        log(f"Processing type '{key}'")

        mmdb4 = MMDBWriter(ip_version=4, description=MMDB_DESCRIPTION)
        mmdb6 = MMDBWriter(ip_version=6, description=MMDB_DESCRIPTION)
        json4 = {}
        json6 = {}
        asn_reports = {}

        for ip, reports in ip_list.items():
            if reports['all'] < MIN_IP_REPORTS:
                continue

            asn_info = ip_asn_info(
                ip=ip,
                reports=reports,
                ptrs=ptrs,
                lookup_lists=lookup_lists,
            )
            net = {'network': networks[key][networks['ip_to_net'][ip]]}
            net_sm = {'network': {
                'reported_ips': net['network']['reported_ips'],
                'reputation': net['network']['reputation'],
            }}
            asn = asn_info['nr']
            ipset = IPSet(IPNetwork(ip))

            try:
                IPv4Address(ip)
                mmdb4.insert_network(ipset, {**asn_info['full'], **net})

                if asn not in json4:
                    json4[asn] = {}

                json4[asn][ip] = {**asn_info['small'], **net_sm}

            except AddressValueError:
                mmdb6.insert_network(ipset, {**asn_info['full'], **net})

                if asn not in json6:
                    json6[asn] = {}

                json6[asn][ip] = {**asn_info['small'], **net_sm}

            if asn not in asn_reports:
                try:
                    asn_data = lookup_lists['asn'][str(asn)]
                    asn_reports[asn] = {
                        'reports': reports,
                        'kind': {
                            'hosting': asn in lookup_lists['hosting'],
                            'vpn': asn in lookup_lists['vpn'],
                            'proxy': asn in lookup_lists['proxy'],
                            'scanner': asn in lookup_lists['scanner'],
                        },
                        'info': {
                            'name': asn_data['info']['name'] if 'name' in asn_data['info'] else None,
                            'org': {
                                'name': asn_data['organization']['name'] if 'name' in asn_data['organization'] else None,
                                'country': asn_data['organization']['country'] if 'country' in asn_data['organization'] else None,
                                'state': asn_data['organization']['state'] if 'state' in asn_data['organization'] else None,
                                'website': asn_data['info']['website'] if 'website' in asn_data['info'] else None,
                            },
                            'ipv4': sum((2 ** (32 - int(net_cidr.split('/', 1)[1]))) for net_cidr in asn_data['ipv4']),
                            'ipv6': sum((2 ** (128 - int(net_cidr.split('/', 1)[1]))) for net_cidr in asn_data['ipv6']),
                            'contacts': asn_data['contacts'],
                            'url': {
                                'oxl_geoip': f'https://geoip.oxl.app/api/asn/{asn}',
                                'ipinfo': f'https://ipinfo.io/AS{asn}',
                                'shodan': f'https://www.shodan.io/search?query=asn%3A%22AS{asn}%22',
                            },
                        }
                    }

                    if not asn_reports[asn]['kind']['hosting']:
                        asn_info = str(asn_reports[asn]['info']['org']).lower()
                        if asn_info.find('cloud') != -1 or asn_info.find('hosting') != -1:
                            asn_reports[asn]['kind']['hosting'] = True

                except KeyError as e:
                    print(f'ERROR: Failed to lookup metadata of ASN {asn} ({e})')
                    asn_reports[asn] = {'reports': reports}

            else:
                for report_type, report_count in reports.items():
                    if report_type not in asn_reports[asn]['reports']:
                        asn_reports[asn]['reports'][report_type] = 0

                    asn_reports[asn]['reports'][report_type] += report_count

        # todo: score relative by IP and separate ip4/6
        for asn in asn_reports:
            rel_by_ip4 = round(
                asn_reports[asn]['reports']['all'] / (asn_reports[asn]['info']['ipv4'] + 1),
                5
            )
            if str(rel_by_ip4).find('-') != -1:
                asn_reports[asn]['reports']['rel_by_ip4'] = 0.0

            else:
                asn_reports[asn]['reports']['rel_by_ip4'] = rel_by_ip4

        write_ip_asn(
            key=key,
            mmdb4=mmdb4,
            mmdb6=mmdb6,
            json4=json4,
            json6=json6,
            asn_reports=asn_reports,
        )


def build_dbs_net(networks: dict):
    for key, net_list in {
        'all': networks['all'],
        'med': networks['med'],
        'high': networks['high'],
    }.items():
        json4 = {}
        json6 = {}

        for n, nv in net_list.items():
            ipv = nv.pop('ipv')
            n = f"{n}/{BGP_NET_SIZE[ipv]}"
            if ipv =='4':
                json4[n] = nv

            else:
                json6[n] = nv

        write_nets(key=key, json6=json6, json4=json4)
