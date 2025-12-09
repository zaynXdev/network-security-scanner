import socket
import subprocess
import re
from threading import Thread
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
import platform


class SimplePortScanner:
    """Fallback port scanner for when nmap is not available"""

    def scan_port(self, target, port, timeout=1):
        """Scan a single port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Try to get service name
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = 'unknown'
                    return port, True, service
                return port, False, 'unknown'
        except:
            return port, False, 'unknown'

    def simple_scan(self, target, ports='1-1000', max_workers=50):
        """Simple TCP port scan"""
        try:
            # Parse port range
            if '-' in ports:
                start, end = map(int, ports.split('-'))
                port_list = list(range(start, end + 1))
            elif ',' in ports:
                port_list = [int(p.strip()) for p in ports.split(',')]
            else:
                port_list = [int(ports)]

            open_ports = []

            print(f"Scanning {target} on {len(port_list)} ports...")

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_port = {
                    executor.submit(self.scan_port, target, port): port
                    for port in port_list
                }

                for future in as_completed(future_to_port):
                    port, is_open, service = future.result()
                    if is_open:
                        open_ports.append({
                            'port': port,
                            'service': service,
                            'state': 'open',
                            'protocol': 'tcp'
                        })

            return {
                'target': target,
                'scan_type': 'tcp_connect',
                'ports': ports,
                'hosts': {
                    target: {
                        'hostname': socket.getfqdn(target),
                        'state': 'up',
                        'protocols': {
                            'tcp': {port_info['port']: port_info for port_info in open_ports}
                        }
                    }
                },
                'summary': {
                    'total_hosts': 1,
                    'up_hosts': 1,
                    'open_ports': len(open_ports)
                }
            }

        except Exception as e:
            return {'error': f'Simple scan failed: {str(e)}'}


class NetworkScanner:
    def __init__(self):
        self.nm = None
        self.simple_scanner = SimplePortScanner()
        self.nmap_available = self._check_nmap_availability()

    def _check_nmap_availability(self):
        """Check if nmap is available in the system"""
        try:
            import nmap
            # Try to find nmap in PATH
            result = subprocess.run(['nmap', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                self.nm = nmap.PortScanner()
                print("Nmap is available - using advanced scanning")
                return True
            else:
                print("Nmap not found in PATH - using simple scanner")
                return False
        except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
            print("Nmap not available - using simple TCP connect scanner")
            return False

    def validate_target(self, target: str) -> bool:
        """Validate the target IP/hostname"""
        try:
            # Remove common URL prefixes
            clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]
            socket.gethostbyname(clean_target)
            return True
        except socket.gaierror:
            return False

    def scan_target(self, target: str, scan_type: str = 'tcp', ports: str = '1-1000') -> Dict[str, Any]:
        """
        Scan target for open ports
        Returns: Dictionary with scan results
        """
        if not self.validate_target(target):
            return {'error': f'Invalid target: {target}'}

        # Clean target (remove http:// etc.)
        clean_target = target.replace('http://', '').replace('https://', '').split('/')[0]

        # Use simple scanner if nmap is not available
        if not self.nmap_available:
            return self.simple_scanner.simple_scan(clean_target, ports)

        # Use nmap if available
        try:
            scan_args = ''
            if scan_type == 'tcp_syn':
                scan_args = '-sS'
            elif scan_type == 'udp':
                scan_args = '-sU'
            elif scan_type == 'full_connect':
                scan_args = '-sT'
            else:
                scan_args = '-sS'  # Default to SYN scan

            print(f"Scanning {clean_target} with nmap (args: {scan_args}) on ports {ports}")

            # Perform the scan
            self.nm.scan(hosts=clean_target, arguments=f'{scan_args} -p {ports}')

            results = {
                'target': clean_target,
                'scan_type': scan_type,
                'ports': ports,
                'hosts': {},
                'summary': {
                    'total_hosts': len(self.nm.all_hosts()),
                    'up_hosts': 0,
                    'open_ports': 0
                }
            }

            for host in self.nm.all_hosts():
                host_info = {
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'protocols': {}
                }

                for proto in self.nm[host].all_protocols():
                    ports_info = self.nm[host][proto]
                    host_info['protocols'][proto] = {}

                    for port, port_info in ports_info.items():
                        if port_info['state'] == 'open':
                            results['summary']['open_ports'] += 1
                            host_info['protocols'][proto][port] = {
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            }

                if host_info['state'] == 'up':
                    results['summary']['up_hosts'] += 1

                results['hosts'][host] = host_info

            return results

        except Exception as e:
            return {'error': f'Scan failed: {str(e)}'}

    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform a quick scan on common ports"""
        common_ports = '21,22,23,25,53,80,110,143,443,993,995,3389,5432,3306,27017'
        return self.scan_target(target, 'tcp_syn', common_ports)

    def ping_sweep(self, network: str) -> Dict[str, Any]:
        """Perform a ping sweep to discover hosts"""
        try:
            if self.nmap_available:
                self.nm.scan(hosts=network, arguments='-sn')
                hosts = []
                for host in self.nm.all_hosts():
                    hosts.append({
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'state': self.nm[host].state()
                    })
                return {'network': network, 'hosts': hosts}
            else:
                return {'error': 'Ping sweep requires nmap'}
        except Exception as e:
            return {'error': f'Ping sweep failed: {str(e)}'}