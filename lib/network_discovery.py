#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Network Discovery Module
April 12, 2013 - Automated network host and service discovery
Python 2.7 compatible network discovery for security auditing
"""

import os
import sys
import socket
import subprocess
import threading
import time
from datetime import datetime
import netaddr
import nmap


class NetworkDiscoveryError(Exception):
    """Custom exception for network discovery errors"""
    pass


class NetworkDiscoveryEngine(object):
    """
    Network discovery engine for security auditing
    Discovers live hosts, services, and network topology
    """
    
    def __init__(self, timeout=30, max_threads=20):
        """
        Initialize network discovery engine
        
        Args:
            timeout (int): Discovery timeout in seconds
            max_threads (int): Maximum concurrent discovery threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        
        # Initialize Nmap scanner
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise NetworkDiscoveryError("Failed to initialize Nmap: %s" % str(e))
        
        # Discovery results storage
        self.discovered_hosts = {}
        self.discovery_stats = {
            'total_ips_scanned': 0,
            'live_hosts_found': 0,
            'services_discovered': 0,
            'scan_start_time': None,
            'scan_end_time': None
        }
        
        # Thread synchronization
        self.thread_lock = threading.Lock()
        
        # Common service ports for discovery (2013 era)
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            993,   # IMAPS
            995,   # POP3S
            1433,  # SQL Server
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            8080,  # HTTP Alt
            8443   # HTTPS Alt
        ]
    
    def discover_network_range(self, network_range, discovery_type='ping'):
        """
        Discover hosts in network range
        
        Args:
            network_range (str): Network range in CIDR notation (e.g., '192.168.1.0/24')
            discovery_type (str): Type of discovery ('ping', 'tcp', 'comprehensive')
            
        Returns:
            dict: Discovery results with host information
        """
        if discovery_type not in ['ping', 'tcp', 'comprehensive']:
            raise NetworkDiscoveryError("Invalid discovery type: %s" % discovery_type)
        
        # Validate network range
        try:
            network = netaddr.IPNetwork(network_range)
        except netaddr.AddrFormatError as e:
            raise NetworkDiscoveryError("Invalid network range: %s" % str(e))
        
        print "Starting %s discovery for network: %s" % (discovery_type, network_range)
        self.discovery_stats['scan_start_time'] = datetime.now()
        
        # Clear previous results
        self.discovered_hosts = {}
        self.discovery_stats['total_ips_scanned'] = len(list(network))
        
        try:
            if discovery_type == 'ping':
                self._ping_discovery(network)
            elif discovery_type == 'tcp':
                self._tcp_discovery(network)
            elif discovery_type == 'comprehensive':
                self._comprehensive_discovery(network)
            
            self.discovery_stats['scan_end_time'] = datetime.now()
            self.discovery_stats['live_hosts_found'] = len(self.discovered_hosts)
            
            # Calculate total services discovered
            total_services = 0
            for host_info in self.discovered_hosts.values():
                total_services += len(host_info.get('services', {}))
            self.discovery_stats['services_discovered'] = total_services
            
            print "Discovery completed: %d live hosts found" % self.discovery_stats['live_hosts_found']
            
            return {
                'hosts': self.discovered_hosts,
                'statistics': self.discovery_stats,
                'network_range': network_range,
                'discovery_type': discovery_type
            }
            
        except Exception as e:
            raise NetworkDiscoveryError("Discovery failed: %s" % str(e))
    
    def _ping_discovery(self, network):
        """Ping-based host discovery"""
        print "Performing ping discovery..."
        
        # Use Nmap for ping discovery
        nm_args = '-sn -PE -PP -PM'  # Ping scan with ICMP echo, timestamp, and netmask
        
        try:
            self.nm.scan(str(network), arguments=nm_args)
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip_address': host,
                        'status': 'up',
                        'discovery_method': 'ping',
                        'hostname': self._resolve_hostname(host),
                        'mac_address': self._get_mac_address(host),
                        'vendor': self._get_vendor_info(host),
                        'services': {},
                        'os_info': {},
                        'discovery_time': datetime.now().isoformat()
                    }
                    
                    with self.thread_lock:
                        self.discovered_hosts[host] = host_info
                        
        except Exception as e:
            print "Ping discovery error: %s" % str(e)
    
    def _tcp_discovery(self, network):
        """TCP connect discovery on common ports"""
        print "Performing TCP discovery on common ports..."
        
        # Convert common ports to string for Nmap
        port_list = ','.join(map(str, self.common_ports))
        
        try:
            # TCP SYN scan on common ports
            nm_args = '-sS -O --version-detection'
            self.nm.scan(str(network), ports=port_list, arguments=nm_args)
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip_address': host,
                        'status': 'up',
                        'discovery_method': 'tcp',
                        'hostname': self._resolve_hostname(host),
                        'mac_address': self._get_mac_address(host),
                        'vendor': self._get_vendor_info(host),
                        'services': self._extract_services(host),
                        'os_info': self._extract_os_info(host),
                        'discovery_time': datetime.now().isoformat()
                    }
                    
                    with self.thread_lock:
                        self.discovered_hosts[host] = host_info
                        
        except Exception as e:
            print "TCP discovery error: %s" % str(e)
    
    def _comprehensive_discovery(self, network):
        """Comprehensive discovery with OS detection and service enumeration"""
        print "Performing comprehensive discovery..."
        
        try:
            # Comprehensive scan with OS detection, version detection, and script scanning
            nm_args = '-sS -O -sV -sC --traceroute'
            port_range = '1-1000'  # Scan first 1000 ports
            
            self.nm.scan(str(network), ports=port_range, arguments=nm_args)
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip_address': host,
                        'status': 'up',
                        'discovery_method': 'comprehensive',
                        'hostname': self._resolve_hostname(host),
                        'mac_address': self._get_mac_address(host),
                        'vendor': self._get_vendor_info(host),
                        'services': self._extract_services(host),
                        'os_info': self._extract_os_info(host),
                        'traceroute': self._extract_traceroute(host),
                        'scripts': self._extract_script_results(host),
                        'discovery_time': datetime.now().isoformat()
                    }
                    
                    with self.thread_lock:
                        self.discovered_hosts[host] = host_info
                        
        except Exception as e:
            print "Comprehensive discovery error: %s" % str(e)
    
    def _resolve_hostname(self, ip_address):
        """Resolve hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _get_mac_address(self, ip_address):
        """Extract MAC address from Nmap results"""
        try:
            if 'addresses' in self.nm[ip_address]:
                return self.nm[ip_address]['addresses'].get('mac', None)
        except:
            pass
        return None
    
    def _get_vendor_info(self, ip_address):
        """Extract vendor information from Nmap results"""
        try:
            if 'vendor' in self.nm[ip_address]:
                vendors = self.nm[ip_address]['vendor']
                if vendors:
                    # Return first vendor info
                    return vendors.values()[0] if vendors.values() else None
        except:
            pass
        return None
    
    def _extract_services(self, ip_address):
        """Extract service information from Nmap scan"""
        services = {}
        
        try:
            for protocol in self.nm[ip_address].all_protocols():
                ports = self.nm[ip_address][protocol].keys()
                
                for port in ports:
                    port_info = self.nm[ip_address][protocol][port]
                    
                    service_info = {
                        'port': port,
                        'protocol': protocol,
                        'state': port_info.get('state', 'unknown'),
                        'name': port_info.get('name', 'unknown'),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'confidence': port_info.get('conf', '0')
                    }
                    
                    services['%s/%d' % (protocol, port)] = service_info
                    
        except Exception as e:
            print "Error extracting services for %s: %s" % (ip_address, str(e))
        
        return services
    
    def _extract_os_info(self, ip_address):
        """Extract OS information from Nmap scan"""
        os_info = {}
        
        try:
            if 'osmatch' in self.nm[ip_address]:
                os_matches = self.nm[ip_address]['osmatch']
                
                if os_matches:
                    best_match = os_matches[0]
                    os_info = {
                        'name': best_match.get('name', 'Unknown'),
                        'accuracy': best_match.get('accuracy', '0'),
                        'line': best_match.get('line', ''),
                        'osclass': best_match.get('osclass', [])
                    }
                    
        except Exception as e:
            print "Error extracting OS info for %s: %s" % (ip_address, str(e))
        
        return os_info
    
    def _extract_traceroute(self, ip_address):
        """Extract traceroute information from Nmap scan"""
        traceroute_info = []
        
        try:
            if 'traceroute' in self.nm[ip_address]:
                traceroute_data = self.nm[ip_address]['traceroute']
                
                for hop in traceroute_data:
                    hop_info = {
                        'hop': hop.get('hop', ''),
                        'ipaddr': hop.get('ipaddr', ''),
                        'rtt': hop.get('rtt', ''),
                        'hostname': hop.get('host', '')
                    }
                    traceroute_info.append(hop_info)
                    
        except Exception as e:
            print "Error extracting traceroute for %s: %s" % (ip_address, str(e))
        
        return traceroute_info
    
    def _extract_script_results(self, ip_address):
        """Extract NSE script results from Nmap scan"""
        scripts = {}
        
        try:
            # Check for host scripts
            if 'hostscript' in self.nm[ip_address]:
                for script in self.nm[ip_address]['hostscript']:
                    script_id = script.get('id', 'unknown')
                    scripts[script_id] = {
                        'output': script.get('output', ''),
                        'elements': script.get('elements', {})
                    }
            
            # Check for port scripts
            for protocol in self.nm[ip_address].all_protocols():
                ports = self.nm[ip_address][protocol].keys()
                
                for port in ports:
                    port_info = self.nm[ip_address][protocol][port]
                    
                    if 'script' in port_info:
                        port_scripts = port_info['script']
                        for script_name, script_output in port_scripts.items():
                            script_key = '%s_%s_%d' % (script_name, protocol, port)
                            scripts[script_key] = {
                                'port': port,
                                'protocol': protocol,
                                'output': script_output
                            }
                            
        except Exception as e:
            print "Error extracting scripts for %s: %s" % (ip_address, str(e))
        
        return scripts
    
    def discover_single_host(self, ip_address, port_range='1-1000'):
        """
        Perform detailed discovery on single host
        
        Args:
            ip_address (str): Target IP address
            port_range (str): Port range to scan (e.g., '1-1000')
            
        Returns:
            dict: Detailed host information
        """
        print "Discovering single host: %s" % ip_address
        
        try:
            # Comprehensive single host scan
            nm_args = '-sS -O -sV -sC --traceroute'
            self.nm.scan(ip_address, ports=port_range, arguments=nm_args)
            
            if ip_address in self.nm.all_hosts():
                if self.nm[ip_address].state() == 'up':
                    host_info = {
                        'ip_address': ip_address,
                        'status': 'up',
                        'discovery_method': 'single_host_detailed',
                        'hostname': self._resolve_hostname(ip_address),
                        'mac_address': self._get_mac_address(ip_address),
                        'vendor': self._get_vendor_info(ip_address),
                        'services': self._extract_services(ip_address),
                        'os_info': self._extract_os_info(ip_address),
                        'traceroute': self._extract_traceroute(ip_address),
                        'scripts': self._extract_script_results(ip_address),
                        'discovery_time': datetime.now().isoformat()
                    }
                    
                    return host_info
                else:
                    return {
                        'ip_address': ip_address,
                        'status': 'down',
                        'discovery_time': datetime.now().isoformat()
                    }
            else:
                return {
                    'ip_address': ip_address,
                    'status': 'not_found',
                    'discovery_time': datetime.now().isoformat()
                }
                
        except Exception as e:
            raise NetworkDiscoveryError("Single host discovery failed: %s" % str(e))
    
    def get_discovery_summary(self):
        """
        Get summary of discovery results
        
        Returns:
            dict: Summary statistics and information
        """
        summary = {
            'total_hosts_discovered': len(self.discovered_hosts),
            'discovery_statistics': self.discovery_stats.copy(),
            'service_summary': {},
            'os_summary': {},
            'top_services': [],
            'security_concerns': []
        }
        
        # Analyze services
        service_counts = {}
        os_counts = {}
        security_issues = []
        
        for host_info in self.discovered_hosts.values():
            # Count services
            for service_key, service_info in host_info.get('services', {}).items():
                service_name = service_info.get('name', 'unknown')
                service_counts[service_name] = service_counts.get(service_name, 0) + 1
                
                # Check for potential security concerns
                if service_name in ['telnet', 'ftp', 'rsh', 'rlogin']:
                    security_issues.append({
                        'host': host_info['ip_address'],
                        'issue': 'Insecure service detected',
                        'service': service_name,
                        'port': service_info.get('port')
                    })
            
            # Count operating systems
            os_name = host_info.get('os_info', {}).get('name', 'Unknown')
            if os_name != 'Unknown':
                os_counts[os_name] = os_counts.get(os_name, 0) + 1
        
        summary['service_summary'] = service_counts
        summary['os_summary'] = os_counts
        summary['security_concerns'] = security_issues
        
        # Get top 10 services
        sorted_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)
        summary['top_services'] = sorted_services[:10]
        
        return summary
    
    def export_results(self, output_file=None, format='json'):
        """
        Export discovery results
        
        Args:
            output_file (str): Output filename (optional)
            format (str): Export format ('json', 'xml', 'csv')
            
        Returns:
            str: Exported data
        """
        export_data = {
            'discovery_results': {
                'hosts': self.discovered_hosts,
                'statistics': self.discovery_stats,
                'summary': self.get_discovery_summary()
            },
            'export_timestamp': datetime.now().isoformat(),
            'export_format': format
        }
        
        if format == 'json':
            import json
            exported_content = json.dumps(export_data, indent=2, sort_keys=True)
        else:
            # For 2013, primarily focus on JSON format
            exported_content = str(export_data)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(exported_content)
            except IOError as e:
                raise NetworkDiscoveryError("Failed to export results: %s" % str(e))
        
        return exported_content


# Test and example usage
if __name__ == '__main__':
    print "Network Discovery Engine Test - April 12, 2013"
    print "==============================================="
    
    # Create discovery engine
    discovery_engine = NetworkDiscoveryEngine(timeout=30, max_threads=10)
    
    try:
        # Test network range discovery
        print "Testing ping discovery on localhost..."
        
        # Use localhost range for testing
        test_network = '127.0.0.0/30'  # Small range for testing
        
        results = discovery_engine.discover_network_range(test_network, discovery_type='ping')
        
        print "\nDiscovery Results:"
        print "=================="
        print "Hosts discovered: %d" % len(results['hosts'])
        print "Scan duration: %s" % (
            results['statistics']['scan_end_time'] - results['statistics']['scan_start_time']
            if results['statistics']['scan_end_time'] else 'N/A'
        )
        
        # Display discovered hosts
        for ip, host_info in results['hosts'].items():
            print "\nHost: %s" % ip
            print "  Status: %s" % host_info['status']
            print "  Hostname: %s" % (host_info['hostname'] or 'N/A')
            print "  Discovery method: %s" % host_info['discovery_method']
            print "  Services: %d" % len(host_info['services'])
        
        # Get summary
        print "\nDiscovery Summary:"
        summary = discovery_engine.get_discovery_summary()
        print "  Total hosts: %d" % summary['total_hosts_discovered']
        print "  Top services: %s" % [s[0] for s in summary['top_services'][:3]]
        
        if summary['security_concerns']:
            print "  Security concerns: %d" % len(summary['security_concerns'])
        
        # Test export
        print "\nTesting export functionality..."
        exported_data = discovery_engine.export_results(format='json')
        print "Export completed (%d characters)" % len(exported_data)
        
        print "\nNetwork discovery test completed successfully!"
        
    except NetworkDiscoveryError as e:
        print "Discovery Error: %s" % str(e)
    except Exception as e:
        print "Unexpected error: %s" % str(e)