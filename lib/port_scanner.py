#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Advanced Port Scanning Engine
April 19, 2013 - High-performance port scanning for security audits
Python 2.7 compatible multi-threaded port scanner with stealth capabilities
"""

import os
import sys
import socket
import threading
import time
import random
import struct
from datetime import datetime
import nmap


class PortScannerError(Exception):
    """Custom exception for port scanning errors"""
    pass


class AdvancedPortScanner(object):
    """
    Advanced port scanning engine for security auditing
    Supports multiple scan types and stealth techniques
    """
    
    def __init__(self, max_threads=100, timeout=3, scan_delay=0):
        """
        Initialize port scanner
        
        Args:
            max_threads (int): Maximum concurrent scanning threads
            timeout (int): Socket timeout in seconds
            scan_delay (float): Delay between scans in seconds (for stealth)
        """
        self.max_threads = max_threads
        self.timeout = timeout
        self.scan_delay = scan_delay
        
        # Thread synchronization
        self.thread_lock = threading.Lock()
        self.thread_semaphore = threading.Semaphore(max_threads)
        
        # Scan results storage
        self.scan_results = {}
        self.scan_statistics = {
            'total_ports_scanned': 0,
            'open_ports_found': 0,
            'closed_ports_found': 0,
            'filtered_ports_found': 0,
            'scan_start_time': None,
            'scan_end_time': None,
            'scan_duration': 0
        }
        
        # Initialize Nmap for advanced scanning
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            print "Warning: Nmap not available for advanced scans: %s" % str(e)
            self.nm = None
        
        # Common port ranges and services (2013 era)
        self.port_ranges = {
            'top100': [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157],
            'top1000': list(range(1, 1001)),
            'all': list(range(1, 65536))
        }
        
        # Service fingerprints for common ports
        self.service_fingerprints = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql'
        }
    
    def scan_host_ports(self, target_host, ports=None, scan_type='tcp_connect'):
        """
        Scan ports on target host
        
        Args:
            target_host (str): Target IP address or hostname
            ports (list): List of ports to scan (default: top100)
            scan_type (str): Type of scan ('tcp_connect', 'tcp_syn', 'udp', 'stealth')
            
        Returns:
            dict: Scan results with port states and services
        """
        if ports is None:
            ports = self.port_ranges['top100']
        
        if scan_type not in ['tcp_connect', 'tcp_syn', 'udp', 'stealth', 'nmap_advanced']:
            raise PortScannerError("Invalid scan type: %s" % scan_type)
        
        print "Scanning %d ports on %s using %s method..." % (len(ports), target_host, scan_type)
        
        self.scan_statistics['scan_start_time'] = datetime.now()
        self.scan_statistics['total_ports_scanned'] = len(ports)
        
        # Clear previous results
        self.scan_results = {
            'target_host': target_host,
            'scan_type': scan_type,
            'ports': {},
            'scan_info': {
                'start_time': self.scan_statistics['scan_start_time'].isoformat(),
                'total_ports': len(ports)
            }
        }
        
        try:
            if scan_type == 'tcp_connect':
                self._tcp_connect_scan(target_host, ports)
            elif scan_type == 'tcp_syn':
                self._tcp_syn_scan(target_host, ports)
            elif scan_type == 'udp':
                self._udp_scan(target_host, ports)
            elif scan_type == 'stealth':
                self._stealth_scan(target_host, ports)
            elif scan_type == 'nmap_advanced':
                self._nmap_advanced_scan(target_host, ports)
            
            self.scan_statistics['scan_end_time'] = datetime.now()
            self.scan_statistics['scan_duration'] = (
                self.scan_statistics['scan_end_time'] - self.scan_statistics['scan_start_time']
            ).total_seconds()
            
            # Update scan statistics
            self._update_scan_statistics()
            
            self.scan_results['scan_info']['end_time'] = self.scan_statistics['scan_end_time'].isoformat()
            self.scan_results['scan_info']['duration'] = self.scan_statistics['scan_duration']
            self.scan_results['statistics'] = self.scan_statistics.copy()
            
            print "Scan completed: %d open ports found in %.2f seconds" % (
                self.scan_statistics['open_ports_found'],
                self.scan_statistics['scan_duration']
            )
            
            return self.scan_results
            
        except Exception as e:
            raise PortScannerError("Port scan failed: %s" % str(e))
    
    def _tcp_connect_scan(self, target_host, ports):
        """TCP connect scan using full three-way handshake"""
        print "Performing TCP connect scan..."
        
        def scan_port(port):
            self.thread_semaphore.acquire()
            try:
                if self.scan_delay > 0:
                    time.sleep(random.uniform(0, self.scan_delay))
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((target_host, port))
                
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open' if result == 0 else 'closed',
                    'service': self.service_fingerprints.get(port, 'unknown'),
                    'method': 'tcp_connect',
                    'scan_time': datetime.now().isoformat()
                }
                
                # Try to grab banner if port is open
                if result == 0:
                    try:
                        sock.send('HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024)
                        port_info['banner'] = banner.strip()[:200]  # Limit banner size
                    except:
                        port_info['banner'] = ''
                
                sock.close()
                
                with self.thread_lock:
                    self.scan_results['ports'][port] = port_info
                    
            except socket.gaierror:
                # Host resolution failed
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'filtered',
                    'service': 'unknown',
                    'method': 'tcp_connect',
                    'scan_time': datetime.now().isoformat(),
                    'error': 'host_resolution_failed'
                }
                
                with self.thread_lock:
                    self.scan_results['ports'][port] = port_info
                    
            except Exception as e:
                # Other errors (filtered, etc.)
                port_info = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'filtered',
                    'service': 'unknown',
                    'method': 'tcp_connect',
                    'scan_time': datetime.now().isoformat(),
                    'error': str(e)
                }
                
                with self.thread_lock:
                    self.scan_results['ports'][port] = port_info
                    
            finally:
                self.thread_semaphore.release()
        
        # Start threads for each port
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
    
    def _tcp_syn_scan(self, target_host, ports):
        """TCP SYN scan using raw sockets (requires root privileges)"""
        print "Performing TCP SYN scan (requires root privileges)..."
        
        # Note: Raw socket SYN scanning requires root privileges
        # For 2013 implementation, we'll use Nmap for SYN scanning
        if self.nm:
            try:
                port_list = ','.join(map(str, ports))
                self.nm.scan(target_host, ports=port_list, arguments='-sS')
                
                if target_host in self.nm.all_hosts():
                    for protocol in self.nm[target_host].all_protocols():
                        scanned_ports = self.nm[target_host][protocol].keys()
                        
                        for port in scanned_ports:
                            port_info = self.nm[target_host][protocol][port]
                            
                            scan_result = {
                                'port': port,
                                'protocol': protocol,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'method': 'tcp_syn',
                                'scan_time': datetime.now().isoformat(),
                                'reason': port_info.get('reason', '')
                            }
                            
                            with self.thread_lock:
                                self.scan_results['ports'][port] = scan_result
                else:
                    print "Host not responsive to SYN scan"
                    
            except Exception as e:
                print "SYN scan failed, falling back to connect scan: %s" % str(e)
                self._tcp_connect_scan(target_host, ports)
        else:
            print "Nmap not available, falling back to connect scan"
            self._tcp_connect_scan(target_host, ports)
    
    def _udp_scan(self, target_host, ports):
        """UDP port scan"""
        print "Performing UDP scan..."
        
        def scan_udp_port(port):
            self.thread_semaphore.acquire()
            try:
                if self.scan_delay > 0:
                    time.sleep(random.uniform(0, self.scan_delay))
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Send UDP probe
                try:
                    sock.sendto('probe', (target_host, port))
                    
                    # Try to receive response
                    try:
                        data, addr = sock.recvfrom(1024)
                        # Got response - port is open
                        state = 'open'
                        response = data[:100]  # Limit response size
                    except socket.timeout:
                        # No response - might be open or filtered
                        state = 'open|filtered'
                        response = ''
                        
                except socket.error as e:
                    # ICMP port unreachable - port is closed
                    if 'Connection refused' in str(e):
                        state = 'closed'
                    else:
                        state = 'filtered'
                    response = ''
                
                port_info = {
                    'port': port,
                    'protocol': 'udp',
                    'state': state,
                    'service': self.service_fingerprints.get(port, 'unknown'),
                    'method': 'udp_probe',
                    'scan_time': datetime.now().isoformat(),
                    'response': response
                }
                
                sock.close()
                
                with self.thread_lock:
                    self.scan_results['ports'][port] = port_info
                    
            except Exception as e:
                port_info = {
                    'port': port,
                    'protocol': 'udp',
                    'state': 'filtered',
                    'service': 'unknown',
                    'method': 'udp_probe',
                    'scan_time': datetime.now().isoformat(),
                    'error': str(e)
                }
                
                with self.thread_lock:
                    self.scan_results['ports'][port] = port_info
                    
            finally:
                self.thread_semaphore.release()
        
        # Start threads for UDP scanning
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_udp_port, args=(port,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for completion
        for thread in threads:
            thread.join()
    
    def _stealth_scan(self, target_host, ports):
        """Stealth scanning with randomized timing and techniques"""
        print "Performing stealth scan with randomized timing..."
        
        # Randomize port order for stealth
        randomized_ports = list(ports)
        random.shuffle(randomized_ports)
        
        # Use variable delays
        original_delay = self.scan_delay
        self.scan_delay = random.uniform(0.1, 2.0)  # Random delay between 0.1-2 seconds
        
        try:
            # Use TCP connect scan with stealth timing
            self._tcp_connect_scan(target_host, randomized_ports)
            
            # Add stealth indicators to results
            for port_info in self.scan_results['ports'].values():
                port_info['method'] = 'stealth_tcp'
                port_info['stealth_features'] = {
                    'randomized_order': True,
                    'variable_timing': True,
                    'delay_range': '0.1-2.0s'
                }
                
        finally:
            self.scan_delay = original_delay
    
    def _nmap_advanced_scan(self, target_host, ports):
        """Advanced scanning using Nmap with multiple techniques"""
        print "Performing advanced Nmap scan..."
        
        if not self.nm:
            raise PortScannerError("Nmap not available for advanced scanning")
        
        try:
            port_list = ','.join(map(str, ports))
            
            # Use comprehensive Nmap arguments for 2013
            nmap_args = '-sS -sV -O -A --version-all'
            
            self.nm.scan(target_host, ports=port_list, arguments=nmap_args)
            
            if target_host in self.nm.all_hosts():
                # Extract comprehensive port information
                for protocol in self.nm[target_host].all_protocols():
                    scanned_ports = self.nm[target_host][protocol].keys()
                    
                    for port in scanned_ports:
                        port_data = self.nm[target_host][protocol][port]
                        
                        scan_result = {
                            'port': port,
                            'protocol': protocol,
                            'state': port_data['state'],
                            'service': port_data.get('name', 'unknown'),
                            'product': port_data.get('product', ''),
                            'version': port_data.get('version', ''),
                            'extrainfo': port_data.get('extrainfo', ''),
                            'confidence': port_data.get('conf', ''),
                            'method': 'nmap_advanced',
                            'scan_time': datetime.now().isoformat(),
                            'reason': port_data.get('reason', ''),
                            'reason_ttl': port_data.get('reason_ttl', '')
                        }
                        
                        # Extract script results if available
                        if 'script' in port_data:
                            scan_result['scripts'] = port_data['script']
                        
                        with self.thread_lock:
                            self.scan_results['ports'][port] = scan_result
                
                # Extract OS information if available
                if 'osmatch' in self.nm[target_host]:
                    self.scan_results['os_detection'] = self.nm[target_host]['osmatch']
                    
            else:
                print "Host not found in Nmap results"
                
        except Exception as e:
            print "Advanced Nmap scan failed: %s" % str(e)
            # Fallback to basic scanning
            self._tcp_connect_scan(target_host, ports)
    
    def _update_scan_statistics(self):
        """Update scan statistics based on results"""
        open_count = 0
        closed_count = 0
        filtered_count = 0
        
        for port_info in self.scan_results['ports'].values():
            state = port_info['state']
            
            if state == 'open':
                open_count += 1
            elif state == 'closed':
                closed_count += 1
            else:
                filtered_count += 1
        
        self.scan_statistics['open_ports_found'] = open_count
        self.scan_statistics['closed_ports_found'] = closed_count
        self.scan_statistics['filtered_ports_found'] = filtered_count
    
    def scan_multiple_hosts(self, target_hosts, ports=None, scan_type='tcp_connect'):
        """
        Scan multiple hosts
        
        Args:
            target_hosts (list): List of target hosts
            ports (list): Ports to scan
            scan_type (str): Scan type
            
        Returns:
            dict: Results for all hosts
        """
        if ports is None:
            ports = self.port_ranges['top100']
        
        print "Scanning %d hosts with %d ports each..." % (len(target_hosts), len(ports))
        
        multi_host_results = {
            'scan_summary': {
                'total_hosts': len(target_hosts),
                'total_ports_per_host': len(ports),
                'scan_type': scan_type,
                'start_time': datetime.now().isoformat()
            },
            'host_results': {}
        }
        
        for host in target_hosts:
            try:
                print "Scanning host: %s" % host
                host_results = self.scan_host_ports(host, ports, scan_type)
                multi_host_results['host_results'][host] = host_results
                
            except Exception as e:
                print "Failed to scan host %s: %s" % (host, str(e))
                multi_host_results['host_results'][host] = {
                    'error': str(e),
                    'scan_time': datetime.now().isoformat()
                }
        
        multi_host_results['scan_summary']['end_time'] = datetime.now().isoformat()
        
        return multi_host_results
    
    def get_open_ports(self):
        """
        Get list of open ports from last scan
        
        Returns:
            list: List of open ports with details
        """
        open_ports = []
        
        for port_info in self.scan_results.get('ports', {}).values():
            if port_info['state'] == 'open':
                open_ports.append(port_info)
        
        # Sort by port number
        open_ports.sort(key=lambda x: x['port'])
        
        return open_ports
    
    def generate_scan_report(self, include_closed=False):
        """
        Generate comprehensive scan report
        
        Args:
            include_closed (bool): Include closed ports in report
            
        Returns:
            dict: Detailed scan report
        """
        open_ports = self.get_open_ports()
        
        report = {
            'scan_summary': {
                'target_host': self.scan_results.get('target_host'),
                'scan_type': self.scan_results.get('scan_type'),
                'total_ports_scanned': self.scan_statistics['total_ports_scanned'],
                'open_ports': self.scan_statistics['open_ports_found'],
                'closed_ports': self.scan_statistics['closed_ports_found'],
                'filtered_ports': self.scan_statistics['filtered_ports_found'],
                'scan_duration': self.scan_statistics['scan_duration']
            },
            'open_ports': open_ports,
            'security_analysis': self._analyze_security_implications(open_ports),
            'recommendations': self._generate_security_recommendations(open_ports)
        }
        
        if include_closed:
            closed_ports = [p for p in self.scan_results.get('ports', {}).values() 
                          if p['state'] in ['closed', 'filtered']]
            report['closed_filtered_ports'] = closed_ports
        
        return report
    
    def _analyze_security_implications(self, open_ports):
        """Analyze security implications of open ports"""
        security_analysis = {
            'high_risk_services': [],
            'insecure_protocols': [],
            'administrative_services': [],
            'web_services': [],
            'database_services': []
        }
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # High risk services
            if service in ['telnet', 'ftp', 'rsh', 'rlogin'] or port in [23, 21, 514, 513]:
                security_analysis['high_risk_services'].append(port_info)
            
            # Insecure protocols
            if service in ['telnet', 'ftp', 'http', 'snmp'] or port in [23, 21, 80, 161]:
                security_analysis['insecure_protocols'].append(port_info)
            
            # Administrative services
            if service in ['ssh', 'rdp', 'vnc'] or port in [22, 3389, 5900]:
                security_analysis['administrative_services'].append(port_info)
            
            # Web services
            if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                security_analysis['web_services'].append(port_info)
            
            # Database services
            if service in ['mysql', 'mssql', 'postgresql', 'oracle'] or port in [3306, 1433, 5432, 1521]:
                security_analysis['database_services'].append(port_info)
        
        return security_analysis
    
    def _generate_security_recommendations(self, open_ports):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Check for insecure services
        insecure_services = [p for p in open_ports if p['service'] in ['telnet', 'ftp', 'rsh']]
        if insecure_services:
            recommendations.append({
                'severity': 'high',
                'category': 'insecure_protocols',
                'recommendation': 'Replace insecure protocols (telnet, ftp, rsh) with secure alternatives (ssh, sftp)',
                'affected_ports': [p['port'] for p in insecure_services]
            })
        
        # Check for unnecessary services
        if len(open_ports) > 10:
            recommendations.append({
                'severity': 'medium',
                'category': 'service_reduction',
                'recommendation': 'Consider disabling unnecessary services to reduce attack surface',
                'affected_ports': 'multiple'
            })
        
        # Check for administrative services
        admin_services = [p for p in open_ports if p['service'] in ['ssh', 'rdp', 'vnc']]
        if admin_services:
            recommendations.append({
                'severity': 'medium',
                'category': 'administrative_access',
                'recommendation': 'Ensure administrative services are properly secured and access-controlled',
                'affected_ports': [p['port'] for p in admin_services]
            })
        
        return recommendations
    
    def export_scan_results(self, output_file=None, format='json'):
        """
        Export scan results to file
        
        Args:
            output_file (str): Output filename
            format (str): Export format ('json', 'xml', 'csv')
            
        Returns:
            str: Exported data
        """
        export_data = {
            'scan_results': self.scan_results,
            'scan_statistics': self.scan_statistics,
            'scan_report': self.generate_scan_report(),
            'export_timestamp': datetime.now().isoformat()
        }
        
        if format == 'json':
            import json
            exported_content = json.dumps(export_data, indent=2, sort_keys=True)
        else:
            exported_content = str(export_data)
        
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(exported_content)
            except IOError as e:
                raise PortScannerError("Failed to export results: %s" % str(e))
        
        return exported_content


# Test and example usage
if __name__ == '__main__':
    print "Advanced Port Scanner Test - April 19, 2013"
    print "==========================================="
    
    # Create port scanner
    scanner = AdvancedPortScanner(max_threads=50, timeout=2, scan_delay=0.1)
    
    try:
        # Test localhost scanning
        print "Testing port scan on localhost..."
        
        # Scan common ports on localhost
        test_ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        results = scanner.scan_host_ports('127.0.0.1', test_ports, scan_type='tcp_connect')
        
        print "\nScan Results:"
        print "============="
        print "Target: %s" % results['target_host']
        print "Scan type: %s" % results['scan_type']
        print "Duration: %.2f seconds" % results['scan_info']['duration']
        print "Ports scanned: %d" % len(test_ports)
        
        # Display open ports
        open_ports = scanner.get_open_ports()
        print "\nOpen Ports: %d" % len(open_ports)
        
        for port_info in open_ports:
            print "  Port %d/%s - %s (%s)" % (
                port_info['port'],
                port_info['protocol'],
                port_info['state'],
                port_info['service']
            )
        
        # Generate security report
        print "\nSecurity Analysis:"
        report = scanner.generate_scan_report()
        
        security_analysis = report['security_analysis']
        for category, services in security_analysis.items():
            if services:
                print "  %s: %d services" % (category.replace('_', ' ').title(), len(services))
        
        # Display recommendations
        recommendations = report['recommendations']
        if recommendations:
            print "\nSecurity Recommendations:"
            for rec in recommendations:
                print "  [%s] %s" % (rec['severity'].upper(), rec['recommendation'])
        
        # Test export functionality
        print "\nTesting export functionality..."
        exported_data = scanner.export_scan_results(format='json')
        print "Export completed (%d characters)" % len(exported_data)
        
        print "\nPort scanner test completed successfully!"
        
    except PortScannerError as e:
        print "Scanner Error: %s" % str(e)
    except Exception as e:
        print "Unexpected error: %s" % str(e)