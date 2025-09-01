"""
Dynamic Feature Extractor for Android APK Banking Trojan Detection
Extracts dynamic features from sandbox traces, network logs, and system call traces.
Compatible with CIC-AndMal2017 dataset format.
"""

import pandas as pd
import numpy as np
import json
import re
import socket
import ipaddress
from typing import Dict, List, Optional
from collections import Counter
import os

# Suspicious domains and IPs (known C&C servers and malicious infrastructure)
SUSPICIOUS_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'duckdns.org', 'no-ip.com', 'ddns.net'
}

SUSPICIOUS_IPS = {
    '185.234.218.59', '45.77.88.99', '194.147.78.112', '91.240.118.172'
}

# Suspicious system calls commonly used by banking trojans
SUSPICIOUS_SYSCALLS = {
    'open', 'openat', 'read', 'write', 'socket', 'connect', 'sendto', 'recvfrom',
    'execve', 'fork', 'clone', 'ptrace', 'kill', 'tkill', 'tgkill'
}

# Banking-related API calls that indicate malicious behavior
MALICIOUS_API_PATTERNS = [
    r'.*getDeviceId.*', r'.*getSubscriberId.*', r'.*getLine1Number.*',
    r'.*sendTextMessage.*', r'.*getInstalledPackages.*', r'.*getRunningTasks.*',
    r'.*AccessibilityService.*', r'.*setAccessibilityServiceInfo.*',
    r'.*addJavascriptInterface.*', r'.*loadUrl.*', r'.*Runtime\.exec.*',
    r'.*DexClassLoader.*', r'.*PathClassLoader.*', r'.*System\.loadLibrary.*'
]

def extract_network_features(network_log_path: str) -> Dict:
    """
    Extract network-based dynamic features from network traffic logs.
    Expected format: CSV with columns [timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, domain]
    """
    features = {}
    
    if not os.path.exists(network_log_path):
        # Return default values if no network log exists
        return {
            'unique_domains': 0, 'total_bytes_out': 0, 'total_bytes_in': 0,
            'avg_bytes_per_conn': 0, 'suspicious_domain_hits': 0,
            'suspicious_ip_hits': 0, 'unique_dst_ips': 0, 'unique_src_ports': 0,
            'http_connections': 0, 'https_connections': 0, 'dns_queries': 0,
            'tcp_connections': 0, 'udp_connections': 0, 'connection_duration_avg': 0
        }
    
    try:
        df = pd.read_csv(network_log_path)
        
        if df.empty:
            return {
                'unique_domains': 0, 'total_bytes_out': 0, 'total_bytes_in': 0,
                'avg_bytes_per_conn': 0, 'suspicious_domain_hits': 0,
                'suspicious_ip_hits': 0, 'unique_dst_ips': 0, 'unique_src_ports': 0,
                'http_connections': 0, 'https_connections': 0, 'dns_queries': 0,
                'tcp_connections': 0, 'udp_connections': 0, 'connection_duration_avg': 0
            }
        
        # Basic network statistics
        features['unique_domains'] = df['domain'].nunique() if 'domain' in df.columns else 0
        features['total_bytes_out'] = df['bytes'].sum() if 'bytes' in df.columns else 0
        features['total_bytes_in'] = df['bytes'].sum() if 'bytes' in df.columns else 0
        features['avg_bytes_per_conn'] = df['bytes'].mean() if 'bytes' in df.columns else 0
        features['unique_dst_ips'] = df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0
        features['unique_src_ports'] = df['src_port'].nunique() if 'src_port' in df.columns else 0
        
        # Suspicious domain/IP detection
        if 'domain' in df.columns:
            suspicious_domains = df['domain'].apply(lambda x: any(sus in str(x) for sus in SUSPICIOUS_DOMAINS))
            features['suspicious_domain_hits'] = suspicious_domains.sum()
        else:
            features['suspicious_domain_hits'] = 0
            
        if 'dst_ip' in df.columns:
            suspicious_ips = df['dst_ip'].apply(lambda x: str(x) in SUSPICIOUS_IPS)
            features['suspicious_ip_hits'] = suspicious_ips.sum()
        else:
            features['suspicious_ip_hits'] = 0
        
        # Protocol analysis
        if 'protocol' in df.columns:
            protocol_counts = df['protocol'].value_counts()
            features['tcp_connections'] = protocol_counts.get('TCP', 0)
            features['udp_connections'] = protocol_counts.get('UDP', 0)
            features['http_connections'] = protocol_counts.get('HTTP', 0)
            features['https_connections'] = protocol_counts.get('HTTPS', 0)
            features['dns_queries'] = protocol_counts.get('DNS', 0)
        else:
            features.update({
                'tcp_connections': 0, 'udp_connections': 0, 'http_connections': 0,
                'https_connections': 0, 'dns_queries': 0
            })
        
        # Connection duration analysis
        if 'timestamp' in df.columns and len(df) > 1:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            duration = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            features['connection_duration_avg'] = duration / len(df) if len(df) > 0 else 0
        else:
            features['connection_duration_avg'] = 0
            
    except Exception as e:
        print(f"Error processing network log {network_log_path}: {e}")
        # Return default values on error
        features = {
            'unique_domains': 0, 'total_bytes_out': 0, 'total_bytes_in': 0,
            'avg_bytes_per_conn': 0, 'suspicious_domain_hits': 0,
            'suspicious_ip_hits': 0, 'unique_dst_ips': 0, 'unique_src_ports': 0,
            'http_connections': 0, 'https_connections': 0, 'dns_queries': 0,
            'tcp_connections': 0, 'udp_connections': 0, 'connection_duration_avg': 0
        }
    
    return features

def extract_api_trace_features(api_trace_path: str) -> Dict:
    """
    Extract features from API call traces.
    Expected format: CSV with columns [timestamp, api_name, parameters, return_value]
    """
    features = {}
    
    if not os.path.exists(api_trace_path):
        return {
            'total_api_calls': 0, 'unique_apis': 0, 'sensitive_api_runtime': 0,
            'reflection_calls': 0, 'crypto_calls': 0, 'file_operations': 0,
            'network_operations': 0, 'sms_operations': 0, 'contact_operations': 0,
            'location_operations': 0, 'camera_operations': 0, 'microphone_operations': 0
        }
    
    try:
        df = pd.read_csv(api_trace_path)
        
        if df.empty or 'api_name' not in df.columns:
            return {
                'total_api_calls': 0, 'unique_apis': 0, 'sensitive_api_runtime': 0,
                'reflection_calls': 0, 'crypto_calls': 0, 'file_operations': 0,
                'network_operations': 0, 'sms_operations': 0, 'contact_operations': 0,
                'location_operations': 0, 'camera_operations': 0, 'microphone_operations': 0
            }
        
        features['total_api_calls'] = len(df)
        features['unique_apis'] = df['api_name'].nunique()
        
        # Count sensitive API calls using regex patterns
        api_names = df['api_name'].astype(str)
        features['sensitive_api_runtime'] = sum(
            api_names.str.contains(pattern, case=False, na=False).sum()
            for pattern in MALICIOUS_API_PATTERNS
        )
        
        # Specific API categories
        features['reflection_calls'] = api_names.str.contains(
            r'.*(reflect|invoke|getMethod|getClass).*', case=False, na=False
        ).sum()
        
        features['crypto_calls'] = api_names.str.contains(
            r'.*(cipher|encrypt|decrypt|hash|MessageDigest|SecureRandom).*', case=False, na=False
        ).sum()
        
        features['file_operations'] = api_names.str.contains(
            r'.*(FileInputStream|FileOutputStream|openFileOutput|openFileInput).*', case=False, na=False
        ).sum()
        
        features['network_operations'] = api_names.str.contains(
            r'.*(HttpURLConnection|Socket|connect|sendto|recvfrom).*', case=False, na=False
        ).sum()
        
        features['sms_operations'] = api_names.str.contains(
            r'.*(sendTextMessage|SmsManager|getInboxSms).*', case=False, na=False
        ).sum()
        
        features['contact_operations'] = api_names.str.contains(
            r'.*(ContactsContract|getContacts|insertContact).*', case=False, na=False
        ).sum()
        
        features['location_operations'] = api_names.str.contains(
            r'.*(LocationManager|getLastKnownLocation|requestLocationUpdates).*', case=False, na=False
        ).sum()
        
        features['camera_operations'] = api_names.str.contains(
            r'.*(Camera|takePicture|startPreview).*', case=False, na=False
        ).sum()
        
        features['microphone_operations'] = api_names.str.contains(
            r'.*(AudioRecord|MediaRecorder|startRecording).*', case=False, na=False
        ).sum()
        
    except Exception as e:
        print(f"Error processing API trace {api_trace_path}: {e}")
        features = {
            'total_api_calls': 0, 'unique_apis': 0, 'sensitive_api_runtime': 0,
            'reflection_calls': 0, 'crypto_calls': 0, 'file_operations': 0,
            'network_operations': 0, 'sms_operations': 0, 'contact_operations': 0,
            'location_operations': 0, 'camera_operations': 0, 'microphone_operations': 0
        }
    
    return features

def extract_syscall_features(syscall_trace_path: str) -> Dict:
    """
    Extract features from system call traces.
    Expected format: CSV with columns [timestamp, syscall, pid, parameters, return_value]
    """
    features = {}
    
    if not os.path.exists(syscall_trace_path):
        return {
            'total_syscalls': 0, 'unique_syscalls': 0, 'suspicious_syscalls': 0,
            'file_syscalls': 0, 'network_syscalls': 0, 'process_syscalls': 0,
            'memory_syscalls': 0, 'ipc_syscalls': 0
        }
    
    try:
        df = pd.read_csv(syscall_trace_path)
        
        if df.empty or 'syscall' not in df.columns:
            return {
                'total_syscalls': 0, 'unique_syscalls': 0, 'suspicious_syscalls': 0,
                'file_syscalls': 0, 'network_syscalls': 0, 'process_syscalls': 0,
                'memory_syscalls': 0, 'ipc_syscalls': 0
            }
        
        features['total_syscalls'] = len(df)
        features['unique_syscalls'] = df['syscall'].nunique()
        
        syscalls = df['syscall'].astype(str)
        
        # Count suspicious system calls
        features['suspicious_syscalls'] = sum(
            syscalls.str.contains(f'^{syscall}$', case=False, na=False).sum()
            for syscall in SUSPICIOUS_SYSCALLS
        )
        
        # Categorize system calls
        features['file_syscalls'] = syscalls.str.contains(
            r'^(open|openat|read|write|close|stat|fstat|lstat|access)$', case=False, na=False
        ).sum()
        
        features['network_syscalls'] = syscalls.str.contains(
            r'^(socket|connect|bind|listen|accept|send|recv|sendto|recvfrom)$', case=False, na=False
        ).sum()
        
        features['process_syscalls'] = syscalls.str.contains(
            r'^(fork|clone|execve|exit|wait|kill|tkill|tgkill)$', case=False, na=False
        ).sum()
        
        features['memory_syscalls'] = syscalls.str.contains(
            r'^(mmap|munmap|mprotect|brk|sbrk)$', case=False, na=False
        ).sum()
        
        features['ipc_syscalls'] = syscalls.str.contains(
            r'^(pipe|msgget|semget|shmget|mq_open)$', case=False, na=False
        ).sum()
        
    except Exception as e:
        print(f"Error processing syscall trace {syscall_trace_path}: {e}")
        features = {
            'total_syscalls': 0, 'unique_syscalls': 0, 'suspicious_syscalls': 0,
            'file_syscalls': 0, 'network_syscalls': 0, 'process_syscalls': 0,
            'memory_syscalls': 0, 'ipc_syscalls': 0
        }
    
    return features

def extract_dynamic_features(sample_id: str, traces_directory: str) -> Dict:
    """
    Extract comprehensive dynamic features for a sample.
    
    Args:
        sample_id: Unique identifier for the sample (e.g., SHA256 hash)
        traces_directory: Directory containing trace files
        
    Returns:
        Dictionary of dynamic features
    """
    # Expected trace file paths
    network_log = os.path.join(traces_directory, f"{sample_id}_network.csv")
    api_trace = os.path.join(traces_directory, f"{sample_id}_api.csv")
    syscall_trace = os.path.join(traces_directory, f"{sample_id}_syscall.csv")
    
    # Extract features from each trace type
    network_features = extract_network_features(network_log)
    api_features = extract_api_trace_features(api_trace)
    syscall_features = extract_syscall_features(syscall_trace)
    
    # Combine all dynamic features
    dynamic_features = {
        'sample_id': sample_id,
        **network_features,
        **api_features,
        **syscall_features
    }
    
    # Calculate composite features
    dynamic_features['total_dynamic_activity'] = (
        dynamic_features['total_api_calls'] + 
        dynamic_features['total_syscalls'] + 
        dynamic_features['unique_domains']
    )
    
    dynamic_features['malicious_behavior_score'] = (
        dynamic_features['sensitive_api_runtime'] * 2 +
        dynamic_features['suspicious_syscalls'] * 1.5 +
        dynamic_features['suspicious_domain_hits'] * 3 +
        dynamic_features['suspicious_ip_hits'] * 3
    )
    
    return dynamic_features

def create_mock_dynamic_features(sample_id: str) -> Dict:
    """
    Create mock dynamic features for samples without trace data.
    This simulates realistic dynamic behavior patterns.
    """
    np.random.seed(hash(sample_id) % 2**32)  # Deterministic randomness based on sample_id
    
    # Generate realistic ranges for different feature types
    features = {
        'sample_id': sample_id,
        'unique_domains': np.random.randint(0, 50),
        'total_bytes_out': np.random.randint(1000, 1000000),
        'total_bytes_in': np.random.randint(1000, 1000000),
        'avg_bytes_per_conn': np.random.randint(100, 10000),
        'suspicious_domain_hits': np.random.randint(0, 5),
        'suspicious_ip_hits': np.random.randint(0, 3),
        'unique_dst_ips': np.random.randint(1, 30),
        'unique_src_ports': np.random.randint(1, 20),
        'http_connections': np.random.randint(0, 100),
        'https_connections': np.random.randint(0, 50),
        'dns_queries': np.random.randint(5, 200),
        'tcp_connections': np.random.randint(10, 150),
        'udp_connections': np.random.randint(0, 50),
        'connection_duration_avg': np.random.uniform(0.1, 30.0),
        'total_api_calls': np.random.randint(100, 5000),
        'unique_apis': np.random.randint(20, 200),
        'sensitive_api_runtime': np.random.randint(0, 50),
        'reflection_calls': np.random.randint(0, 20),
        'crypto_calls': np.random.randint(0, 30),
        'file_operations': np.random.randint(10, 200),
        'network_operations': np.random.randint(5, 100),
        'sms_operations': np.random.randint(0, 10),
        'contact_operations': np.random.randint(0, 15),
        'location_operations': np.random.randint(0, 10),
        'camera_operations': np.random.randint(0, 5),
        'microphone_operations': np.random.randint(0, 5),
        'total_syscalls': np.random.randint(500, 10000),
        'unique_syscalls': np.random.randint(50, 300),
        'suspicious_syscalls': np.random.randint(0, 100),
        'file_syscalls': np.random.randint(50, 500),
        'network_syscalls': np.random.randint(10, 200),
        'process_syscalls': np.random.randint(5, 100),
        'memory_syscalls': np.random.randint(20, 300),
        'ipc_syscalls': np.random.randint(0, 50)
    }
    
    # Calculate composite features
    features['total_dynamic_activity'] = (
        features['total_api_calls'] + 
        features['total_syscalls'] + 
        features['unique_domains']
    )
    
    features['malicious_behavior_score'] = (
        features['sensitive_api_runtime'] * 2 +
        features['suspicious_syscalls'] * 1.5 +
        features['suspicious_domain_hits'] * 3 +
        features['suspicious_ip_hits'] * 3
    )
    
    return features

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) != 3:
        print("Usage: python dynamic_feature_extractor.py <sample_id> <traces_directory>")
        print("Example: python dynamic_feature_extractor.py abc123def456 ./traces/")
        sys.exit(1)
    
    sample_id = sys.argv[1]
    traces_dir = sys.argv[2]
    
    features = extract_dynamic_features(sample_id, traces_dir)
    print(json.dumps(features, indent=2))
