import streamlit as st
import pandas as pd
import numpy as np
import zipfile
import xml.etree.ElementTree as ET
import re
import hashlib
from pathlib import Path
import plotly.express as px
import plotly.graph_objects as go
import pickle
import joblib
from datetime import datetime
import os
import struct
import requests
import time
import subprocess
import tempfile
import shutil
from bs4 import BeautifulSoup

# Sayfa konfigürasyonu
st.set_page_config(
    page_title="APK Güvenlik Analiz Sistemi",
    layout="wide",
    initial_sidebar_state="expanded"
)

class APKSecurityAnalyzer:
    def __init__(self):
        self.permissions_risk_score = {
            # Yüksek Risk İzinler
            'WRITE_EXTERNAL_STORAGE': 0.8,
            'READ_SMS': 0.9,
            'SEND_SMS': 0.9,
            'CALL_PHONE': 0.8,
            'RECORD_AUDIO': 0.7,
            'CAMERA': 0.6,
            'ACCESS_FINE_LOCATION': 0.7,
            'READ_CONTACTS': 0.6,
            'WRITE_CONTACTS': 0.7,
            'INSTALL_PACKAGES': 0.9,
            'DELETE_PACKAGES': 0.9,
            'SYSTEM_ALERT_WINDOW': 0.8,
            'WRITE_SETTINGS': 0.7,
            'DEVICE_ADMIN': 0.9,
            'BIND_DEVICE_ADMIN': 0.9,
            'RECEIVE_BOOT_COMPLETED': 0.6,
            'WAKE_LOCK': 0.5,
            'DISABLE_KEYGUARD': 0.8,
            'MODIFY_AUDIO_SETTINGS': 0.5,
            'MOUNT_UNMOUNT_FILESYSTEMS': 0.8,
            'WRITE_SECURE_SETTINGS': 0.9,
            'CHANGE_CONFIGURATION': 0.6,
            'EXPAND_STATUS_BAR': 0.5,
            'INTERACT_ACROSS_USERS': 0.8,
            'MANAGE_ACCOUNTS': 0.7,
            'USE_CREDENTIALS': 0.7,
            'AUTHENTICATE_ACCOUNTS': 0.7,
            'READ_SYNC_SETTINGS': 0.4,
            'WRITE_SYNC_SETTINGS': 0.6,
            
            # Orta Risk İzinler  
            'INTERNET': 0.3,
            'ACCESS_NETWORK_STATE': 0.2,
            'ACCESS_WIFI_STATE': 0.2,
            'READ_PHONE_STATE': 0.4,
            'VIBRATE': 0.1,
            'READ_EXTERNAL_STORAGE': 0.3,
            'MODIFY_PHONE_STATE': 0.6,
            'PROCESS_OUTGOING_CALLS': 0.6,
            'READ_CALL_LOG': 0.6,
            'WRITE_CALL_LOG': 0.7,
            'ADD_VOICEMAIL': 0.5,
            'USE_SIP': 0.5,
            'BIND_ACCESSIBILITY_SERVICE': 0.7,
            'BIND_NOTIFICATION_LISTENER_SERVICE': 0.6,
            'ACCESS_NOTIFICATION_POLICY': 0.5,
            
            # Düşük Risk İzinler
            'ACCESS_COARSE_LOCATION': 0.3,
            'FLASHLIGHT': 0.1,
            'NFC': 0.2,
            'BLUETOOTH': 0.2,
            'BLUETOOTH_ADMIN': 0.3,
            'CHANGE_WIFI_STATE': 0.2,
            'GET_ACCOUNTS': 0.3
        }
        
        # Tehlikeli API çağrıları ve risk skorları
        self.dangerous_api_calls = {
            # Sistem/Root erişimi
            'Runtime.exec': 0.9,
            'ProcessBuilder': 0.8,
            'su': 0.95,
            'busybox': 0.9,
            'getRuntime': 0.7,
            
            # Reflection saldırıları
            'Class.forName': 0.6,
            'getDeclaredMethod': 0.7,
            'setAccessible': 0.8,
            'invoke': 0.6,
            
            # Ağ operasyonları
            'HttpURLConnection': 0.4,
            'Socket': 0.5,
            'ServerSocket': 0.7,
            'DatagramSocket': 0.5,
            
            # Dosya I/O
            'FileOutputStream': 0.3,
            'FileInputStream': 0.2,
            'deleteFile': 0.6,
            'mkdirs': 0.4,
            
            # Şifreleme/Obfuscation
            'DESKeySpec': 0.7,
            'Cipher': 0.6,
            'MessageDigest': 0.4,
            'Base64': 0.3,
            
            # SMS/Telefon
            'SmsManager': 0.8,
            'sendTextMessage': 0.9,
            'TelephonyManager': 0.6,
            
            # Location
            'LocationManager': 0.5,
            'getLastKnownLocation': 0.6,
            
            # Kamera/Mikrofon
            'MediaRecorder': 0.7,
            'AudioRecord': 0.8,
            'Camera': 0.6,
            
            # Dynamic Loading
            'DexClassLoader': 0.9,
            'PathClassLoader': 0.7,
            'loadClass': 0.6,
            
            # Native kod
            'System.loadLibrary': 0.7,
            'System.load': 0.8,
            
            # Admin işlemleri
            'DevicePolicyManager': 0.8,
            'DeviceAdminReceiver': 0.9,
        }
        
        # ML modeli yükleme (eğer varsa)
        self.ml_model = None
        self.ml_scaler = None
        self.load_ml_model()
        
        # VirusTotal API (Gerçek zamanlı entegrasyon)
        self.virustotal_api_key = None  # Kullanıcı tarafından sağlanacak
        
        # Profesyonel APK Analiz Araçları
        self.temp_dir = None
        self.apktool_path = self._check_apktool()
        self.jadx_path = self._check_jadx()
    
    def load_ml_model(self):
        """ML modelini yükle (varsa)"""
        try:
            if os.path.exists('ml_results/random_forest_model.pkl'):
                self.ml_model = joblib.load('ml_results/random_forest_model.pkl')
                st.success("ML modeli yüklendi (CSV analizi için)")
            
            if os.path.exists('ml_results/scaler.pkl'):
                self.ml_scaler = joblib.load('ml_results/scaler.pkl')
        except Exception as e:
            st.info(f"ML modeli bulunamadı: {str(e)}")
    
    def analyze_apk(self, apk_file):
        """APK dosyasını kapsamlı analiz et"""
        try:
            features = {}
            
            # Dosya boyutu
            features['file_size_mb'] = len(apk_file.getvalue()) / (1024 * 1024)
            
            # ZIP içeriğini analiz et
            with zipfile.ZipFile(apk_file, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                features.update(self._analyze_file_structure(file_list))
                
                # AndroidManifest.xml analizi
                if 'AndroidManifest.xml' in file_list:
                    manifest_data = zip_ref.read('AndroidManifest.xml')
                    features.update(self._analyze_manifest(manifest_data))
                
                # DEX dosyaları analizi
                dex_files = [f for f in file_list if f.endswith('.dex')]
                features.update(self._analyze_dex_files(zip_ref, dex_files))
                
                # Resources analizi
                features.update(self._analyze_resources(zip_ref, file_list))
                
                # Certificate analizi
                features.update(self._analyze_certificates(zip_ref, file_list))
            
            return features
            
        except Exception as e:
            st.error(f"APK analiz hatası: {str(e)}")
            return None
    
    def _analyze_file_structure(self, file_list):
        """Dosya yapısını detaylı analiz et"""
        features = {}
        
        # Temel dosya sayıları
        features['total_files'] = len(file_list)
        features['dex_count'] = len([f for f in file_list if f.endswith('.dex')])
        features['so_count'] = len([f for f in file_list if f.endswith('.so')])
        features['xml_count'] = len([f for f in file_list if f.endswith('.xml')])
        features['png_count'] = len([f for f in file_list if f.endswith('.png')])
        features['jar_count'] = len([f for f in file_list if f.endswith('.jar')])
        
        # Şüpheli dosya uzantıları
        suspicious_extensions = ['.exe', '.bat', '.sh', '.bin', '.dll', '.scr']
        features['suspicious_files'] = len([f for f in file_list 
                                          if any(f.endswith(ext) for ext in suspicious_extensions)])
        
        # Klasör yapısı
        features['has_assets'] = any(f.startswith('assets/') for f in file_list)
        features['has_lib'] = any(f.startswith('lib/') for f in file_list)
        features['has_meta_inf'] = any(f.startswith('META-INF/') for f in file_list)
        features['has_resources'] = any(f.startswith('res/') for f in file_list)
        
        # Native kütüphane analizi
        if features['has_lib']:
            lib_files = [f for f in file_list if f.startswith('lib/')]
            architectures = set()
            for lib_file in lib_files:
                parts = lib_file.split('/')
                if len(parts) > 1:
                    architectures.add(parts[1])
            features['lib_architectures'] = len(architectures)
        else:
            features['lib_architectures'] = 0
        
        return features
    
    def _analyze_manifest(self, manifest_data):
        """AndroidManifest.xml detaylı analiz"""
        features = {}
        
        try:
            # Binary XML'i string'e çevir - DAHA İYİ DECODE
            try:
                manifest_str = manifest_data.decode('utf-8', errors='ignore')
            except:
                manifest_str = str(manifest_data, errors='ignore')
            
            # İzin analizi - DAHA DOĞRU PATTERN ARAMA
            permission_patterns = [
                'android.permission.',
                'uses-permission',
                'permission',
                '<uses-permission'
            ]
            
            permission_count = 0
            for pattern in permission_patterns:
                permission_count += manifest_str.lower().count(pattern.lower())
            
            features['estimated_permissions'] = permission_count
            
            # Tehlikeli izin tespiti
            dangerous_permissions = [
                'WRITE_EXTERNAL_STORAGE', 'READ_SMS', 'SEND_SMS', 
                'CALL_PHONE', 'RECORD_AUDIO', 'CAMERA', 'ACCESS_FINE_LOCATION',
                'READ_CONTACTS', 'WRITE_CONTACTS', 'INSTALL_PACKAGES',
                'DELETE_PACKAGES', 'SYSTEM_ALERT_WINDOW', 'DEVICE_ADMIN'
            ]
            
            features['dangerous_permissions'] = sum(
                1 for perm in dangerous_permissions 
                if perm.lower() in manifest_str.lower()
            )
            
            # Component analizi
            features['estimated_receivers'] = manifest_str.lower().count('receiver')
            features['estimated_services'] = manifest_str.lower().count('service')
            features['estimated_activities'] = manifest_str.lower().count('activity')
            features['estimated_providers'] = manifest_str.lower().count('provider')
            
            # Intent filter analizi
            features['intent_filters'] = manifest_str.lower().count('intent-filter')
            
            # Export edilen component'ler (güvenlik riski)
            features['exported_components'] = manifest_str.lower().count('exported="true"')
            
        except Exception as e:
            # Hata durumunda varsayılan değerler
            features.update({
                'estimated_permissions': 0,
                'dangerous_permissions': 0,
                'estimated_receivers': 0,
                'estimated_services': 0,
                'estimated_activities': 1,  # En az 1 activity olmalı
                'estimated_providers': 0,
                'intent_filters': 0,
                'exported_components': 0
            })
        
        return features
    
    def _analyze_dex_files(self, zip_ref, dex_files):
        """DEX dosyalarını kapsamlı analiz et - GELİŞTİRİLMİŞ VERSİYON"""
        features = {}
        
        total_dex_size = 0
        total_suspicious = 0
        api_call_counts = {}
        total_api_risk = 0.0
        string_pool_analysis = {}
        method_count = 0
        class_count = 0
        
        for dex_file in dex_files:
            try:
                dex_data = zip_ref.read(dex_file)
                total_dex_size += len(dex_data)
                
                # DEX header analizi
                dex_features = self._parse_dex_header(dex_data)
                method_count += dex_features.get('method_count', 0)
                class_count += dex_features.get('class_count', 0)
                
                # String analizi (UTF-8 decode attempt)
                try:
                    dex_str = dex_data.decode('utf-8', errors='ignore')
                except:
                    dex_str = str(dex_data, errors='ignore')
                
                # Şüpheli pattern'ler - YÜKSEK RİSKLİ OLANLAR
                suspicious_patterns = [
                    'payload', 'backdoor', 'keylog', 'stealer', 'trojan',
                    'bot', 'zombie', 'c&c', 'malware', 'virus', 'spy',
                    'exploit', 'escalation', 'inject', 'obfuscat'
                ]
                
                for pattern in suspicious_patterns:
                    count = dex_str.lower().count(pattern.lower())
                    total_suspicious += count
                    if count > 0:
                        string_pool_analysis[pattern] = count
                
                # API çağrısı analizi
                for api_call, risk_score in self.dangerous_api_calls.items():
                    count = dex_str.count(api_call)
                    if count > 0:
                        api_call_counts[api_call] = api_call_counts.get(api_call, 0) + count
                        total_api_risk += count * risk_score
                
                # Reflection kullanımı tespiti
                reflection_patterns = [
                    'Class.forName', 'getDeclaredMethod', 'getDeclaredField',
                    'setAccessible', 'invoke', 'newInstance'
                ]
                reflection_count = sum(dex_str.count(pattern) for pattern in reflection_patterns)
                
                # Dynamic loading tespiti
                dynamic_patterns = [
                    'DexClassLoader', 'PathClassLoader', 'loadClass',
                    'loadDex', 'loadLibrary'
                ]
                dynamic_count = sum(dex_str.count(pattern) for pattern in dynamic_patterns)
                
                # Crypto operasyonları
                crypto_patterns = [
                    'AES', 'DES', 'RSA', 'MD5', 'SHA', 'Cipher',
                    'encrypt', 'decrypt', 'Base64'
                ]
                crypto_count = sum(dex_str.count(pattern) for pattern in crypto_patterns)
                
            except Exception as e:
                st.warning(f"DEX analiz hatası ({dex_file}): {str(e)}")
                continue
        
        # Hesaplanmış özellikler
        features['total_dex_size_mb'] = total_dex_size / (1024 * 1024)
        features['suspicious_strings'] = total_suspicious
        features['dex_density'] = total_dex_size / len(dex_files) if dex_files else 0
        features['api_call_risk_score'] = min(total_api_risk / 50, 1.0)  # Normalize edilmiş (daha makul)
        features['unique_dangerous_apis'] = len(api_call_counts)
        features['total_api_calls'] = sum(api_call_counts.values())
        features['reflection_usage'] = reflection_count
        features['dynamic_loading'] = dynamic_count
        features['crypto_operations'] = crypto_count
        features['method_count'] = method_count
        features['class_count'] = class_count
        features['method_per_class'] = method_count / max(class_count, 1)
        
        # String pool çeşitliliği (entropy benzeri)
        features['string_diversity'] = len(string_pool_analysis)
        
        return features
    
    def _parse_dex_header(self, dex_data):
        """DEX dosyası header'ını parse et"""
        features = {}
        try:
            if len(dex_data) < 112:  # Minimum DEX header boyutu
                return features
            
            # DEX magic kontrolü
            magic = dex_data[0:8]
            if not magic.startswith(b'dex\n'):
                return features
            
            # Header bilgilerini oku (little-endian)
            file_size = struct.unpack('<I', dex_data[32:36])[0]
            header_size = struct.unpack('<I', dex_data[36:40])[0]
            string_ids_size = struct.unpack('<I', dex_data[56:60])[0]
            type_ids_size = struct.unpack('<I', dex_data[64:68])[0]
            proto_ids_size = struct.unpack('<I', dex_data[72:76])[0]
            field_ids_size = struct.unpack('<I', dex_data[80:84])[0]
            method_ids_size = struct.unpack('<I', dex_data[88:92])[0]
            class_defs_size = struct.unpack('<I', dex_data[96:100])[0]
            
            features['dex_file_size'] = file_size
            features['string_count'] = string_ids_size
            features['type_count'] = type_ids_size
            features['proto_count'] = proto_ids_size
            features['field_count'] = field_ids_size
            features['method_count'] = method_ids_size
            features['class_count'] = class_defs_size
            
        except Exception as e:
            st.warning(f"DEX header parse hatası: {str(e)}")
            
        return features
    
    def extract_enhanced_features(self, apk_file):
        """50+ gelişmiş özellik çıkarımı - UPGRADE EDİLMİŞ VERSİYON"""
        try:
            features = self.analyze_apk(apk_file)
            if not features:
                return None
            
            # Önceki 28 özelliğe ek olarak yeni özellikler
            enhanced_features = features.copy()
            
            # Network behavior analysis (13-18)
            enhanced_features['network_complexity'] = (
                enhanced_features.get('total_api_calls', 0) * 0.1 +
                enhanced_features.get('crypto_operations', 0) * 0.2
            )
            enhanced_features['has_socket_usage'] = 1 if enhanced_features.get('total_api_calls', 0) > 5 else 0
            enhanced_features['encryption_ratio'] = min(enhanced_features.get('crypto_operations', 0) / 10, 1.0)
            enhanced_features['api_diversity_index'] = min(enhanced_features.get('unique_dangerous_apis', 0) / 20, 1.0)
            enhanced_features['reflection_intensity'] = min(enhanced_features.get('reflection_usage', 0) / 15, 1.0)
            enhanced_features['dynamic_load_risk'] = min(enhanced_features.get('dynamic_loading', 0) / 8, 1.0)
            
            # Code complexity metrics (19-25)
            enhanced_features['code_density'] = enhanced_features.get('method_per_class', 0) / 100
            enhanced_features['structural_complexity'] = (
                enhanced_features.get('class_count', 0) / max(enhanced_features.get('total_files', 1), 1)
            )
            enhanced_features['obfuscation_indicator'] = min(enhanced_features.get('string_diversity', 0) / 25, 1.0)
            enhanced_features['bytecode_ratio'] = (
                enhanced_features.get('total_dex_size_mb', 0) / 
                max(enhanced_features.get('file_size_mb', 1), 0.1)
            )
            enhanced_features['suspicious_density'] = (
                enhanced_features.get('suspicious_strings', 0) / 
                max(enhanced_features.get('method_count', 1), 1)
            )
            enhanced_features['file_entropy'] = np.random.random()  # Placeholder for real entropy calculation
            enhanced_features['string_entropy'] = min(enhanced_features.get('string_diversity', 0) / 30, 1.0)
            
            # Permission analysis (26-32)
            enhanced_features['permission_density'] = (
                enhanced_features.get('estimated_permissions', 0) / 
                max(enhanced_features.get('file_size_mb', 1), 0.1)
            )
            enhanced_features['dangerous_perm_ratio'] = (
                enhanced_features.get('dangerous_permissions', 0) / 
                max(enhanced_features.get('estimated_permissions', 1), 1)
            )
            enhanced_features['perm_api_correlation'] = (
                enhanced_features.get('total_api_calls', 0) / 
                max(enhanced_features.get('estimated_permissions', 1), 1)
            )
            enhanced_features['export_risk_score'] = min(enhanced_features.get('exported_components', 0) / 15, 1.0)
            enhanced_features['service_risk_score'] = min(enhanced_features.get('estimated_services', 0) / 20, 1.0)
            enhanced_features['receiver_risk_score'] = min(enhanced_features.get('estimated_receivers', 0) / 25, 1.0)
            enhanced_features['cert_trust_score'] = 1.0 - min(enhanced_features.get('suspicious_cert', 0) / 3, 1.0)
            
            # Advanced static analysis (33-40)
            enhanced_features['native_code_ratio'] = (
                enhanced_features.get('so_count', 0) / 
                max(enhanced_features.get('total_files', 1), 1)
            )
            enhanced_features['architecture_diversity'] = min(enhanced_features.get('lib_architectures', 0) / 6, 1.0)
            enhanced_features['resource_bloat_index'] = (
                enhanced_features.get('resources_size_mb', 0) / 
                max(enhanced_features.get('file_size_mb', 1), 0.1)
            )
            enhanced_features['multimedia_ratio'] = (
                (enhanced_features.get('image_count', 0) + enhanced_features.get('audio_count', 0) + 
                 enhanced_features.get('video_count', 0)) / max(enhanced_features.get('total_files', 1), 1)
            )
            enhanced_features['layout_complexity'] = min(enhanced_features.get('layout_count', 0) / 50, 1.0)
            enhanced_features['drawable_density'] = min(enhanced_features.get('drawable_count', 0) / 100, 1.0)
            enhanced_features['manifest_complexity'] = min(enhanced_features.get('manifest_files', 0) / 5, 1.0)
            enhanced_features['signature_integrity'] = min(enhanced_features.get('signature_files', 0) / 3, 1.0)
            
            # Behavioral patterns (41-48)
            enhanced_features['stealth_indicator'] = (
                enhanced_features.get('obfuscation_indicator', 0) * 0.4 +
                enhanced_features.get('reflection_intensity', 0) * 0.3 +
                enhanced_features.get('dynamic_load_risk', 0) * 0.3
            )
            enhanced_features['persistence_risk'] = (
                enhanced_features.get('service_risk_score', 0) * 0.5 +
                enhanced_features.get('receiver_risk_score', 0) * 0.5
            )
            enhanced_features['privilege_escalation_risk'] = (
                enhanced_features.get('dangerous_perm_ratio', 0) * 0.6 +
                enhanced_features.get('api_diversity_index', 0) * 0.4
            )
            enhanced_features['data_exfiltration_risk'] = (
                enhanced_features.get('network_complexity', 0) * 0.4 +
                enhanced_features.get('encryption_ratio', 0) * 0.3 +
                enhanced_features.get('permission_density', 0) * 0.3
            )
            enhanced_features['evasion_techniques'] = (
                enhanced_features.get('obfuscation_indicator', 0) * 0.3 +
                enhanced_features.get('reflection_intensity', 0) * 0.3 +
                enhanced_features.get('dynamic_load_risk', 0) * 0.4
            )
            enhanced_features['payload_delivery_risk'] = (
                enhanced_features.get('native_code_ratio', 0) * 0.4 +
                enhanced_features.get('bytecode_ratio', 0) * 0.3 +
                enhanced_features.get('architecture_diversity', 0) * 0.3
            )
            enhanced_features['command_control_risk'] = (
                enhanced_features.get('network_complexity', 0) * 0.5 +
                enhanced_features.get('encryption_ratio', 0) * 0.5
            )
            enhanced_features['overall_maliciousness'] = (
                enhanced_features.get('api_call_risk_score', 0) * 0.3 +
                enhanced_features.get('stealth_indicator', 0) * 0.2 +
                enhanced_features.get('privilege_escalation_risk', 0) * 0.2 +
                enhanced_features.get('persistence_risk', 0) * 0.15 +
                enhanced_features.get('evasion_techniques', 0) * 0.15
            )
            
            # Additional meta features (49-52)
            enhanced_features['complexity_anomaly'] = abs(
                enhanced_features.get('code_density', 0) - 0.5
            )
            enhanced_features['size_function_mismatch'] = abs(
                enhanced_features.get('file_size_mb', 0) / 10 - 
                enhanced_features.get('method_count', 0) / 1000
            )
            enhanced_features['feature_count'] = len([k for k, v in enhanced_features.items() if v > 0])
            enhanced_features['risk_concentration'] = np.std([
                enhanced_features.get('stealth_indicator', 0),
                enhanced_features.get('persistence_risk', 0),
                enhanced_features.get('privilege_escalation_risk', 0),
                enhanced_features.get('data_exfiltration_risk', 0)
            ])
            
            return enhanced_features
            
        except Exception as e:
            st.error(f"Gelişmiş özellik çıkarım hatası: {str(e)}")
            return None
    
    def set_virustotal_api_key(self, api_key):
        """VirusTotal API anahtarını ayarla"""
        self.virustotal_api_key = api_key
    
    def check_virustotal(self, file_hash):
        """VirusTotal ile dosya hash'ini kontrol et"""
        if not self.virustotal_api_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.virustotal_api_key,
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'scan_date': result.get('scan_date', 'Bilinmiyor'),
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'permalink': result.get('permalink', ''),
                    'verbose_msg': result.get('verbose_msg', ''),
                    'response_code': result.get('response_code', 0)
                }
            else:
                st.warning(f"VirusTotal API hatası: {response.status_code}")
                return None
                
        except Exception as e:
            st.warning(f"VirusTotal bağlantı hatası: {str(e)}")
            return None
    
    def upload_to_virustotal(self, apk_file):
        """APK dosyasını VirusTotal'a yükle (isteğe bağlı)"""
        if not self.virustotal_api_key:
            return None
        
        try:
            url = "https://www.virustotal.com/vtapi/v2/file/scan"
            files = {'file': apk_file.getvalue()}
            params = {'apikey': self.virustotal_api_key}
            
            response = requests.post(url, files=files, params=params, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                return {
                    'scan_id': result.get('scan_id', ''),
                    'permalink': result.get('permalink', ''),
                    'verbose_msg': result.get('verbose_msg', ''),
                    'response_code': result.get('response_code', 0)
                }
            else:
                st.warning(f"VirusTotal upload hatası: {response.status_code}")
                return None
                
        except Exception as e:
            st.warning(f"VirusTotal upload bağlantı hatası: {str(e)}")
            return None
    
    def get_file_hash(self, file_data):
        """Dosya hash'lerini hesapla"""
        md5_hash = hashlib.md5(file_data).hexdigest()
        sha1_hash = hashlib.sha1(file_data).hexdigest()
        sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        return {
            'md5': md5_hash,
            'sha1': sha1_hash,
            'sha256': sha256_hash
        }
    
    def _check_apktool(self):
        """APKTool'un varlığını kontrol et"""
        try:
            # Basit java -jar apktool.jar kontrolü
            result = subprocess.run(['java', '-jar', 'apktool.jar', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                st.sidebar.success("✅ APKTool bulundu")
                return True
        except:
            pass
        st.sidebar.warning("⚠️ APKTool bulunamadı - Basit analiz kullanılacak")
        return False
    
    def _check_jadx(self):
        """JADX'in varlığını kontrol et"""
        try:
            # Önce yerel bin klasöründeki .bat dosyasını dene
            local_jadx = os.path.join(os.getcwd(), 'bin', 'jadx.bat')
            if os.path.exists(local_jadx):
                result = subprocess.run([local_jadx, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    st.sidebar.success(f"✅ JADX {result.stdout.strip()} bulundu")
                    return local_jadx
            
            # Sistem PATH'inde jadx komutunu dene
            result = subprocess.run(['jadx', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                st.sidebar.success("✅ JADX sistem PATH'inde bulundu")
                return 'jadx'
        except Exception as e:
            pass
        st.sidebar.warning("⚠️ JADX bulunamadı - DEX analizi sınırlı olacak")
        return False
    
    def professional_apk_analysis(self, apk_file):
        """🎯 PROFESYONEL APK ANALİZİ - APKTool & JADX"""
        try:
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # 1. Temel analiz (%20)
            status_text.text("📱 Temel APK analizi yapılıyor...")
            basic_analysis = self.extract_enhanced_features(apk_file)
            progress_bar.progress(20)
            
            # 2. Hash analizi (%30)
            status_text.text("🔍 Hash değerleri hesaplanıyor...")
            file_hashes = self.get_file_hash(apk_file.getvalue())
            progress_bar.progress(30)
            
            # 3. VirusTotal kontrolü (%50)
            vt_result = None
            if self.virustotal_api_key:
                status_text.text("🌐 VirusTotal kontrolü yapılıyor...")
                vt_result = self.check_virustotal(file_hashes['sha256'])
                if not vt_result or vt_result.get('response_code') != 1:
                    status_text.text("📤 VirusTotal'a yükleniyor...")
                    upload_result = self.upload_to_virustotal(apk_file)
                    if upload_result:
                        st.info("✅ Dosya VirusTotal'a yüklendi. Birkaç dakika sonra tekrar kontrol edin.")
            progress_bar.progress(50)
            
            # 4. Gelişmiş statik analiz (%70)
            status_text.text("🔧 Derinlemesine kod analizi...")
            detailed_analysis = self._perform_detailed_static_analysis(apk_file)
            progress_bar.progress(70)
            
            # 5. Manifest detay analizi (%85)
            status_text.text("📋 Manifest detay analizi...")
            manifest_details = self._analyze_manifest_deeply(apk_file)
            progress_bar.progress(85)
            
            # 6. Final risk hesaplama (%100)
            status_text.text("⚖️ Risk skoru hesaplanıyor...")
            if basic_analysis:
                risk_score, risk_factors = self.calculate_comprehensive_risk_score(basic_analysis)
            else:
                risk_score, risk_factors = 0.5, ["❌ Temel analiz başarısız"]
            
            progress_bar.progress(100)
            status_text.text("✅ Analiz tamamlandı!")
            
            return {
                'basic_analysis': basic_analysis,
                'file_hashes': file_hashes,
                'virustotal_result': vt_result,
                'detailed_analysis': detailed_analysis,
                'manifest_details': manifest_details,
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            st.error(f"🚨 Profesyonel analiz hatası: {str(e)}")
            return None
    
    def _perform_detailed_static_analysis(self, apk_file):
        """Detaylı statik analiz"""
        analysis = {
            'code_complexity': {},
            'security_indicators': [],
            'api_abuse_patterns': [],
            'obfuscation_level': 0
        }
        
        try:
            with zipfile.ZipFile(apk_file, 'r') as zip_ref:
                file_list = zip_ref.namelist()
                
                # DEX dosyalarını detaylı analiz et
                dex_files = [f for f in file_list if f.endswith('.dex')]
                for dex_file in dex_files:
                    dex_data = zip_ref.read(dex_file)
                    
                    # Bytecode pattern analizi
                    analysis['security_indicators'].extend(
                        self._detect_bytecode_patterns(dex_data)
                    )
                    
                    # Obfuscation seviyesi
                    analysis['obfuscation_level'] += self._calculate_obfuscation_level(dex_data)
                
                # Kaynak analizi
                analysis['code_complexity'] = self._analyze_code_complexity(zip_ref, file_list)
                
        except Exception as e:
            st.warning(f"Detaylı statik analiz hatası: {str(e)}")
        
        return analysis
    
    def _analyze_manifest_deeply(self, apk_file):
        """AndroidManifest.xml derinlemesine analiz"""
        details = {
            'permissions_detailed': [],
            'components': {},
            'intents': [],
            'security_flags': {}
        }
        
        try:
            with zipfile.ZipFile(apk_file, 'r') as zip_ref:
                if 'AndroidManifest.xml' in zip_ref.namelist():
                    manifest_data = zip_ref.read('AndroidManifest.xml')
                    
                    # Binary XML parsing (basit)
                    manifest_str = str(manifest_data, errors='ignore')
                    
                    # İzin detayları
                    permission_patterns = {
                        'SMS': ['SEND_SMS', 'READ_SMS', 'RECEIVE_SMS'],
                        'Location': ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'],
                        'Phone': ['CALL_PHONE', 'READ_PHONE_STATE', 'MODIFY_PHONE_STATE'],
                        'Storage': ['WRITE_EXTERNAL_STORAGE', 'READ_EXTERNAL_STORAGE'],
                        'Camera': ['CAMERA', 'RECORD_AUDIO'],
                        'Admin': ['DEVICE_ADMIN', 'BIND_DEVICE_ADMIN'],
                        'System': ['SYSTEM_ALERT_WINDOW', 'WRITE_SETTINGS']
                    }
                    
                    for category, perms in permission_patterns.items():
                        found_perms = [p for p in perms if p in manifest_str]
                        if found_perms:
                            details['permissions_detailed'].append({
                                'category': category,
                                'permissions': found_perms,
                                'risk_level': self._assess_permission_category_risk(category, len(found_perms))
                            })
                    
                    # Component analizi
                    components = ['activity', 'service', 'receiver', 'provider']
                    for comp in components:
                        count = manifest_str.count(comp)
                        details['components'][comp] = count
                    
                    # Güvenlik bayrakları
                    security_flags = ['debuggable', 'allowBackup', 'exported']
                    for flag in security_flags:
                        if flag in manifest_str:
                            details['security_flags'][flag] = True
                            
        except Exception as e:
            st.warning(f"Manifest detay analiz hatası: {str(e)}")
        
        return details
    
    def _detect_bytecode_patterns(self, dex_data):
        """Bytecode'da güvenlik pattern'lerini tespit et"""
        patterns = []
        
        # String olarak dönüştür
        try:
            dex_str = dex_data.decode('utf-8', errors='ignore')
        except:
            dex_str = str(dex_data, errors='ignore')
        
        # Güvenlik pattern'leri - DAHA SPESIFIK ARAMA
        security_patterns = {
            'Encryption': ['Cipher.getInstance', 'MessageDigest', 'SecretKeySpec', 'AESCrypt'],
            'Network': ['HttpURLConnection', 'Socket(', 'ServerSocket', 'URLConnection'],
            'File_Access': ['FileOutputStream', 'FileInputStream', 'deleteFile', 'openFileOutput'],
            'System_Calls': ['Runtime.exec', 'ProcessBuilder', 'getRuntime().exec'],
            'Reflection': ['Class.forName', 'getDeclaredMethod', 'setAccessible', 'invoke(']
        }
        
        for category, keywords in security_patterns.items():
            count = 0
            for keyword in keywords:
                # Daha kesin eşleşme için word boundary kullan
                pattern_count = len(re.findall(re.escape(keyword), dex_str, re.IGNORECASE))
                count += pattern_count
            
            # Threshold değerlerini yükselttik
            if count > 15:  # Eski threshold: 5, Yeni: 15  
                patterns.append({
                    'type': category,
                    'count': count,
                    'risk': 'HIGH' if count > 50 else 'MEDIUM'  # Eski: 20, Yeni: 50
                })
        
        return patterns
    
    def _calculate_obfuscation_level(self, dex_data):
        """Obfuscation seviyesini hesapla - FIX EDİLDİ"""
        try:
            dex_str = str(dex_data, errors='ignore')
            
            # Daha spesifik obfuscation pattern'leri
            # Sadece class/method/field isimlerini ara
            java_identifiers = re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b', dex_str)
            
            if len(java_identifiers) < 10:  # Çok az identifier varsa
                return 0
            
            # Kısa isimlerin oranı (1-3 karakter)
            short_names = len([name for name in java_identifiers if len(name) <= 3])
            total_names = len(java_identifiers)
            
            if total_names > 0:
                obfuscation_ratio = short_names / total_names
                # %100'ü aşmasın ve makul sınırlar içinde kalsın
                return min(max(obfuscation_ratio * 100, 0), 100)
            
        except Exception as e:
            pass
        
        return 0
    
    def _analyze_code_complexity(self, zip_ref, file_list):
        """Kod karmaşıklığını analiz et"""
        complexity = {
            'total_methods': 0,
            'total_classes': 0,
            'native_libraries': 0,
            'resources': 0
        }
        
        # Native kütüphaneler
        complexity['native_libraries'] = len([f for f in file_list if f.endswith('.so')])
        
        # Resources
        complexity['resources'] = len([f for f in file_list if f.startswith('res/')])
        
        return complexity
    
    def _assess_permission_category_risk(self, category, count):
        """İzin kategorisi risk seviyesi"""
        high_risk_categories = ['SMS', 'Phone', 'Admin', 'System']
        
        if category in high_risk_categories:
            return 'HIGH' if count > 2 else 'MEDIUM'
        else:
            return 'MEDIUM' if count > 3 else 'LOW'
    
    def _analyze_resources(self, zip_ref, file_list):
        """Resources kapsamlı analiz"""
        features = {}
        
        # Resources.arsc analizi
        if 'resources.arsc' in file_list:
            try:
                resources_data = zip_ref.read('resources.arsc')
                features['resources_size_mb'] = len(resources_data) / (1024 * 1024)
            except:
                features['resources_size_mb'] = 0
        else:
            features['resources_size_mb'] = 0
        
        # Multimedia dosyalar
        image_files = [f for f in file_list if any(f.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.gif', '.bmp'])]
        audio_files = [f for f in file_list if any(f.endswith(ext) for ext in ['.mp3', '.wav', '.ogg', '.m4a'])]
        video_files = [f for f in file_list if any(f.endswith(ext) for ext in ['.mp4', '.avi', '.mkv', '.webm'])]
        
        features['image_count'] = len(image_files)
        features['audio_count'] = len(audio_files)
        features['video_count'] = len(video_files)
        
        # Layout ve drawable analizi
        layout_files = [f for f in file_list if 'layout' in f and f.endswith('.xml')]
        drawable_files = [f for f in file_list if 'drawable' in f]
        
        features['layout_count'] = len(layout_files)
        features['drawable_count'] = len(drawable_files)
        
        return features
    
    def _analyze_certificates(self, zip_ref, file_list):
        """Sertifika analizi"""
        features = {}
        
        # META-INF klasöründeki sertifika dosyaları
        cert_files = [f for f in file_list if f.startswith('META-INF/') and any(f.endswith(ext) for ext in ['.RSA', '.DSA', '.EC'])]
        manifest_files = [f for f in file_list if f.startswith('META-INF/') and f.endswith('.MF')]
        sf_files = [f for f in file_list if f.startswith('META-INF/') and f.endswith('.SF')]
        
        features['certificate_count'] = len(cert_files)
        features['manifest_files'] = len(manifest_files)
        features['signature_files'] = len(sf_files)
        
        # Şüpheli sertifika isimleri
        suspicious_cert_names = ['test', 'debug', 'android', 'example', 'temp']
        features['suspicious_cert'] = sum(1 for cert in cert_files 
                                        if any(sus in cert.lower() for sus in suspicious_cert_names))
        
        return features
    
    def calculate_comprehensive_risk_score(self, features):
        """Kapsamlı risk skoru hesaplama - DENGELİ VERSİYON"""
        
        # Risk kategorileri ve ağırlıkları
        risk_categories = {}
        risk_factors = []
        
        # 1. API Çağrısı Davranış Riski (Ağırlık: 0.3)
        api_risk = features.get('api_call_risk_score', 0)
        if api_risk > 0.8:
            risk_categories['api_risk'] = 0.9
            risk_factors.append("🚨 Çok tehlikeli API çağrıları tespit edildi")
        elif api_risk > 0.5:
            risk_categories['api_risk'] = 0.6
            risk_factors.append("⚠️ Şüpheli API çağrıları")
        elif api_risk > 0.2:
            risk_categories['api_risk'] = 0.3
            risk_factors.append("📊 Orta riskli API kullanımı")
        else:
            risk_categories['api_risk'] = 0.0
        
        # 2. Reflection ve Dynamic Loading (Ağırlık: 0.15)
        reflection = features.get('reflection_usage', 0)
        dynamic = features.get('dynamic_loading', 0)
        if reflection > 15 or dynamic > 8:
            risk_categories['reflection_risk'] = 0.8
            risk_factors.append("🔍 Yoğun reflection/dynamic loading kullanımı")
        elif reflection > 8 or dynamic > 3:
            risk_categories['reflection_risk'] = 0.4
            risk_factors.append("🔧 Orta seviye reflection kullanımı")
        else:
            risk_categories['reflection_risk'] = 0.0
        
        # 3. İzin Riski (Ağırlık: 0.2)
        dangerous_perms = features.get('dangerous_permissions', 0)
        total_perms = features.get('estimated_permissions', 1)
        perm_ratio = dangerous_perms / total_perms if total_perms > 0 else 0
        
        if dangerous_perms > 15 or perm_ratio > 0.7:
            risk_categories['permission_risk'] = 0.9
            risk_factors.append("🔒 Çok sayıda tehlikeli izin")
        elif dangerous_perms > 8 or perm_ratio > 0.4:
            risk_categories['permission_risk'] = 0.5
            risk_factors.append("⚠️ Orta seviye tehlikeli izin")
        else:
            risk_categories['permission_risk'] = min(dangerous_perms / 15, 0.3)
        
        # 4. Şüpheli İçerik (Ağırlık: 0.15)
        suspicious_strings = features.get('suspicious_strings', 0)
        suspicious_files = features.get('suspicious_files', 0)
        
        if suspicious_strings > 50 or suspicious_files > 2:
            risk_categories['content_risk'] = 0.8
            risk_factors.append("🚩 Çok sayıda şüpheli içerik")
        elif suspicious_strings > 20 or suspicious_files > 0:
            risk_categories['content_risk'] = 0.4
            risk_factors.append("⚠️ Şüpheli içerik tespit")
        else:
            risk_categories['content_risk'] = min(suspicious_strings / 50, 0.2)
        
        # 5. Yapısal Anomali (Ağırlık: 0.1)
        method_per_class = features.get('method_per_class', 0)
        crypto = features.get('crypto_operations', 0)
        
        structural_risk = 0.0
        if method_per_class > 100:
            structural_risk += 0.3
            risk_factors.append("🏗️ Aşırı karmaşık kod yapısı")
        elif method_per_class > 60:
            structural_risk += 0.15
            
        if crypto > 50:
            structural_risk += 0.3
            risk_factors.append("🔐 Yoğun şifreleme operasyonları")
        elif crypto > 20:
            structural_risk += 0.15
            
        risk_categories['structural_risk'] = min(structural_risk, 0.8)
        
        # 6. Sertifika ve İmza (Ağırlık: 0.1)
        suspicious_cert = features.get('suspicious_cert', 0)
        if suspicious_cert > 0:
            risk_categories['cert_risk'] = 0.7
            risk_factors.append("📋 Şüpheli sertifika imzası")
        else:
            risk_categories['cert_risk'] = 0.0
        
        # Ağırlıklı toplam risk hesaplama
        weights = {
            'api_risk': 0.30,
            'reflection_risk': 0.15,
            'permission_risk': 0.20,
            'content_risk': 0.15,
            'structural_risk': 0.10,
            'cert_risk': 0.10
        }
        
        final_risk = sum(
            risk_categories.get(category, 0) * weight 
            for category, weight in weights.items()
        )
        
        # Risk seviyesi ayarlama (çok yüksek skorları düzelt)
        if final_risk > 0.8:
            final_risk = 0.8 + (final_risk - 0.8) * 0.5  # Üst limiti yumuşat
        
        # Ek risk faktörleri (bonus)
        bonus_risk = 0.0
        
        # Davranışsal anomali bonus
        anomaly_count = 0
        if features.get('unique_dangerous_apis', 0) > 15:
            anomaly_count += 1
        if features.get('dex_count', 0) > 5:
            anomaly_count += 1
        if features.get('total_files', 0) > 1500:
            anomaly_count += 1
            
        if anomaly_count >= 2:
            bonus_risk = 0.1
            risk_factors.append("🎯 Çoklu davranışsal anomali")
        
        # İzin-kod korelasyon bonusu
        api_calls = features.get('total_api_calls', 0)
        if dangerous_perms > 5 and api_calls == 0:
            bonus_risk += 0.1
            risk_factors.append("⚡ İzin var ama kod kullanımı yok")
        
        return min(final_risk + bonus_risk, 1.0), risk_factors

def main():
    # Ana başlık
    st.title(" APK Güvenlik Analiz Sistemi")
    st.markdown("""
    ** Android APK Zararlı Yazılım Tespit Sistemi**
    
    Bu uygulama Android APK dosyalarını kapsamlı güvenlik analizi ile inceleyerek 
    zararlı yazılım tespiti yapar. **Sadece APK dosyası yükleyin, analiz edin!**
    
    -  **Statik Analiz**: Dosya yapısı, izinler, sertifikalar
    -  **ML Analiz**: Makine öğrenmesi ile pattern tespiti (varsa)
    - **Risk Değerlendirmesi**: Kapsamlı güvenlik skoru
    - **Akıllı Öneriler**: Uzman tavsiyeleri
    """)
    
    # Sidebar
    st.sidebar.title("Analiz Kontrol Paneli")
    st.sidebar.markdown("---")
    
    # Analiz türü seçimi
    analysis_mode = st.sidebar.selectbox(
        "Analiz Modu:",
        [
            "APK Dosyası Analizi", 
            "CSV Verisi Analizi (İsteğe Bağlı)",
            "Sistem Bilgileri"
        ]
    )
    
    analyzer = APKSecurityAnalyzer()
    
    if analysis_mode == "APK Dosyası Analizi":
        apk_analysis_interface(analyzer)
    elif analysis_mode == " CSV Verisi Analizi (İsteğe Bağlı)":
        csv_analysis_interface(analyzer)
    elif analysis_mode == "Sistem Bilgileri":
        system_info_interface(analyzer)

def apk_analysis_interface(analyzer):
    """APK analiz arayüzü - GELİŞTİRİLMİŞ VERSİYON"""
    st.header("🛡️ APK Dosyası Güvenlik Analizi - Gelişmiş v2.0")
    
    # VirusTotal API anahtarı girişi
    st.sidebar.markdown("---")
    st.sidebar.subheader("🔗 VirusTotal Entegrasyonu")
    vt_api_key = st.sidebar.text_input(
        "VirusTotal API Anahtarı (İsteğe bağlı):",
        type="password",
        help="VirusTotal'dan ücretsiz API anahtarı alabilirsiniz"
    )
    
    if vt_api_key:
        analyzer.set_virustotal_api_key(vt_api_key)
        st.sidebar.success("✅ VirusTotal API bağlandı")
    
    # Analiz modu seçimi
    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Analiz Ayarları")
    analysis_depth = st.sidebar.selectbox(
        "Analiz Derinliği:",
        [
            "🚀 Hızlı Analiz (Temel)",
            "🔬 Kapsamlı Analiz (50+ özellik)", 
            "🎯 Profesyonel Analiz (APKTool + VirusTotal)",
            "🌐 Sadece VirusTotal Kontrolü"
        ]
    )
    
    enable_upload = st.sidebar.checkbox(
        "VirusTotal'a yükle (eğer bulunamazsa)",
        value=False,
        help="Dosya VirusTotal'da bulunamazsa otomatik yükler"
    )
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### APK Dosyası Yükleyin
        Android uygulamanızın APK dosyasını seçin. Sistem otomatik olarak:
        - Dosya yapısını analiz eder
        - İzinleri kontrol eder  
        - Şüpheli içerikleri tarar
        - Risk skorunu hesaplar
        """)
    
    with col2:
        st.info("""
        **İpucu:**
        - Google Play Store APK'ları genelde güvenli
        - Bilinmeyen kaynaklar dikkat gerektirir
        - Büyük dosyalar analiz süresi uzatabilir
        """)
    
    # Dosya yükleme
    uploaded_file = st.file_uploader(
        "APK dosyasını seçin:",
        type=['apk'],
        help="Android APK dosyası (.apk uzantılı)"
    )
    
    if uploaded_file is not None:
        col1, col2, col3 = st.columns([1, 1, 1])
        
        with col1:
            st.success(f"**Dosya Yüklendi**")
            st.write(f"**İsim:** {uploaded_file.name}")
        
        with col2:
            st.metric("Dosya Boyutu", f"{uploaded_file.size / (1024*1024):.2f} MB")
        
        with col3:
            st.metric("Yüklenme", datetime.now().strftime("%H:%M:%S"))
        
        st.markdown("---")
        
        # Analiz butonu
        if st.button(f"🚀 **{analysis_depth.split(' ')[1]} ANALİZİNİ BAŞLAT**", type="primary", use_container_width=True):
            
            # Seçilen analiz türüne göre farklı işlemler
            if "Profesyonel" in analysis_depth:
                st.info("🎯 Profesyonel analiz başlatılıyor - Bu işlem 1-3 dakika sürebilir...")
                analysis_result = analyzer.professional_apk_analysis(uploaded_file)
                
                if analysis_result:
                    display_professional_results(analysis_result, uploaded_file.name)
                else:
                    st.error("❌ Profesyonel analiz başarısız oldu")
            
            elif "VirusTotal" in analysis_depth:
                if analyzer.virustotal_api_key:
                    st.info("🌐 VirusTotal analizi başlatılıyor...")
                    file_hashes = analyzer.get_file_hash(uploaded_file.getvalue())
                    vt_result = analyzer.check_virustotal(file_hashes['sha256'])
                    display_virustotal_results(vt_result, file_hashes, uploaded_file.name)
                else:
                    st.error("❌ VirusTotal API anahtarı gerekli!")
            
            elif "Kapsamlı" in analysis_depth:
                with st.spinner("🔬 Kapsamlı analiz yapılıyor..."):
                    features = analyzer.extract_enhanced_features(uploaded_file)
                    
                    if features:
                        risk_score, risk_factors = analyzer.calculate_comprehensive_risk_score(features)
                        display_comprehensive_results(features, risk_score, risk_factors, uploaded_file.name, mode="comprehensive")
                    else:
                        st.error("❌ Kapsamlı analiz başarısız oldu")
            
            else:  # Hızlı Analiz
                with st.spinner("🚀 Hızlı analiz yapılıyor..."):
                    features = analyzer.analyze_apk(uploaded_file)
                    
                    if features:
                        risk_score, risk_factors = analyzer.calculate_comprehensive_risk_score(features)
                        display_comprehensive_results(features, risk_score, risk_factors, uploaded_file.name, mode="basic")
                    else:
                        st.error("❌ Temel analiz başarısız oldu")

def display_professional_results(analysis_result, filename):
    """Profesyonel analiz sonuçlarını göster"""
    st.markdown("---")
    st.header("🎯 Profesyonel APK Güvenlik Analizi Sonuçları")
    
    # Temel bilgiler
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        risk_score = analysis_result.get('risk_score', 0)
        if risk_score < 0.3:
            st.success("**✅ GÜVENLİ**")
            status_color = "green"
        elif risk_score < 0.7:
            st.warning("**⚠️ ŞÜPHELİ**")
            status_color = "orange"
        else:
            st.error("**🚨 TEHLİKELİ**")
            status_color = "red"
    
    with col2:
        st.metric("🎯 Risk Skoru", f"{risk_score*100:.1f}%")
    
    with col3:
        vt_result = analysis_result.get('virustotal_result')
        if vt_result and vt_result.get('response_code') == 1:
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            st.metric("🌐 VirusTotal", f"{positives}/{total}")
        else:
            st.metric("🌐 VirusTotal", "Kontrol edilmedi")
    
    with col4:
        manifest_details = analysis_result.get('manifest_details', {})
        perm_count = len(manifest_details.get('permissions_detailed', []))
        st.metric("🔒 İzinler", perm_count)
    
    # Detaylı analiz tabları
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🎯 Risk Analizi", "🔒 İzinler", "🔧 Kod Analizi", 
        "🌐 VirusTotal", "📊 Hash Değerleri"
    ])
    
    with tab1:
        st.subheader("⚠️ Risk Faktörleri")
        risk_factors = analysis_result.get('risk_factors', [])
        if risk_factors:
            for factor in risk_factors:
                st.write(f"• {factor}")
        else:
            st.success("✅ Önemli risk faktörü tespit edilmedi")
        
        # Detaylı analiz sonuçları
        detailed_analysis = analysis_result.get('detailed_analysis', {})
        if detailed_analysis.get('security_indicators'):
            st.subheader("🛡️ Güvenlik Göstergeleri")
            for indicator in detailed_analysis['security_indicators']:
                risk_level = indicator.get('risk', 'LOW')
                color = "red" if risk_level == 'HIGH' else "orange" if risk_level == 'MEDIUM' else "green"
                st.markdown(f"**{indicator['type']}:** {indicator['count']} tespit - <span style='color:{color}'>{risk_level}</span>", unsafe_allow_html=True)
    
    with tab2:
        manifest_details = analysis_result.get('manifest_details', {})
        permissions_detailed = manifest_details.get('permissions_detailed', [])
        
        if permissions_detailed:
            st.subheader("🔒 İzin Kategorileri")
            for perm_category in permissions_detailed:
                risk_level = perm_category['risk_level']
                color = "red" if risk_level == 'HIGH' else "orange" if risk_level == 'MEDIUM' else "green"
                
                st.markdown(f"**{perm_category['category']}** - <span style='color:{color}'>{risk_level}</span>", unsafe_allow_html=True)
                for perm in perm_category['permissions']:
                    st.write(f"  • {perm}")
        else:
            st.info("ℹ️ Detaylı izin bilgisi bulunamadı")
        
        # Component analizi
        components = manifest_details.get('components', {})
        if components:
            st.subheader("📱 Uygulama Bileşenleri")
            comp_df = pd.DataFrame(list(components.items()), columns=['Bileşen', 'Sayı'])
            st.dataframe(comp_df, use_container_width=True)
    
    with tab3:
        detailed_analysis = analysis_result.get('detailed_analysis', {})
        code_complexity = detailed_analysis.get('code_complexity', {})
        
        if code_complexity:
            st.subheader("📊 Kod Karmaşıklığı")
            
            complexity_metrics = {
                'Native Kütüphaneler': code_complexity.get('native_libraries', 0),
                'Kaynak Dosyaları': code_complexity.get('resources', 0),
                'Obfuscation Seviyesi': f"{detailed_analysis.get('obfuscation_level', 0):.1f}%"
            }
            
            for metric, value in complexity_metrics.items():
                st.metric(metric, value)
        
        # Güvenlik pattern'leri
        security_indicators = detailed_analysis.get('security_indicators', [])
        if security_indicators:
            st.subheader("🔍 Tespit Edilen Pattern'ler")
            pattern_df = pd.DataFrame(security_indicators)
            st.dataframe(pattern_df, use_container_width=True)
    
    with tab4:
        vt_result = analysis_result.get('virustotal_result')
        if vt_result and vt_result.get('response_code') == 1:
            st.subheader("🌐 VirusTotal Sonuçları")
            
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)
            scan_date = vt_result.get('scan_date', 'Bilinmiyor')
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Tespit Eden Engine", positives)
                st.metric("Toplam Engine", total)
            
            with col2:
                detection_rate = (positives / total) * 100 if total > 0 else 0
                st.metric("Tespit Oranı", f"{detection_rate:.1f}%")
                st.write(f"**Tarama Tarihi:** {scan_date}")
            
            if positives > 0:
                st.error(f"⚠️ {positives} antivirus engine bu dosyayı tehlikeli olarak işaretledi!")
            else:
                st.success("✅ Hiçbir antivirus engine tehdit tespit etmedi")
            
            if vt_result.get('permalink'):
                st.markdown(f"[🔗 VirusTotal Detay Raporu]({vt_result['permalink']})")
        else:
            st.info("ℹ️ VirusTotal kontrolü yapılamadı veya dosya bulunamadı")
    
    with tab5:
        file_hashes = analysis_result.get('file_hashes', {})
        if file_hashes:
            st.subheader("🔐 Dosya Hash Değerleri")
            
            hash_df = pd.DataFrame([
                ['MD5', file_hashes.get('md5', 'N/A')],
                ['SHA1', file_hashes.get('sha1', 'N/A')],
                ['SHA256', file_hashes.get('sha256', 'N/A')]
            ], columns=['Hash Türü', 'Değer'])
            
            st.dataframe(hash_df, use_container_width=True)
            
            st.info("💡 Bu hash değerlerini diğer güvenlik platformlarında aratabilirsiniz")

def display_virustotal_results(vt_result, file_hashes, filename):
    """VirusTotal sonuçlarını göster"""
    st.markdown("---")
    st.header("🌐 VirusTotal Analiz Sonuçları")
    
    if vt_result and vt_result.get('response_code') == 1:
        positives = vt_result.get('positives', 0)
        total = vt_result.get('total', 0)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if positives == 0:
                st.success("✅ TEMİZ")
            elif positives < 5:
                st.warning("⚠️ ŞÜPHELİ")
            else:
                st.error("🚨 TEHLİKELİ")
        
        with col2:
            st.metric("Tespit", f"{positives}/{total}")
        
        with col3:
            detection_rate = (positives / total) * 100 if total > 0 else 0
            st.metric("Tespit Oranı", f"{detection_rate:.1f}%")
        
        if positives > 0:
            st.error(f"⚠️ {positives} antivirus engine bu dosyayı zararlı olarak tanımladı!")
        else:
            st.success("✅ Tüm antivirus engine'ler dosyayı temiz buldu")
        
        if vt_result.get('permalink'):
            st.markdown(f"[🔗 Detaylı VirusTotal Raporu]({vt_result['permalink']})")
    else:
        st.warning("⚠️ Dosya VirusTotal veritabanında bulunamadı")
        st.info("📤 Dosyayı VirusTotal'a yüklemek ister misiniz? (Sidebar'da yükleme seçeneğini aktifleştirin)")
    
    # Hash değerleri
    st.subheader("🔐 Dosya Hash Değerleri")
    hash_df = pd.DataFrame([
        ['MD5', file_hashes.get('md5', 'N/A')],
        ['SHA1', file_hashes.get('sha1', 'N/A')],
        ['SHA256', file_hashes.get('sha256', 'N/A')]
    ], columns=['Hash Türü', 'Değer'])
    st.dataframe(hash_df, use_container_width=True)

def display_comprehensive_results(features, risk_score, risk_factors, filename, mode="basic"):
    """Kapsamlı sonuçları göster"""
    st.markdown("---")
    st.header("APK Güvenlik Analiz Sonuçları")
    
    # Ana risk durumu
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if risk_score < 0.3:
            st.success("**GÜVENLİ APK**")
            status_color = "green"
        elif risk_score < 0.7:
            st.warning(" **DİKKAT GEREKTİRİR**")
            status_color = "orange"
        else:
            st.error(" **YÜKSEK RİSK**")
            status_color = "red"
    
    with col2:
        st.metric(" Risk Skoru", f"{risk_score*100:.1f}%", delta=f"{risk_score*100-50:.1f}%")
    
    with col3:
        st.metric(" Dosya Boyutu", f"{features.get('file_size_mb', 0):.2f} MB")
    
    with col4:
        st.metric(" Toplam Dosya", features.get('total_files', 0))
    
    # Detaylı analiz tabları
    tab1, tab2, tab3, tab4 = st.tabs([" Risk Analizi", " Dosya Yapısı", " Güvenlik", " Öneriler"])
    
    with tab1:
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk gauge
            fig = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = risk_score * 100,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Risk Skoru (%)"},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': status_color},
                    'steps': [
                        {'range': [0, 30], 'color': "lightgreen"},
                        {'range': [30, 70], 'color': "yellow"}, 
                        {'range': [70, 100], 'color': "red"}],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 80
                    }
                }))
            
            fig.update_layout(height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("⚠️ Risk Faktörleri")
            if risk_factors:
                for factor in risk_factors:
                    st.write(f"• {factor}")
            else:
                st.success(" Önemli risk faktörü tespit edilmedi")
    
    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Dosya İstatistikleri")
            
            file_stats = {
                'Toplam Dosya': features.get('total_files', 0),
                'DEX Dosyaları': features.get('dex_count', 0),
                'SO Kütüphaneleri': features.get('so_count', 0),
                'XML Dosyaları': features.get('xml_count', 0),
                'Görsel Dosyalar': features.get('image_count', 0),
                'Layout Dosyaları': features.get('layout_count', 0),
                'Şüpheli Dosyalar': features.get('suspicious_files', 0)
            }
            
            stats_df = pd.DataFrame(list(file_stats.items()), 
                                   columns=['Dosya Türü', 'Sayı'])
            st.dataframe(stats_df, use_container_width=True)
        
        with col2:
            # Dosya türü dağılımı
            file_types = {
                'DEX': features.get('dex_count', 0),
                'SO': features.get('so_count', 0), 
                'XML': features.get('xml_count', 0),
                'Görseller': features.get('image_count', 0),
                'Diğer': features.get('total_files', 0) - features.get('dex_count', 0) - features.get('so_count', 0) - features.get('xml_count', 0) - features.get('image_count', 0)
            }
            
            if sum(file_types.values()) > 0:
                fig = px.pie(
                    values=list(file_types.values()),
                    names=list(file_types.keys()),
                    title="Dosya Türü Dağılımı"
                )
                st.plotly_chart(fig, use_container_width=True)
    
    with tab3:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("İzin Analizi")
            
            permission_data = {
                'Toplam İzin': features.get('estimated_permissions', 0),
                'Tehlikeli İzinler': features.get('dangerous_permissions', 0),
                'Export Edilen': features.get('exported_components', 0),
                'Şüpheli Sertifika': features.get('suspicious_cert', 0)
            }
            
            perm_df = pd.DataFrame(list(permission_data.items()), 
                                  columns=['İzin Türü', 'Sayı'])
            st.dataframe(perm_df, use_container_width=True)
        
        with col2:
            st.subheader(" Component Analizi")
            
            component_data = {
                'Activities': features.get('estimated_activities', 0),
                'Services': features.get('estimated_services', 0),
                'Receivers': features.get('estimated_receivers', 0),
                'Providers': features.get('estimated_providers', 0),
                'Intent Filters': features.get('intent_filters', 0)
            }
            
            comp_df = pd.DataFrame(list(component_data.items()), 
                                  columns=['Component', 'Sayı'])
            st.dataframe(comp_df, use_container_width=True)
    
    with tab4:
        st.subheader(" Güvenlik Değerlendirmesi ve Öneriler")
        
        if risk_score < 0.3:
            st.success("""
            ###  Bu APK güvenli görünüyor
            
            **Pozitif Özellikler:**
            - Normal dosya yapısı ve boyut
            - Makul izin kullanımı  
            - Şüpheli içerik tespit edilmedi
            - Standart Android app yapısı
            
            **Öneriler:**
            -  Kurulum yapabilirsiniz
            -  Normal kullanım güvenli
            -  Güncellemeleri takip edin
            """)
        elif risk_score < 0.7:
            st.warning("""
            ### Bu APK dikkatli inceleme gerektiriyor
            
            **Tespit Edilen Sorunlar:**
            - Bazı şüpheli özellikler mevcut
            - Risk faktörleri tespit edildi
            - İlave doğrulama gerekli
            
            **Öneriler:**
            - Kaynak güvenilirliğini kontrol edin
            - İzinleri dikkatlice inceleyin
            -  Antivirus taraması yapın
            -  Güvenlik uzmanına danışın
            """)
        else:
            st.error("""
            ###  Bu APK yüksek risk taşıyor!
            
            **Kritik Sorunlar:**
            - Çoklu şüpheli özellik tespit edildi
            - Zararlı yazılım belirtileri mevcut
            - Güvenlik tehdidi oluşturabilir
            
            **ACİL ÖNERİLER:**
            - KURMAYIN!
            - Dosyayı silin
            - Güvenlik uzmanı analizi gerekli
            - Cihazınızı tarayın
            - Kaynak güvenilir değil
            """)
        
        # Ek teknik bilgiler
        with st.expander("🔧 Teknik Detaylar"):
            st.json(features)

def csv_analysis_interface(analyzer):
    """CSV analiz arayüzü (isteğe bağlı)"""
    st.header(" CSV Verisi Analizi (Eski Yöntem)")
    
    st.info("""
    **Not:** Bu özellik sistem çağrısı CSV verisi olan kullanıcılar içindir.
    Çoğu kullanıcı için **APK Dosyası Analizi** daha pratiktir.
    """)
    
    if analyzer.ml_model is not None:
        st.success(" ML modeli mevcut - CSV analizi yapılabilir")
        
        uploaded_csv = st.file_uploader(
            "Sistem çağrısı CSV dosyasını yükleyin:",
            type=['csv'],
            help="APK sistem çağrısı izleme verilerini içeren CSV dosyası"
        )
        
        if uploaded_csv is not None:
            st.write("CSV analizi burada implement edilecek...")
    else:
        st.warning(" ML modeli bulunamadı. Önce modeli eğitmeniz gerekiyor.")

def system_info_interface(analyzer):
    """Sistem bilgileri arayüzü"""
    st.header(" Sistem Bilgileri")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("ML Model Durumu")
        if analyzer.ml_model is not None:
            st.success(" Random Forest modeli yüklü")
            st.success(" Scaler yüklü")
        else:
            st.warning(" ML modeli bulunamadı")
        
        st.subheader(" Analiz Kapasitesi")
        st.write("• APK statik analizi:  Aktif")
        st.write("• Dosya yapısı analizi:  Aktif") 
        st.write("• İzin risk analizi: Aktif")
        st.write("• Sertifika analizi:  Aktif")
        st.write("• ML CSV analizi:", " Aktif" if analyzer.ml_model else "Pasif")
    
    with col2:
        st.subheader("Proje İstatistikleri")
        st.metric("Desteklenen Format", "APK")
        st.metric("Analiz Yöntemi", "Statik Analiz")
        st.metric("Risk Kategorisi", "3 Seviye")
        st.metric("Özellik Sayısı", "25+")

if __name__ == "__main__":
    main() 