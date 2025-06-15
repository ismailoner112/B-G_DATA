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

class DirectAPKAnalyzer:
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
    
    def analyze_apk(self, apk_file):
        """APK dosyasını analiz et"""
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
            
            return features
            
        except Exception as e:
            st.error(f"APK analiz hatası: {str(e)}")
            return None
    
    def _analyze_file_structure(self, file_list):
        """Dosya yapısını analiz et"""
        features = {}
        
        features['total_files'] = len(file_list)
        features['dex_count'] = len([f for f in file_list if f.endswith('.dex')])
        features['so_count'] = len([f for f in file_list if f.endswith('.so')])
        features['xml_count'] = len([f for f in file_list if f.endswith('.xml')])
        features['png_count'] = len([f for f in file_list if f.endswith('.png')])
        features['jar_count'] = len([f for f in file_list if f.endswith('.jar')])
        
        # Şüpheli dosya uzantıları
        suspicious_extensions = ['.exe', '.bat', '.sh', '.bin', '.dll']
        features['suspicious_files'] = len([f for f in file_list 
                                          if any(f.endswith(ext) for ext in suspicious_extensions)])
        
        # Asset ve lib klasörleri
        features['has_assets'] = any(f.startswith('assets/') for f in file_list)
        features['has_lib'] = any(f.startswith('lib/') for f in file_list)
        features['has_meta_inf'] = any(f.startswith('META-INF/') for f in file_list)
        
        return features
    
    def _analyze_manifest(self, manifest_data):
        """AndroidManifest.xml analiz et"""
        features = {}
        
        try:
            manifest_str = str(manifest_data)
            
            permission_patterns = [
                b'android.permission.',
                b'PERMISSION',
                b'uses-permission'
            ]
            
            permission_count = 0
            for pattern in permission_patterns:
                permission_count += manifest_str.count(pattern.decode('latin-1', errors='ignore'))
            
            features['estimated_permissions'] = permission_count
            
            # Tehlikeli izinleri tespit et
            dangerous_permissions = [
                'WRITE_EXTERNAL_STORAGE', 'READ_SMS', 'SEND_SMS', 
                'CALL_PHONE', 'RECORD_AUDIO', 'CAMERA'
            ]
            
            features['dangerous_permissions'] = sum(
                1 for perm in dangerous_permissions 
                if perm.lower() in manifest_str.lower()
            )
            
            # Receiver ve Service sayısını tahmin et
            features['estimated_receivers'] = manifest_str.lower().count('receiver')
            features['estimated_services'] = manifest_str.lower().count('service')
            features['estimated_activities'] = manifest_str.lower().count('activity')
            
        except Exception:
            # Hata durumunda varsayılan değerler
            features.update({
                'estimated_permissions': 0,
                'dangerous_permissions': 0,
                'estimated_receivers': 0,
                'estimated_services': 0,
                'estimated_activities': 0
            })
        
        return features
    
    def _analyze_dex_files(self, zip_ref, dex_files):
        """DEX dosyalarını analiz et"""
        features = {}
        
        total_dex_size = 0
        for dex_file in dex_files:
            dex_data = zip_ref.read(dex_file)
            total_dex_size += len(dex_data)
            
            # Şüpheli string patterns
            dex_str = str(dex_data)
            suspicious_patterns = [
                'root', 'su', 'busybox', 'superuser',
                'payload', 'backdoor', 'keylog', 'stealer',
                'bot', 'zombie', 'command', 'control',
                'encrypt', 'decrypt', 'obfuscat'
            ]
            
            features['suspicious_strings'] = sum(
                1 for pattern in suspicious_patterns
                if pattern.lower() in dex_str.lower()
            )
        
        features['total_dex_size_mb'] = total_dex_size / (1024 * 1024)
        
        return features
    
    def _analyze_resources(self, zip_ref, file_list):
        """Resources analiz et"""
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
        
        # Drawable resources
        drawable_files = [f for f in file_list if 'drawable' in f]
        features['drawable_count'] = len(drawable_files)
        
        # Layout files
        layout_files = [f for f in file_list if 'layout' in f]
        features['layout_count'] = len(layout_files)
        
        return features
    
    def calculate_risk_score(self, features):
        """Risk skoru hesapla"""
        risk_score = 0.0
        
        # Dosya boyutu riski (çok büyük veya çok küçük şüpheli)
        file_size = features.get('file_size_mb', 0)
        if file_size > 100:  # 100MB'dan büyük
            risk_score += 0.3
        elif file_size < 0.5:  # 500KB'dan küçük
            risk_score += 0.2
        
        # İzin riski
        dangerous_perms = features.get('dangerous_permissions', 0)
        total_perms = features.get('estimated_permissions', 0)
        if total_perms > 0:
            perm_risk = dangerous_perms / total_perms
            risk_score += perm_risk * 0.4
        
        # Şüpheli dosya riski
        suspicious_files = features.get('suspicious_files', 0)
        if suspicious_files > 0:
            risk_score += min(suspicious_files * 0.2, 0.5)
        
        # Şüpheli string riski
        suspicious_strings = features.get('suspicious_strings', 0)
        if suspicious_strings > 0:
            risk_score += min(suspicious_strings * 0.1, 0.3)
        
        # Component riski (çok fazla service/receiver şüpheli)
        services = features.get('estimated_services', 0)
        receivers = features.get('estimated_receivers', 0)
        if services > 10 or receivers > 15:
            risk_score += 0.2
        
        return min(risk_score, 1.0)  # Max 1.0

def create_apk_analyzer_ui():
    """APK Analyzer UI"""
    st.title("📱 APK Direkt Analiz Sistemi")
    st.markdown("""
    **Android APK Dosyalarını Direkt Analiz**
    
    Bu sistem APK dosyalarını sistem çağrısı verisi olmadan direkt analiz eder:
    -  Dosya yapısı analizi
    -  İzin analizi  
    -  Şüpheli içerik tespiti
    -  Risk değerlendirmesi
    """)
    
    analyzer = DirectAPKAnalyzer()
    
    # Dosya yükleme
    uploaded_file = st.file_uploader(
        "APK dosyasını yükleyin:",
        type=['apk'],
        help="Android APK dosyası (.apk uzantılı)"
    )
    
    if uploaded_file is not None:
        st.success(f" APK yüklendi: {uploaded_file.name} ({uploaded_file.size / (1024*1024):.2f} MB)")
        
        if st.button(" APK ANALİZİ BAŞLAT", type="primary"):
            with st.spinner("APK analiz ediliyor..."):
                features = analyzer.analyze_apk(uploaded_file)
                
                if features:
                    # Risk skoru hesapla
                    risk_score = analyzer.calculate_risk_score(features)
                    
                    # Sonuçları göster
                    display_apk_results(features, risk_score)

def display_apk_results(features, risk_score):
    """APK analiz sonuçlarını göster"""
    st.markdown("---")
    st.header("🎯 APK Analiz Sonuçları")
    
    # Ana metrikler
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if risk_score < 0.3:
            st.success(" DÜŞÜK RİSK")
        elif risk_score < 0.7:
            st.warning(" ORTA RİSK")
        else:
            st.error(" YÜKSEK RİSK")
    
    with col2:
        st.metric("Risk Skoru", f"{risk_score*100:.1f}%")
    
    with col3:
        st.metric("Dosya Boyutu", f"{features.get('file_size_mb', 0):.2f} MB")
    
    with col4:
        st.metric("Toplam Dosya", features.get('total_files', 0))
    
    # Detaylı analiz
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader(" Risk Göstergesi")
        
        # Risk gauge
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = risk_score * 100,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Risk Skoru (%)"},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "yellow"}, 
                    {'range': [70, 100], 'color': "red"}]
            }))
        
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader(" Özellik Analizi")
        
        analysis_data = {
            'Dosya Sayısı': features.get('total_files', 0),
            'DEX Dosyaları': features.get('dex_count', 0),
            'SO Kütüphaneleri': features.get('so_count', 0),
            'Tahmini İzinler': features.get('estimated_permissions', 0),
            'Tehlikeli İzinler': features.get('dangerous_permissions', 0),
            'Şüpheli Dosyalar': features.get('suspicious_files', 0),
            'Şüpheli Stringler': features.get('suspicious_strings', 0)
        }
        
        analysis_df = pd.DataFrame(list(analysis_data.items()), 
                                 columns=['Özellik', 'Değer'])
        st.dataframe(analysis_df, use_container_width=True)
    
    # Dosya yapısı analizi
    st.subheader(" Dosya Yapısı")
    
    file_types = {
        'DEX': features.get('dex_count', 0),
        'SO': features.get('so_count', 0), 
        'XML': features.get('xml_count', 0),
        'PNG': features.get('png_count', 0),
        'JAR': features.get('jar_count', 0)
    }
    
    if sum(file_types.values()) > 0:
        fig = px.pie(
            values=list(file_types.values()),
            names=list(file_types.keys()),
            title="Dosya Türü Dağılımı"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Güvenlik önerileri
    st.subheader(" Güvenlik Değerlendirmesi")
    
    if risk_score < 0.3:
        st.info("""
         **Bu APK düşük risk seviyesinde görünüyor**
        - Normal dosya yapısı
        - Makul izin kullanımı
        - Şüpheli içerik tespit edilmedi
        """)
    elif risk_score < 0.7:
        st.warning("""
         **Bu APK orta risk seviyesinde**
        - Bazı şüpheli özellikler tespit edildi
        - Dikkatli inceleme önerilir
        - Güvenilir kaynaklardan indirdiğinizden emin olun
        """)
    else:
        st.error("""
         **Bu APK yüksek risk seviyesinde!**
        - Çoklu şüpheli özellik tespit edildi
        - Kurulum önerilmez
        - Güvenlik uzmanı analizi gerekli
        - Bilinmeyen kaynaklardan gelebilir
        """)

if __name__ == "__main__":
    create_apk_analyzer_ui() 