
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pickle
from pathlib import Path
import json
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

# Sayfa konfigürasyonu
st.set_page_config(
    page_title="APK Güvenlik Analiz",
    layout="wide",
    initial_sidebar_state="expanded"
)

class APKSecurityAnalyzer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_models()
    
    def load_models(self):
        """Eğitilmiş modelleri yükle"""
        try:
            model_path = Path('./ml_results/random_forest_model.pkl')
            scaler_path = Path('./ml_results/scaler.pkl')
            
            if model_path.exists() and scaler_path.exists():
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                return True
            else:
                st.error("Model dosyaları bulunamadı! Önce ML pipeline'ını çalıştırın.")
                return False
        except Exception as e:
            st.error(f" Model yükleme hatası: {str(e)}")
            return False
    
    def extract_features_from_csv(self, df):
        """CSV dosyasından özellik çıkarımı yapar - Model ile uyumlu"""
        try:
            # Model tarafından beklenen tam özellik sırası (eğitim sırasında kullanılan)
            features = {
                'file_size_mb': len(df) * 0.001,  # Yaklaşık tahmin
                'total_rows': len(df),
                'total_columns': len(df.columns),
                'syscall_read_count': 0,
                'syscall_write_count': 0,
                'syscall_ioctl_count': 0,
                'syscall_recvfrom_count': 0,
                'syscall_sendto_count': 0,
                'syscall_futex_count': 0,
                'syscall_epoll_pwait_count': 0,
                'syscall_rt_sigprocmask_count': 0,
                'syscall_getuid_count': 0,
                'syscall_fstat_count': 0,
                'unique_syscalls': 0,
                'total_syscalls': len(df),
                'syscall_entropy': 0,
                'unique_processes': 0,
                'total_processes': 0,
                'process_RenderThread_count': 0,
                'process_Chrome_IOThread_count': 0,
                'process_Binder_count': 0,
                'process_pool_count': 0,
                'avg_time_diff': 0,
                'std_time_diff': 0,
                'max_time_diff': 0,
                'min_time_diff': 0,
                'avg_args_per_call': 0,
                'max_args_per_call': 0
            }
            
            # 1. Sistem çağrısı analizi (eventName veya syscall sütunu)
            syscall_column = None
            if 'eventName' in df.columns:
                syscall_column = 'eventName'
            elif 'syscall' in df.columns:
                syscall_column = 'syscall'
            
            if syscall_column:
                syscalls = df[syscall_column].dropna()
                if len(syscalls) > 0:
                    # Syscall işleme (eğer değerler tab karakteri içeriyorsa temizle)
                    syscalls_clean = syscalls.astype(str).str.replace('\t', '').str.strip()
                    syscall_counts = syscalls_clean.value_counts()
                    
                    features['unique_syscalls'] = len(syscall_counts)
                    features['total_syscalls'] = len(syscalls)
                    
                    # Entropi hesapla
                    if len(syscall_counts) > 0:
                        total = sum(syscall_counts.values)
                        probabilities = [v/total for v in syscall_counts.values if v > 0]
                        features['syscall_entropy'] = -sum(p * np.log2(p) for p in probabilities) if probabilities else 0
                    
                    # Özel sistem çağrıları (eğitim setindeki isimlerle aynı)
                    features['syscall_read_count'] = syscall_counts.get('read', 0)
                    features['syscall_write_count'] = syscall_counts.get('write', 0)
                    features['syscall_ioctl_count'] = syscall_counts.get('ioctl', 0)
                    features['syscall_recvfrom_count'] = syscall_counts.get('recvfrom', 0)
                    features['syscall_sendto_count'] = syscall_counts.get('sendto', 0)
                    features['syscall_futex_count'] = syscall_counts.get('futex', 0)
                    features['syscall_epoll_pwait_count'] = syscall_counts.get('epoll_pwait', 0)
                    features['syscall_rt_sigprocmask_count'] = syscall_counts.get('rt_sigprocmask', 0)
                    features['syscall_getuid_count'] = syscall_counts.get('getuid', 0)
                    features['syscall_fstat_count'] = syscall_counts.get('fstat', 0)
            
            # 2. Process analizi
            if 'processId' in df.columns:
                features['unique_processes'] = df['processId'].nunique()
            if 'processName' in df.columns:
                processes = df['processName'].dropna()
                features['total_processes'] = len(processes)
                
                # Process türleri (eğitim setindeki isimlerle aynı)
                process_counts = processes.value_counts()
                features['process_RenderThread_count'] = sum(count for name, count in process_counts.items() 
                                                           if 'render' in str(name).lower())
                features['process_Chrome_IOThread_count'] = sum(count for name, count in process_counts.items() 
                                                              if 'chrome' in str(name).lower() and 'io' in str(name).lower())
                features['process_Binder_count'] = sum(count for name, count in process_counts.items() 
                                                     if 'binder' in str(name).lower())
                features['process_pool_count'] = sum(count for name, count in process_counts.items() 
                                                   if 'pool' in str(name).lower())
            
            # 3. Temporal analiz
            if 'timestamp' in df.columns:
                timestamps = pd.to_numeric(df['timestamp'], errors='coerce').dropna()
                if len(timestamps) > 1:
                    time_diffs = timestamps.diff().dropna()
                    if len(time_diffs) > 0:
                        features['avg_time_diff'] = time_diffs.mean()
                        features['std_time_diff'] = time_diffs.std()
                        features['max_time_diff'] = time_diffs.max()
                        features['min_time_diff'] = time_diffs.min()
            
            # 4. Argument analizi
            value_cols = [col for col in df.columns if col.startswith('value')]
            if value_cols:
                args_per_call = df[value_cols].notna().sum(axis=1)
                features['avg_args_per_call'] = args_per_call.mean()
                features['max_args_per_call'] = args_per_call.max()
            elif 'argsNum' in df.columns:
                features['avg_args_per_call'] = df['argsNum'].mean() if df['argsNum'].notna().sum() > 0 else 0
                features['max_args_per_call'] = df['argsNum'].max() if df['argsNum'].notna().sum() > 0 else 0
            else:
                # Varsayılan değer (eğitim setinde görülen)
                features['avg_args_per_call'] = 6.0
                features['max_args_per_call'] = 6.0
            
            return features
            
        except Exception as e:
            st.error(f"Özellik çıkarımında hata: {str(e)}")
            # Hata durumunda varsayılan özellikler döndür (eğitim setindeki format)
            return {
                'file_size_mb': 0, 'total_rows': 0, 'total_columns': 0,
                'syscall_read_count': 0, 'syscall_write_count': 0, 'syscall_ioctl_count': 0,
                'syscall_recvfrom_count': 0, 'syscall_sendto_count': 0, 'syscall_futex_count': 0,
                'syscall_epoll_pwait_count': 0, 'syscall_rt_sigprocmask_count': 0, 'syscall_getuid_count': 0,
                'syscall_fstat_count': 0, 'unique_syscalls': 0, 'total_syscalls': 0,
                'syscall_entropy': 0, 'unique_processes': 0, 'total_processes': 0,
                'process_RenderThread_count': 0, 'process_Chrome_IOThread_count': 0, 'process_Binder_count': 0,
                'process_pool_count': 0, 'avg_time_diff': 0, 'std_time_diff': 0,
                'max_time_diff': 0, 'min_time_diff': 0, 'avg_args_per_call': 6.0, 'max_args_per_call': 6.0
            }
    
    def calculate_entropy(self, values):
        """Shannon entropisi hesapla"""
        if not values:
            return 0
        
        total = sum(values)
        if total == 0:
            return 0
        
        probabilities = [v/total for v in values if v > 0]
        entropy = -sum(p * np.log2(p) for p in probabilities)
        return entropy
    
    def predict_malware(self, features):
        """Zararlı yazılım tahmini yap"""
        try:
            if self.model is None or self.scaler is None:
                return None, None, None
            
            # DataFrame'e dönüştür
            feature_df = pd.DataFrame([features])
            
            # Eğitim sırasında kullanılan özellik sırası (extracted_features.csv'den)
            expected_features = [
                'file_size_mb', 'total_rows', 'total_columns', 'syscall_read_count',
                'syscall_write_count', 'syscall_ioctl_count', 'syscall_recvfrom_count',
                'syscall_sendto_count', 'syscall_futex_count', 'syscall_epoll_pwait_count',
                'syscall_rt_sigprocmask_count', 'syscall_getuid_count', 'syscall_fstat_count',
                'unique_syscalls', 'total_syscalls', 'syscall_entropy', 'unique_processes',
                'total_processes', 'process_RenderThread_count', 'process_Chrome_IOThread_count',
                'process_Binder_count', 'process_pool_count', 'avg_time_diff',
                'std_time_diff', 'max_time_diff', 'min_time_diff',
                'avg_args_per_call', 'max_args_per_call'
            ]
            
            # Eksik özellikleri tamamla
            for feature in expected_features:
                if feature not in feature_df.columns:
                    if feature in ['avg_args_per_call', 'max_args_per_call']:
                        feature_df[feature] = 6.0  # Eğitim setindeki varsayılan değer
                    else:
                        feature_df[feature] = 0
            
            # Sütun sırasını düzenle (eğitim sırasındaki sıra)
            feature_df = feature_df[expected_features]
            
            # Ölçeklendirme
            feature_scaled = self.scaler.transform(feature_df)
            
            # Tahmin
            prediction = self.model.predict(feature_scaled)[0]
            probability = self.model.predict_proba(feature_scaled)[0]
            confidence = max(probability)
            
            return prediction, probability, confidence
            
        except Exception as e:
            st.error(f" Tahmin hatası: {str(e)}")
            return None, None, None

def main():
    # Başlık ve açıklama
    st.title("APK Güvenlik Analiz Sistemi")
    st.markdown("""
    **Android APK Zararlı Yazılım Tespit Sistemi**
    
    Bu uygulama, Android uygulamalarını iki farklı yöntemle analiz ederek 
    zararlı yazılım tespiti yapar:
    - **CSV Analizi**: Sistem çağrısı verilerini ML ile analiz
    - 📱 **Direkt APK**: APK dosyasını statik analiz ile inceleme
    """)
    
    # Sidebar
    st.sidebar.title(" Analiz Menüsü")
    st.sidebar.markdown("---")
    
    # Analiz süreci seçimi
    analysis_option = st.sidebar.selectbox(
        "🔍 Analiz Türü Seçin:",
        [
            " CSV Dosyası Analizi (ML)", 
            "Direkt APK Analizi", 
            
            "Model İstatistikleri"
        ]
    )
    
    # Analyzer nesnesi oluştur
    analyzer = APKSecurityAnalyzer()
    
    if analysis_option == "CSV Dosyası Analizi (ML)":
        file_upload_analysis(analyzer)
    elif analysis_option == "Direkt APK Analizi":
        st.info("**Yeni Özellik**: APK dosyalarını direkt analiz edebilirsiniz!")
        st.markdown("""
        **APK Direkt Analizi şu özellikleri sunar:**
        -  Dosya yapısı analizi
        -  İzin kontrolü
        -  Şüpheli içerik tespiti
        -  Risk değerlendirmesi
        
        **Bu mod için ayrı bir uygulama çalıştırın:**
        """)
        if st.button(" APK Direkt Analiz Uygulamasını Başlat"):
            st.code("streamlit run apk_direct_analyzer.py --server.port 8502")
            st.success(" Yukarıdaki komutu terminalde çalıştırın")
            st.info("📱 APK analizi http://localhost:8502 adresinde açılacak")
  
        demo_analysis(analyzer)
    elif analysis_option == "Model İstatistikleri":
        model_statistics()

def file_upload_analysis(analyzer):
    """Dosya yükleme ve analiz"""
    st.header("APK CSV Dosyası Analizi")
    
    uploaded_file = st.file_uploader(
        "APK sistem çağrısı CSV dosyasını yükleyin:",
        type=['csv'],
        help="Android APK'nın sistem çağrısı izleme verilerini içeren CSV dosyası"
    )
    
    if uploaded_file is not None:
        try:
            # Farklı encoding türlerini dene
            encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252', 'utf-16']
            df = None
            used_encoding = None
            
            for encoding in encodings:
                try:
                    uploaded_file.seek(0)  # Dosya başına dön
                    df = pd.read_csv(uploaded_file, encoding=encoding)
                    used_encoding = encoding
                    break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            if df is None:
                st.error("Dosya kodlaması desteklenmiyor. Lütfen UTF-8 formatında bir dosya yükleyin.")
                return
            
            st.success(f"Dosya başarıyla yüklendi! {len(df)} satır, {len(df.columns)} sütun")
            if used_encoding != 'utf-8':
                st.info(f"ℹ Dosya {used_encoding} kodlaması ile okundu.")
            
            # Veri önizlemesi
            with st.expander(" Veri Önizlemesi", expanded=False):
                st.write("**İlk 5 satır:**")
                st.dataframe(df.head())
                st.write("**Sütun bilgileri:**")
                st.write(df.columns.tolist())
            
            # Analiz butonu
            if st.button("🔍 GÜVENLİK ANALİZİ BAŞLAT", type="primary"):
                with st.spinner("Analiz yapılıyor..."):
                    # Özellik çıkarımı
                    features = analyzer.extract_features_from_csv(df)
                    
                    if features:
                        # Tahmin yap
                        prediction, probability, confidence = analyzer.predict_malware(features)
                        
                        if prediction is not None:
                            display_analysis_results(prediction, probability, confidence, features, df)
                        else:
                            st.error(" Tahmin yapılamadı!")
                    else:
                        st.error("Özellik çıkarımı başarısız!")
                        
        except Exception as e:
            st.error(f" Dosya okuma hatası: {str(e)}")
            st.info(" **Çözüm önerileri:**\n- Dosyanın CSV formatında olduğundan emin olun\n- Dosya boyutunun 200MB'dan küçük olduğundan emin olun\n- Farklı bir dosya deneyin")

def demo_analysis(analyzer):
    """Demo analiz"""
    st.header(" Demo Analiz")
    st.info(" Örnek APK verileri ile demo analiz")
    
    # Demo veriler
    demo_options = {
        " Güvenli APK Örneği": {
            'total_rows': 1500,
            'total_columns': 67,
            'file_size_mb': 2.5,
            'syscall_read_count': 800,
            'syscall_write_count': 400,
            'unique_syscalls': 15,
            'total_syscalls': 1200,
            'syscall_entropy': 2.8
        },
        "Şüpheli APK Örneği": {
            'total_rows': 3500,
            'total_columns': 67,
            'file_size_mb': 8.2,
            'syscall_read_count': 2200,
            'syscall_write_count': 180,
            'unique_syscalls': 25,
            'total_syscalls': 2800,
            'syscall_entropy': 3.8
        }
    }
    
    selected_demo = st.selectbox("Demo türü seçin:", list(demo_options.keys()))
    
    if st.button(" DEMO ANALİZİ BAŞLAT", type="primary"):
        with st.spinner("Demo analiz yapılıyor..."):
            features = demo_options[selected_demo]
            
            # Eksik özellikleri sıfır ile doldur
            all_features = {
                'total_rows': features.get('total_rows', 0),
                'total_columns': features.get('total_columns', 0),
                'file_size_mb': features.get('file_size_mb', 0),
                'syscall_read_count': features.get('syscall_read_count', 0),
                'syscall_write_count': features.get('syscall_write_count', 0),
                'syscall_ioctl_count': 0,
                'syscall_recvfrom_count': 0,
                'syscall_sendto_count': 0,
                'syscall_futex_count': 0,
                'syscall_epoll_pwait_count': 0,
                'syscall_rt_sigprocmask_count': 0,
                'syscall_getuid_count': 0,
                'syscall_fstat_count': 0,
                'unique_syscalls': features.get('unique_syscalls', 0),
                'total_syscalls': features.get('total_syscalls', 0),
                'syscall_entropy': features.get('syscall_entropy', 0),
                'unique_processes': 0,
                'total_processes': 0,
                'process_RenderThread_count': 0,
                'process_Chrome_IOThread_count': 0,
                'process_Binder_count': 0,
                'process_pool_count': 0,
                'avg_time_diff': 0,
                'std_time_diff': 0,
                'max_time_diff': 0,
                'min_time_diff': 0,
                'sin6_addr_non_null_count': 0,
                'sin6_port_non_null_count': 0,
                'sa_family_non_null_count': 0,
                'avg_args_per_call': 0,
                'max_args_per_call': 0
            }
            
            prediction, probability, confidence = analyzer.predict_malware(all_features)
            
            if prediction is not None:
                display_analysis_results(prediction, probability, confidence, all_features, None, is_demo=True)

def display_analysis_results(prediction, probability, confidence, features, df=None, is_demo=False):
    """Analiz sonuçlarını göster"""
    st.markdown("---")
    st.header("🎯 Analiz Sonuçları")
    
    # Ana sonuç
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if prediction == 0:
            st.success("GÜVENLİ APK")
            st.metric("Güvenlik Durumu", "Normal")
        else:
            st.error(" RİSKLİ APK")
            st.metric("Güvenlik Durumu", "Zararlı")
    
    with col2:
        risk_score = probability[1] * 100
        st.metric("Risk Skoru", f"{risk_score:.1f}%", f"{risk_score:.1f}%")
    
    with col3:
        st.metric("Model Güveni", f"{confidence*100:.1f}%", f"{confidence*100:.1f}%")
    
    # Detaylı analiz
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Risk Dağılımı")
        
        # Risk göstergesi grafiği
        fig = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = risk_score,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Risk Skoru (%)"},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90}}))
        
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Özellik Analizi")
        
        # Önemli özellikler
        important_features = {
            'Toplam Satır': features.get('total_rows', 0),
            'Dosya Boyutu (MB)': features.get('file_size_mb', 0),
            'Sistem Çağrısı Sayısı': features.get('total_syscalls', 0),
            'Benzersiz Sistem Çağrısı': features.get('unique_syscalls', 0),
            'Entropi': features.get('syscall_entropy', 0)
        }
        
        feature_df = pd.DataFrame(list(important_features.items()), 
                                columns=['Özellik', 'Değer'])
        st.dataframe(feature_df, use_container_width=True)
    
    # Sistem çağrısı analizi
    if not is_demo and df is not None and 'syscall' in df.columns:
        st.subheader(" Sistem Çağrısı Analizi")
        
        syscalls = df['syscall'].dropna()
        syscall_counts = Counter(syscalls)
        top_syscalls = syscall_counts.most_common(10)
        
        if top_syscalls:
            syscall_df = pd.DataFrame(top_syscalls, columns=['Sistem Çağrısı', 'Frekans'])
            
            fig = px.bar(syscall_df, x='Sistem Çağrısı', y='Frekans',
                        title="En Yaygın 10 Sistem Çağrısı")
            fig.update_layout(xaxis_tickangle=-45)
            st.plotly_chart(fig, use_container_width=True)
    
    # Güvenlik önerileri
    st.subheader("Güvenlik Önerileri")
    
    if prediction == 0:
        st.info("""
        **Bu APK güvenli görünüyor!**
        - Normal sistem çağrısı kalıpları tespit edildi
        - Risk skoru düşük seviyede
        - Rutin kullanım için güvenli
        """)
    else:
        st.warning("""
         **Bu APK riskli olabilir!**
        - Şüpheli sistem çağrısı kalıpları tespit edildi
        - Yüksek risk skoru
        - Dikkatli analiz gerekli
        - Güvenlik uzmanına danışın
        """)

def model_statistics():
    """Model istatistikleri"""
    st.header(" Model Performans İstatistikleri")
    
    # ML raporunu oku
    report_path = Path('./ml_results/ml_report.json')
    if report_path.exists():
        with open(report_path, 'r', encoding='utf-8') as f:
            ml_data = json.load(f)
            ml_results = ml_data["Mobil Güvenlik ML Raporu"]
        
        # Model performansları
        st.subheader(" Model Karşılaştırması")
        
        performances = ml_results["Model Performansları"]
        models_df = pd.DataFrame(performances).T
        
        # Performans grafiği
        fig = go.Figure()
        
        metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score', 'AUC Score']
        for metric in metrics:
            fig.add_trace(go.Scatter(
                x=list(performances.keys()),
                y=[performances[model][metric] for model in performances.keys()],
                mode='lines+markers',
                name=metric,
                line=dict(width=3),
                marker=dict(size=8)
            ))
        
        fig.update_layout(
            title="Model Performans Karşılaştırması",
            xaxis_title="Modeller",
            yaxis_title="Skor",
            hovermode='x unified',
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Detaylı metrikler
        st.subheader(" Detaylı Metrikler")
        st.dataframe(models_df.round(4), use_container_width=True)
        
        # En iyi model
        best_model = ml_results["En İyi Model"]
        st.success(f"**En İyi Model**: {best_model['Model Adı']} (AUC: {best_model['AUC Score']:.4f})")
        
    else:
        st.warning("Model istatistikleri bulunamadı. Önce ML pipeline'ını çalıştırın.")

if __name__ == "__main__":
    main() 