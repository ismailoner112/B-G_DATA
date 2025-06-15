import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import glob
from pathlib import Path
import json
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')

# Türkçe karakter desteği için
plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)

class MobileSecurityDataAnalyzer:
    def __init__(self, workspace_path='.'):
        self.workspace_path = Path(workspace_path)
        # Doğru klasör yapısı: alt klasörlerde iç içe aynı isimli klasörler var
        self.normal_dir = self.workspace_path / 'normal_apks_1mobile' / 'normal_apks_1mobile'
        self.malware_dir = self.workspace_path / 'malware_apks_1mobile' / 'malware_apks_1mobile'
        self.results_dir = self.workspace_path / 'analysis_results'
        self.results_dir.mkdir(exist_ok=True)
        
        # Analiz sonuçlarını saklayacak dictionary
        self.analysis_results = {
            'file_statistics': {},
            'syscall_analysis': {},
            'temporal_analysis': {},
            'comparison_metrics': {}
        }
        
    def get_file_info(self):
        """Dosya bilgilerini topla"""
        print(" Dosya bilgileri toplanıyor...")
        
        # Her iki klasördeki CSV dosyalarını bul
        normal_files = list(self.normal_dir.glob('*.csv'))
        malware_files = list(self.malware_dir.glob('*.csv'))
        
        print(f"   Normal APK CSV dosyası: {len(normal_files)}")
        print(f"   Zararlı APK CSV dosyası: {len(malware_files)}")
        
        def get_file_stats(files, category):
            stats = []
            for file in files:
                size_mb = file.stat().st_size / (1024 * 1024)  # MB cinsinden
                stats.append({
                    'file': file.name,
                    'category': category,
                    'size_mb': size_mb,
                    'path': str(file)
                })
            return stats
        
        normal_stats = get_file_stats(normal_files, 'Normal')
        malware_stats = get_file_stats(malware_files, 'Malware')
        
        all_stats = normal_stats + malware_stats
        
        self.analysis_results['file_statistics'] = {
            'normal_count': len(normal_files),
            'malware_count': len(malware_files),
            'total_count': len(all_stats),
            'normal_sizes': [s['size_mb'] for s in normal_stats],
            'malware_sizes': [s['size_mb'] for s in malware_stats],
            'all_files': all_stats,
            'normal_files': normal_files,
            'malware_files': malware_files
        }
        
        print(f"Normal APK dosyaları: {len(normal_files)}")
        print(f"Zararlı APK dosyaları: {len(malware_files)}")
        print(f"Toplam dosya sayısı: {len(all_stats)}")
        
        return all_stats
    
    def analyze_sample_files(self, sample_size=10):
        """Örnek dosyaları detaylı analiz et"""
        print(f"{sample_size} örnek dosya analiz ediliyor...")
        
        normal_files = self.analysis_results['file_statistics']['normal_files'][:sample_size//2]
        malware_files = self.analysis_results['file_statistics']['malware_files'][:sample_size//2]
        
        syscall_patterns = {'Normal': [], 'Malware': []}
        process_patterns = {'Normal': [], 'Malware': []}
        temporal_patterns = {'Normal': [], 'Malware': []}
        row_counts = {'Normal': [], 'Malware': []}
        
        for category, files in [('Normal', normal_files), ('Malware', malware_files)]:
            for file in files:
                try:
                    print(f"   {category}: {file.name}")
                    df = pd.read_csv(file, nrows=1000)  # İlk 1000 satırı oku
                    
                    # Satır sayısı
                    # Hızlı satır sayımı için
                    with open(file, 'r') as f:
                        row_count = sum(1 for line in f) - 1  # header hariç
                    row_counts[category].append(row_count)
                    
                    # Sistem çağrısı analizi
                    if 'syscall' in df.columns:
                        syscalls = df['syscall'].dropna().tolist()
                        syscall_patterns[category].extend(syscalls)
                    
                    # Process analizi
                    if 'processName' in df.columns:
                        processes = df['processName'].dropna().tolist()
                        process_patterns[category].extend(processes)
                    
                    # Zamansal analiz
                    if 'timestamp' in df.columns:
                        timestamps = pd.to_numeric(df['timestamp'], errors='coerce').dropna()
                        if len(timestamps) > 1:
                            time_diffs = np.diff(timestamps)
                            temporal_patterns[category].extend(time_diffs.tolist())
                            
                except Exception as e:
                    print(f"   ⚠️ Hata: {file.name} - {str(e)}")
        
        # Sonuçları kaydet
        self.analysis_results['syscall_analysis'] = {
            'normal_syscalls': Counter(syscall_patterns['Normal']),
            'malware_syscalls': Counter(syscall_patterns['Malware']),
            'normal_processes': Counter(process_patterns['Normal']),
            'malware_processes': Counter(process_patterns['Malware'])
        }
        
        self.analysis_results['temporal_analysis'] = {
            'normal_time_diffs': temporal_patterns['Normal'],
            'malware_time_diffs': temporal_patterns['Malware']
        }
        
        self.analysis_results['comparison_metrics'] = {
            'normal_row_counts': row_counts['Normal'],
            'malware_row_counts': row_counts['Malware']
        }
        
        print("Örnek dosya analizi tamamlandı!")
    
    def create_visualizations(self):
        """Görselleştirmeler oluştur"""
        print("Görselleştirmeler oluşturuluyor...")
        
        # 1. Dosya boyutu karşılaştırması
        self.plot_file_size_comparison()
        
        # 2. Dosya sayısı karşılaştırması
        self.plot_file_count_comparison()
        
        # 3. Sistem çağrısı analizi
        self.plot_syscall_analysis()
        
        # 4. Satır sayısı karşılaştırması
        self.plot_row_count_comparison()
        
        # 5. Process analizi
        self.plot_process_analysis()
        
        print("Tüm görselleştirmeler oluşturuldu!")
    
    def plot_file_size_comparison(self):
        """Dosya boyutu karşılaştırma grafiği"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        normal_sizes = self.analysis_results['file_statistics']['normal_sizes']
        malware_sizes = self.analysis_results['file_statistics']['malware_sizes']
        
        # Box plot
        data = [normal_sizes, malware_sizes]
        ax1.boxplot(data, labels=['Normal APK', 'Zararlı APK'])
        ax1.set_title('Dosya Boyutu Karşılaştırması (Box Plot)', fontsize=14, fontweight='bold')
        ax1.set_ylabel('Dosya Boyutu (MB)')
        ax1.grid(True, alpha=0.3)
        
        # Histogram
        ax2.hist(normal_sizes, alpha=0.7, label='Normal APK', bins=20, color='green')
        ax2.hist(malware_sizes, alpha=0.7, label='Zararlı APK', bins=20, color='red')
        ax2.set_title('Dosya Boyutu Dağılımı', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Dosya Boyutu (MB)')
        ax2.set_ylabel('Frekans')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'file_size_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_file_count_comparison(self):
        """Dosya sayısı karşılaştırma grafiği"""
        fig, ax = plt.subplots(figsize=(10, 6))
        
        categories = ['Normal APK', 'Zararlı APK']
        counts = [
            self.analysis_results['file_statistics']['normal_count'],
            self.analysis_results['file_statistics']['malware_count']
        ]
        colors = ['green', 'red']
        
        bars = ax.bar(categories, counts, color=colors, alpha=0.7)
        ax.set_title('Veri Seti Dosya Sayısı Karşılaştırması', fontsize=16, fontweight='bold')
        ax.set_ylabel('Dosya Sayısı')
        
        # Değerleri bar üzerine ekle
        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                   str(count), ha='center', va='bottom', fontweight='bold')
        
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(self.results_dir / 'file_count_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_syscall_analysis(self):
        """Sistem çağrısı analizi grafiği"""
        if not self.analysis_results['syscall_analysis']['normal_syscalls']:
            return
            
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))
        
        # En yaygın sistem çağrıları - Normal
        normal_top = self.analysis_results['syscall_analysis']['normal_syscalls'].most_common(10)
        if normal_top:
            syscalls, counts = zip(*normal_top)
            ax1.barh(range(len(syscalls)), counts, color='green', alpha=0.7)
            ax1.set_yticks(range(len(syscalls)))
            ax1.set_yticklabels(syscalls)
            ax1.set_title('En Yaygın Sistem Çağrıları - Normal APK', fontweight='bold')
            ax1.set_xlabel('Frekans')
        
        # En yaygın sistem çağrıları - Malware
        malware_top = self.analysis_results['syscall_analysis']['malware_syscalls'].most_common(10)
        if malware_top:
            syscalls, counts = zip(*malware_top)
            ax2.barh(range(len(syscalls)), counts, color='red', alpha=0.7)
            ax2.set_yticks(range(len(syscalls)))
            ax2.set_yticklabels(syscalls)
            ax2.set_title('En Yaygın Sistem Çağrıları - Zararlı APK', fontweight='bold')
            ax2.set_xlabel('Frekans')
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'syscall_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_row_count_comparison(self):
        """Satır sayısı karşılaştırma grafiği"""
        if not self.analysis_results['comparison_metrics']['normal_row_counts']:
            return
            
        fig, ax = plt.subplots(figsize=(12, 6))
        
        normal_rows = self.analysis_results['comparison_metrics']['normal_row_counts']
        malware_rows = self.analysis_results['comparison_metrics']['malware_row_counts']
        
        data = [normal_rows, malware_rows]
        ax.boxplot(data, labels=['Normal APK', 'Zararlı APK'])
        ax.set_title('Dosya Satır Sayısı Karşılaştırması', fontsize=14, fontweight='bold')
        ax.set_ylabel('Satır Sayısı')
        ax.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'row_count_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_process_analysis(self):
        """Process analizi grafiği"""
        if not self.analysis_results['syscall_analysis']['normal_processes']:
            return
            
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(15, 12))
        
        # Normal processes
        normal_top = self.analysis_results['syscall_analysis']['normal_processes'].most_common(10)
        if normal_top:
            processes, counts = zip(*normal_top)
            ax1.bar(range(len(processes)), counts, color='green', alpha=0.7)
            ax1.set_xticks(range(len(processes)))
            ax1.set_xticklabels(processes, rotation=45, ha='right')
            ax1.set_title('En Yaygın Process Adları - Normal APK', fontweight='bold')
            ax1.set_ylabel('Frekans')
        
        # Malware processes
        malware_top = self.analysis_results['syscall_analysis']['malware_processes'].most_common(10)
        if malware_top:
            processes, counts = zip(*malware_top)
            ax2.bar(range(len(processes)), counts, color='red', alpha=0.7)
            ax2.set_xticks(range(len(processes)))
            ax2.set_xticklabels(processes, rotation=45, ha='right')
            ax2.set_title('En Yaygın Process Adları - Zararlı APK', fontweight='bold')
            ax2.set_ylabel('Frekans')
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'process_analysis.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_summary_report(self):
        """Özet rapor oluştur"""
        print("Özet rapor oluşturuluyor...")
        
        report = {
            "Mobil Güvenlik Veri Seti - Analiz Raporu": {
                "Tarih": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Genel Bilgiler": {
                    "Toplam dosya sayısı": self.analysis_results['file_statistics']['total_count'],
                    "Normal APK dosya sayısı": self.analysis_results['file_statistics']['normal_count'],
                    "Zararlı APK dosya sayısı": self.analysis_results['file_statistics']['malware_count'],
                },
                "Dosya Boyutu İstatistikleri": {
                    "Normal APK": {
                        "Ortalama (MB)": np.mean(self.analysis_results['file_statistics']['normal_sizes']),
                        "Medyan (MB)": np.median(self.analysis_results['file_statistics']['normal_sizes']),
                        "Minimum (MB)": np.min(self.analysis_results['file_statistics']['normal_sizes']),
                        "Maksimum (MB)": np.max(self.analysis_results['file_statistics']['normal_sizes'])
                    },
                    "Zararlı APK": {
                        "Ortalama (MB)": np.mean(self.analysis_results['file_statistics']['malware_sizes']),
                        "Medyan (MB)": np.median(self.analysis_results['file_statistics']['malware_sizes']),
                        "Minimum (MB)": np.min(self.analysis_results['file_statistics']['malware_sizes']),
                        "Maksimum (MB)": np.max(self.analysis_results['file_statistics']['malware_sizes'])
                    }
                }
            }
        }
        
        # Sistem çağrısı bilgilerini ekle
        if self.analysis_results['syscall_analysis']['normal_syscalls']:
            report["Mobil Güvenlik Veri Seti - Analiz Raporu"]["Sistem Çağrısı Analizi"] = {
                "Normal APK - En yaygın 5 sistem çağrısı": dict(self.analysis_results['syscall_analysis']['normal_syscalls'].most_common(5)),
                "Zararlı APK - En yaygın 5 sistem çağrısı": dict(self.analysis_results['syscall_analysis']['malware_syscalls'].most_common(5))
            }
        
        # JSON olarak kaydet
        with open(self.results_dir / 'analysis_summary.json', 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        # Metin raporu oluştur
        with open(self.results_dir / 'analysis_report.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("MOBİL GÜVENLİK VERİ SETİ - KAPSAMLI ANALİZ RAPORU\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Analiz Tarihi: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("GENEL BİLGİLER:\n")
            f.write("-" * 20 + "\n")
            f.write(f"• Toplam dosya sayısı: {self.analysis_results['file_statistics']['total_count']}\n")
            f.write(f"• Normal APK dosyaları: {self.analysis_results['file_statistics']['normal_count']}\n")
            f.write(f"• Zararlı APK dosyaları: {self.analysis_results['file_statistics']['malware_count']}\n\n")
            
            f.write("DOSYA BOYUTU İSTATİSTİKLERİ:\n")
            f.write("-" * 30 + "\n")
            normal_sizes = self.analysis_results['file_statistics']['normal_sizes']
            malware_sizes = self.analysis_results['file_statistics']['malware_sizes']
            
            f.write("Normal APK:\n")
            f.write(f"  - Ortalama: {np.mean(normal_sizes):.2f} MB\n")
            f.write(f"  - Medyan: {np.median(normal_sizes):.2f} MB\n")
            f.write(f"  - Minimum: {np.min(normal_sizes):.2f} MB\n")
            f.write(f"  - Maksimum: {np.max(normal_sizes):.2f} MB\n\n")
            
            f.write("Zararlı APK:\n")
            f.write(f"  - Ortalama: {np.mean(malware_sizes):.2f} MB\n")
            f.write(f"  - Medyan: {np.median(malware_sizes):.2f} MB\n")
            f.write(f"  - Minimum: {np.min(malware_sizes):.2f} MB\n")
            f.write(f"  - Maksimum: {np.max(malware_sizes):.2f} MB\n\n")
            
            f.write("OLUŞTURULAN GÖRSELLEŞTİRMELER:\n")
            f.write("-" * 32 + "\n")
            f.write("• file_size_comparison.png - Dosya boyutu karşılaştırması\n")
            f.write("• file_count_comparison.png - Dosya sayısı karşılaştırması\n")
            f.write("• syscall_analysis.png - Sistem çağrısı analizi\n")
            f.write("• row_count_comparison.png - Satır sayısı karşılaştırması\n")
            f.write("• process_analysis.png - Process analizi\n\n")
            
            f.write("SONUÇ:\n")
            f.write("-" * 8 + "\n")
            f.write("Veri seti ikili sınıflandırma problemi için uygun yapıda.\n")
            f.write("Makine öğrenmesi modellemesi için hazır durumda.\n")
        
        print("Özet rapor oluşturuldu!")
    
    def run_complete_analysis(self):
        """Tam analizi çalıştır"""
        print("Kapsamlı veri analizi başlatılıyor...\n")
        
        # 1. Dosya bilgilerini topla
        self.get_file_info()
        print()
        
        # 2. Örnek dosyaları analiz et
        self.analyze_sample_files(sample_size=20)
        print()
        
        # 3. Görselleştirmeleri oluştur
        self.create_visualizations()
        print()
        
        # 4. Özet rapor oluştur
        self.generate_summary_report()
        print()
        
        print("Analiz tamamlandı!")
        print(f"Sonuçlar '{self.results_dir}' klasöründe saklandı.")
        print("\nOluşturulan dosyalar:")
        for file in self.results_dir.glob('*'):
            print(f"  • {file.name}")

if __name__ == "__main__":
    # Analizi çalıştır
    analyzer = MobileSecurityDataAnalyzer()
    analyzer.run_complete_analysis() 