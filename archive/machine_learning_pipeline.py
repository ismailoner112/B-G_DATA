import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json
import pickle
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')

# ML kütüphaneleri
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (classification_report, confusion_matrix, 
                           roc_auc_score, roc_curve, accuracy_score,
                           precision_score, recall_score, f1_score)

# Görselleştirme ayarları
plt.rcParams['font.family'] = 'DejaVu Sans'
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)

class MobileSecurityMLPipeline:
    def __init__(self, workspace_path='.'):
        self.workspace_path = Path(workspace_path)
        self.normal_dir = self.workspace_path / 'normal_apks_1mobile' / 'normal_apks_1mobile'
        self.malware_dir = self.workspace_path / 'malware_apks_1mobile' / 'malware_apks_1mobile'
        self.results_dir = self.workspace_path / 'ml_results'
        self.results_dir.mkdir(exist_ok=True)
        
        # Modeller ve sonuçlar
        self.models = {}
        self.results = {}
        self.feature_data = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.scaler = StandardScaler()
        
    def extract_features_from_file(self, file_path, label, max_rows=10000):
        """Tek dosyadan özellik çıkarımı"""
        try:
            # Dosyayı oku (bellek tasarrufu için sınırlı satır)
            df = pd.read_csv(file_path, nrows=max_rows)
            
            features = {
                'file_name': file_path.name,
                'label': label,
                'file_size_mb': file_path.stat().st_size / (1024 * 1024)
            }
            
            # Temel istatistikler
            features['total_rows'] = len(df)
            features['total_columns'] = len(df.columns)
            
            # Sistem çağrısı özellikleri
            if 'syscall' in df.columns:
                syscalls = df['syscall'].dropna()
                syscall_counts = Counter(syscalls)
                
                # En yaygın sistem çağrıları
                top_syscalls = ['read', 'write', 'ioctl', 'recvfrom', 'sendto', 
                              'futex', 'epoll_pwait', 'rt_sigprocmask', 'getuid', 'fstat']
                
                for syscall in top_syscalls:
                    # Tab karakterini temizle
                    syscall_clean = syscall + '\t'
                    features[f'syscall_{syscall}_count'] = syscall_counts.get(syscall_clean, 0)
                
                features['unique_syscalls'] = len(syscall_counts)
                features['total_syscalls'] = len(syscalls)
                features['syscall_entropy'] = self.calculate_entropy(list(syscall_counts.values()))
            
            # Process özellikleri
            if 'processName' in df.columns:
                processes = df['processName'].dropna()
                features['unique_processes'] = len(processes.unique())
                features['total_processes'] = len(processes)
                
                # En yaygın process'ler
                common_processes = ['RenderThread', 'Chrome_IOThread', 'Binder', 'pool']
                process_counts = Counter(processes)
                for proc in common_processes:
                    features[f'process_{proc}_count'] = sum(count for name, count in process_counts.items() 
                                                          if proc.lower() in name.lower())
            
            # Zamansal özellikler
            if 'timestamp' in df.columns:
                timestamps = pd.to_numeric(df['timestamp'], errors='coerce').dropna()
                if len(timestamps) > 1:
                    time_diffs = np.diff(timestamps)
                    features['avg_time_diff'] = np.mean(time_diffs)
                    features['std_time_diff'] = np.std(time_diffs)
                    features['max_time_diff'] = np.max(time_diffs)
                    features['min_time_diff'] = np.min(time_diffs)
            
            # Ağ aktivitesi özellikleri
            network_columns = ['sin6_addr', 'sin6_port', 'sa_family']
            for col in network_columns:
                if col in df.columns:
                    features[f'{col}_non_null_count'] = df[col].notna().sum()
            
            # Argüman analizi
            arg_columns = [col for col in df.columns if col.startswith('value')]
            if arg_columns:
                features['avg_args_per_call'] = df[arg_columns].notna().sum(axis=1).mean()
                features['max_args_per_call'] = df[arg_columns].notna().sum(axis=1).max()
            
            return features
            
        except Exception as e:
            print(f"   Hata: {file_path.name} - {str(e)}")
            return None
    
    def calculate_entropy(self, values):
        """Shannon entropisi hesapla"""
        if not values:
            return 0
        
        total = sum(values)
        probabilities = [v/total for v in values if v > 0]
        entropy = -sum(p * np.log2(p) for p in probabilities)
        return entropy
    
    def extract_all_features(self, sample_size_per_class=500):
        """Tüm dosyalardan özellik çıkarımı"""
        print("🔧 Özellik çıkarımı başlatılıyor...")
        
        # Dosya listelerini al
        normal_files = list(self.normal_dir.glob('*.csv'))[:sample_size_per_class]
        malware_files = list(self.malware_dir.glob('*.csv'))[:sample_size_per_class]
        
        print(f"   Normal APK dosyaları: {len(normal_files)}")
        print(f"   Zararlı APK dosyaları: {len(malware_files)}")
        
        all_features = []
        
        # Normal dosyaları işle
        print("    Normal APK dosyaları işleniyor...")
        for i, file in enumerate(normal_files):
            if i % 50 == 0:
                print(f"      Progress: {i}/{len(normal_files)}")
            features = self.extract_features_from_file(file, 0)  # 0 = Normal
            if features:
                all_features.append(features)
        
        # Malware dosyaları işle
        print("    Zararlı APK dosyaları işleniyor...")
        for i, file in enumerate(malware_files):
            if i % 50 == 0:
                print(f"      Progress: {i}/{len(malware_files)}")
            features = self.extract_features_from_file(file, 1)  # 1 = Malware
            if features:
                all_features.append(features)
        
        # DataFrame'e dönüştür
        self.feature_data = pd.DataFrame(all_features)
        
        # Eksik değerleri doldur
        numeric_columns = self.feature_data.select_dtypes(include=[np.number]).columns
        self.feature_data[numeric_columns] = self.feature_data[numeric_columns].fillna(0)
        
        print(f"Özellik çıkarımı tamamlandı! Toplam örnek: {len(self.feature_data)}")
        print(f"Toplam özellik sayısı: {len(self.feature_data.columns) - 2}")  # file_name ve label hariç
        
        # Özellikleri kaydet
        self.feature_data.to_csv(self.results_dir / 'extracted_features.csv', index=False)
        
        return self.feature_data
    
    def prepare_data_for_training(self):
        """Eğitim için veriyi hazırla"""
        print(" Veri eğitim için hazırlanıyor...")
        
        if self.feature_data is None:
            raise ValueError("Önce özellik çıkarımı yapılmalı!")
        
        # Özellik ve hedef değişkenleri ayır
        feature_columns = [col for col in self.feature_data.columns 
                          if col not in ['file_name', 'label']]
        
        X = self.feature_data[feature_columns]
        y = self.feature_data['label']
        
        # Train-test split
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Özellik ölçeklendirme
        self.X_train_scaled = self.scaler.fit_transform(self.X_train)
        self.X_test_scaled = self.scaler.transform(self.X_test)
        
        print(f"Eğitim seti: {len(self.X_train)} örnek")
        print(f"Test seti: {len(self.X_test)} örnek")
        print(f"Özellik sayısı: {self.X_train.shape[1]}")
        
        # Sınıf dağılımını göster
        train_dist = pd.Series(self.y_train).value_counts()
        test_dist = pd.Series(self.y_test).value_counts()
        
        print("\n Sınıf Dağılımları:")
        print(f"   Eğitim - Normal: {train_dist.get(0, 0)}, Zararlı: {train_dist.get(1, 0)}")
        print(f"   Test - Normal: {test_dist.get(0, 0)}, Zararlı: {test_dist.get(1, 0)}")
    
    def train_models(self):
        """Çoklu model eğitimi"""
        print("Model eğitimi başlatılıyor...")
        
        # Model tanımları
        models_config = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100, 
                random_state=42, 
                n_jobs=-1,
                max_depth=10
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=6
            ),
            'SVM': SVC(
                probability=True,
                random_state=42,
                kernel='rbf'
            ),
            'Neural Network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                random_state=42,
                max_iter=500
            )
        }
        
        # Her modeli eğit
        for name, model in models_config.items():
            print(f"   🏋️ {name} eğitiliyor...")
            
            # Veri seçimi (SVM ve NN için scaled, diğerleri için original)
            if name in ['SVM', 'Neural Network']:
                X_train_use = self.X_train_scaled
                X_test_use = self.X_test_scaled
            else:
                X_train_use = self.X_train
                X_test_use = self.X_test
            
            # Modeli eğit
            model.fit(X_train_use, self.y_train)
            
            # Tahminler
            y_pred = model.predict(X_test_use)
            y_pred_proba = model.predict_proba(X_test_use)[:, 1]
            
            # Metrikleri hesapla
            accuracy = accuracy_score(self.y_test, y_pred)
            precision = precision_score(self.y_test, y_pred)
            recall = recall_score(self.y_test, y_pred)
            f1 = f1_score(self.y_test, y_pred)
            auc = roc_auc_score(self.y_test, y_pred_proba)
            
            # Cross-validation
            if name in ['SVM', 'Neural Network']:
                cv_scores = cross_val_score(model, self.X_train_scaled, self.y_train, cv=5)
            else:
                cv_scores = cross_val_score(model, self.X_train, self.y_train, cv=5)
            
            # Sonuçları kaydet
            self.models[name] = model
            self.results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_score': auc,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'y_pred': y_pred,
                'y_pred_proba': y_pred_proba,
                'confusion_matrix': confusion_matrix(self.y_test, y_pred)
            }
            
            print(f"      Accuracy: {accuracy:.4f}, AUC: {auc:.4f}, CV: {cv_scores.mean():.4f}±{cv_scores.std():.4f}")
        
        print(" Tüm modeller eğitildi!")
    
    def create_ml_visualizations(self):
        """ML sonuçlarının görselleştirilmesi"""
        print("ML görselleştirmeleri oluşturuluyor...")
        
        # 1. Model performans karşılaştırması
        self.plot_model_comparison()
        
        # 2. Confusion matrix'ler
        self.plot_confusion_matrices()
        
        # 3. ROC eğrileri
        self.plot_roc_curves()
        
        # 4. Feature importance (Random Forest için)
        self.plot_feature_importance()
        
        # 5. Sınıf dağılımları
        self.plot_class_distributions()
        
        print("Tüm ML görselleştirmeleri oluşturuldu!")
    
    def plot_model_comparison(self):
        """Model performans karşılaştırması"""
        metrics = ['accuracy', 'precision', 'recall', 'f1_score', 'auc_score']
        model_names = list(self.results.keys())
        
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        axes = axes.flatten()
        
        for i, metric in enumerate(metrics):
            values = [self.results[model][metric] for model in model_names]
            colors = ['skyblue', 'lightgreen', 'lightcoral', 'gold']
            
            bars = axes[i].bar(model_names, values, color=colors[:len(model_names)])
            axes[i].set_title(f'{metric.upper()} Karşılaştırması', fontweight='bold')
            axes[i].set_ylabel(metric.upper())
            axes[i].set_ylim(0, 1)
            
            # Değerleri bar üzerine ekle
            for bar, value in zip(bars, values):
                axes[i].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                           f'{value:.3f}', ha='center', va='bottom')
            
            axes[i].tick_params(axis='x', rotation=45)
        
        # Cross-validation skorları
        cv_means = [self.results[model]['cv_mean'] for model in model_names]
        cv_stds = [self.results[model]['cv_std'] for model in model_names]
        
        axes[5].bar(model_names, cv_means, yerr=cv_stds, capsize=5, 
                   color=['skyblue', 'lightgreen', 'lightcoral', 'gold'][:len(model_names)])
        axes[5].set_title('Cross-Validation Skorları', fontweight='bold')
        axes[5].set_ylabel('CV Score')
        axes[5].set_ylim(0, 1)
        axes[5].tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'model_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_confusion_matrices(self):
        """Confusion matrix görselleştirmeleri"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        axes = axes.flatten()
        
        for i, (model_name, results) in enumerate(self.results.items()):
            cm = results['confusion_matrix']
            
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                       xticklabels=['Normal', 'Zararlı'],
                       yticklabels=['Normal', 'Zararlı'],
                       ax=axes[i])
            
            axes[i].set_title(f'{model_name} - Confusion Matrix', fontweight='bold')
            axes[i].set_xlabel('Tahmin Edilen')
            axes[i].set_ylabel('Gerçek')
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_roc_curves(self):
        """ROC eğrileri"""
        plt.figure(figsize=(10, 8))
        
        colors = ['blue', 'green', 'red', 'orange']
        
        for i, (model_name, results) in enumerate(self.results.items()):
            fpr, tpr, _ = roc_curve(self.y_test, results['y_pred_proba'])
            auc_score = results['auc_score']
            
            plt.plot(fpr, tpr, color=colors[i], linewidth=2,
                    label=f'{model_name} (AUC = {auc_score:.3f})')
        
        plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Eğrileri Karşılaştırması', fontweight='bold', fontsize=14)
        plt.legend(loc="lower right")
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'roc_curves.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_feature_importance(self):
        """Feature importance (Random Forest için)"""
        if 'Random Forest' not in self.models:
            return
        
        model = self.models['Random Forest']
        importances = model.feature_importances_
        feature_names = self.X_train.columns
        
        # En önemli 20 özelliği al
        indices = np.argsort(importances)[::-1][:20]
        
        plt.figure(figsize=(12, 8))
        plt.bar(range(20), importances[indices])
        plt.xticks(range(20), [feature_names[i] for i in indices], rotation=45, ha='right')
        plt.xlabel('Özellikler')
        plt.ylabel('Önem Skoru')
        plt.title('En Önemli 20 Özellik (Random Forest)', fontweight='bold', fontsize=14)
        plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def plot_class_distributions(self):
        """Sınıf dağılımları"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Eğitim seti dağılımı
        train_counts = pd.Series(self.y_train).value_counts()
        ax1.pie(train_counts.values, labels=['Normal', 'Zararlı'], autopct='%1.1f%%',
               colors=['lightgreen', 'lightcoral'])
        ax1.set_title('Eğitim Seti Sınıf Dağılımı', fontweight='bold')
        
        # Test seti dağılımı
        test_counts = pd.Series(self.y_test).value_counts()
        ax2.pie(test_counts.values, labels=['Normal', 'Zararlı'], autopct='%1.1f%%',
               colors=['lightgreen', 'lightcoral'])
        ax2.set_title('Test Seti Sınıf Dağılımı', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.results_dir / 'class_distributions.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def generate_ml_report(self):
        """ML raporu oluştur"""
        print("ML raporu oluşturuluyor...")
        
        # En iyi modeli bul
        best_model_name = max(self.results.keys(), 
                             key=lambda x: self.results[x]['auc_score'])
        best_results = self.results[best_model_name]
        
        # JSON raporu
        report_data = {
            "Mobil Güvenlik ML Raporu": {
                "Tarih": pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Veri Seti Bilgileri": {
                    "Toplam örnek sayısı": len(self.feature_data),
                    "Özellik sayısı": self.X_train.shape[1],
                    "Eğitim seti boyutu": len(self.X_train),
                    "Test seti boyutu": len(self.X_test)
                },
                "Model Performansları": {}
            }
        }
        
        # Her modelin sonuçlarını ekle
        for model_name, results in self.results.items():
            report_data["Mobil Güvenlik ML Raporu"]["Model Performansları"][model_name] = {
                "Accuracy": results['accuracy'],
                "Precision": results['precision'],
                "Recall": results['recall'],
                "F1-Score": results['f1_score'],
                "AUC Score": results['auc_score'],
                "CV Mean": results['cv_mean'],
                "CV Std": results['cv_std']
            }
        
        report_data["Mobil Güvenlik ML Raporu"]["En İyi Model"] = {
            "Model Adı": best_model_name,
            "AUC Score": best_results['auc_score'],
            "Accuracy": best_results['accuracy']
        }
        
        # JSON dosyasını kaydet
        with open(self.results_dir / 'ml_report.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        # Metin raporu
        with open(self.results_dir / 'ml_report.txt', 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("MOBİL GÜVENLİK VERİ SETİ - MAKİNE ÖĞRENMESİ RAPORU\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Rapor Tarihi: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("VERİ SETİ BİLGİLERİ:\n")
            f.write("-" * 20 + "\n")
            f.write(f"• Toplam örnek sayısı: {len(self.feature_data)}\n")
            f.write(f"• Özellik sayısı: {self.X_train.shape[1]}\n")
            f.write(f"• Eğitim seti boyutu: {len(self.X_train)}\n")
            f.write(f"• Test seti boyutu: {len(self.X_test)}\n\n")
            
            f.write("MODEL PERFORMANSLARI:\n")
            f.write("-" * 20 + "\n")
            for model_name, results in self.results.items():
                f.write(f"\n{model_name}:\n")
                f.write(f"  - Accuracy: {results['accuracy']:.4f}\n")
                f.write(f"  - Precision: {results['precision']:.4f}\n")
                f.write(f"  - Recall: {results['recall']:.4f}\n")
                f.write(f"  - F1-Score: {results['f1_score']:.4f}\n")
                f.write(f"  - AUC Score: {results['auc_score']:.4f}\n")
                f.write(f"  - CV Score: {results['cv_mean']:.4f} ± {results['cv_std']:.4f}\n")
            
            f.write(f"\nEN İYİ MODEL:\n")
            f.write("-" * 12 + "\n")
            f.write(f"• Model: {best_model_name}\n")
            f.write(f"• AUC Score: {best_results['auc_score']:.4f}\n")
            f.write(f"• Accuracy: {best_results['accuracy']:.4f}\n")
            
            f.write(f"\nOLUŞTURULAN DOSYALAR:\n")
            f.write("-" * 20 + "\n")
            f.write("• extracted_features.csv - Çıkarılan özellikler\n")
            f.write("• model_comparison.png - Model karşılaştırması\n")
            f.write("• confusion_matrices.png - Confusion matrix'ler\n")
            f.write("• roc_curves.png - ROC eğrileri\n")
            f.write("• feature_importance.png - Özellik önemi\n")
            f.write("• class_distributions.png - Sınıf dağılımları\n")
        
        # Modelleri kaydet
        for model_name, model in self.models.items():
            with open(self.results_dir / f'{model_name.lower().replace(" ", "_")}_model.pkl', 'wb') as f:
                pickle.dump(model, f)
        
        # Scaler'ı kaydet
        with open(self.results_dir / 'scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print("ML raporu oluşturuldu!")
        print(f"En iyi model: {best_model_name} (AUC: {best_results['auc_score']:.4f})")
    
    def run_complete_pipeline(self, sample_size_per_class=300):
        """Tam ML pipeline'ını çalıştır"""
        print("🚀 Makine Öğrenmesi Pipeline başlatılıyor...\n")
        
        # 1. Özellik çıkarımı
        self.extract_all_features(sample_size_per_class)
        print()
        
        # 2. Veri hazırlama
        self.prepare_data_for_training()
        print()
        
        # 3. Model eğitimi
        self.train_models()
        print()
        
        # 4. Görselleştirmeler
        self.create_ml_visualizations()
        print()
        
        # 5. Rapor oluşturma
        self.generate_ml_report()
        print()
        
        print("🎉 Makine Öğrenmesi Pipeline tamamlandı!")
        print(f"Sonuçlar '{self.results_dir}' klasöründe saklandı.")
        print("\nOluşturulan dosyalar:")
        for file in sorted(self.results_dir.glob('*')):
            print(f"  • {file.name}")

if __name__ == "__main__":
    # ML Pipeline'ı çalıştır
    ml_pipeline = MobileSecurityMLPipeline()
    ml_pipeline.run_complete_pipeline(sample_size_per_class=300) 