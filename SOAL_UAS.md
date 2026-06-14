Berikut adalah transkripsi soal dari file gambar Soal_UAS_Perancangan big data.jpeg dari nomor 1 sampai 4, bagian per bagian:

Repository: https://bit.ly/UASDSD01 Gunakan Email student untuk mengunduh repository diatas

1. Data Discovery,

a) Load dataset event, user, dan asset. (5)
b) Tampilkan schema, jumlah baris, missing value, duplicate event_id, dan distribusi action/status/classification. (5)
c) Identifikasi 5 user paling aktif dan 5 asset paling sering diakses. (10)
d) Buat data dictionary ringkas untuk minimal 10 kolom utama. (10)

2. Data Science,

a) Buat minimal 5 fitur analitik, contoh: event_per_user, failed_login_rate, total_bytes_out, access_to_restricted_ratio, avg_latency. (5)
b) Lakukan exploratory data analysis dengan minimal 3 visualisasi. (5)
c) Buat model sederhana untuk mendeteksi anomali atau klasifikasi label. Boleh memakai rule-based, IsolationForest, RandomForest, atau LogisticRegression. (10)
d) Evaluasi hasil dengan confusion matrix, precision, recall, dan F1-score. Jelaskan metrik mana yang paling penting untuk kasus keamanan data. (10)

3. Data Security,

a) Temukan minimal 3 pola risiko, misalnya akses oleh terminated user, download besar dari data confidential/restricted, atau permission change dari IP eksternal. (5)
b) Buat fungsi security_alert(event) yang mengeluarkan level: LOW, MEDIUM, HIGH, CRITICAL. (5)
c) Simulasikan pemrosesan streaming dari stream_generator.py dan cetak alert real-time. (10)
d) Berikan rekomendasi mitigasi untuk masing-masing pola risiko. (10)

4. Hasil

a) Buat laporan berisi ringkasan temuan, tabel top alert, visualisasi, dan rekomendasi bisnis/teknis. (5)
b) Tambahkan dashboard sederhana Streamlit atau visualisasi interaktif untuk monitoring alert. (5)