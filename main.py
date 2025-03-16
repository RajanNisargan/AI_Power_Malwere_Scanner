import os
import hashlib
import requests
import threading
import tkinter as tk
import customtkinter as ctk
from tkinter import filedialog, messagebox
from urllib.parse import urlparse
import time
import base64

# VirusTotal API Key
API_KEY = '60cac5a5c354fa6e765638fbbbb3cb060c26d7f6167a36a7b1b81748632353f3'

# Initialize GUI
ctk.set_appearance_mode('Dark')
ctk.set_default_color_theme('blue')


class MalwareScanner(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title('🚀 AI Malware Scanner')
        self.geometry('900x600')
        self.configure(bg='#0f0f0f')

        self.tabview = ctk.CTkTabview(self, width=850, height=500)
        self.tabview.pack(fill='both', expand=True, padx=20, pady=20)

        self.file_scan_tab = self.tabview.add('📂 File Scanner')
        self.url_scan_tab = self.tabview.add('🌐 URL Scanner')

        self.create_file_scan_tab()
        self.create_url_scan_tab()

    def create_file_scan_tab(self):
        self.file_label = ctk.CTkLabel(self.file_scan_tab, text='Select File to Scan', font=('Arial', 18, 'bold'))
        self.file_label.pack(pady=15)

        self.file_button = ctk.CTkButton(self.file_scan_tab, text='Browse File', command=self.start_file_scan,
                                         corner_radius=10)
        self.file_button.pack(pady=15)

        self.file_progress = ctk.CTkProgressBar(self.file_scan_tab, width=500, mode='indeterminate')
        self.file_progress.pack(pady=15)

        self.file_result = ctk.CTkLabel(self.file_scan_tab, text='', font=('Arial', 14), text_color='#00FF00')
        self.file_result.pack(pady=15)

    def create_url_scan_tab(self):
        self.url_label = ctk.CTkLabel(self.url_scan_tab, text='Enter URL to Scan', font=('Arial', 18, 'bold'))
        self.url_label.pack(pady=15)

        self.url_entry = ctk.CTkEntry(self.url_scan_tab, width=500, placeholder_text='https://example.com')
        self.url_entry.pack(pady=15)

        self.url_button = ctk.CTkButton(self.url_scan_tab, text='Scan URL', command=self.start_url_scan,
                                        corner_radius=10)
        self.url_button.pack(pady=15)

        self.url_progress = ctk.CTkProgressBar(self.url_scan_tab, width=500, mode='indeterminate')
        self.url_progress.pack(pady=15)

        self.url_result = ctk.CTkLabel(self.url_scan_tab, text='', font=('Arial', 14), text_color='#00FF00')
        self.url_result.pack(pady=15)

    def start_file_scan(self):
        thread = threading.Thread(target=self.scan_file)
        thread.start()

    def start_url_scan(self):
        thread = threading.Thread(target=self.scan_url)
        thread.start()

    def compute_file_hash(self, file_path):
        """Compute SHA-256 hash of the given file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        self.file_progress.start()
        self.file_result.configure(text='🔍 Analyzing File...')

        file_hash = self.compute_file_hash(file_path)
        result = self.check_file_virustotal(file_hash, file_path)

        self.file_result.configure(text=result)
        self.file_progress.stop()

        if 'Malicious' in result:
            if messagebox.askyesno('Malicious File Detected', 'Do you want to delete the file?'):
                os.remove(file_path)
                messagebox.showinfo('Deleted', 'The file has been deleted successfully.')

    def scan_url(self):
        url = self.url_entry.get()
        if not url:
            messagebox.showwarning('Warning', 'Please enter a URL')
            return

        self.url_progress.start()
        self.url_result.configure(text='🔍 Analyzing URL...')

        result = self.check_url_virustotal(url)

        self.url_result.configure(text=result)
        self.url_progress.stop()

    def check_file_virustotal(self, file_hash, file_path):
        headers = {'x-apikey': API_KEY}
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                analysis_result = response.json()
                malicious_count = analysis_result['data']['attributes']['last_analysis_stats']['malicious']

                if malicious_count > 0:
                    return f'⚠️ Malicious File Detected ({malicious_count} detections)'
                else:
                    return '✅ File is Safe'
            else:
                return '❌ Error: File not found in VirusTotal database. Consider uploading it for scanning.'

        except Exception as e:
            return f'❌ Error: {str(e)}'

    def check_url_virustotal(self, url):
        headers = {'x-apikey': API_KEY}

        try:
            # Submit URL for analysis
            response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers,
                                     data={'url': url})

            if response.status_code == 200:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

                # Retrieve URL analysis
                analysis_response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)

                if analysis_response.status_code == 200:
                    analysis_result = analysis_response.json()
                    positives = analysis_result['data']['attributes']['last_analysis_stats']['malicious']

                    if positives > 0:
                        return f'⚠️ Malicious URL Detected ({positives} detections)'
                    return '✅ URL is Safe'

            return '❌ Error: Could not retrieve URL analysis'

        except Exception as e:
            return f'❌ Error: {str(e)}'


if __name__ == '__main__':
    app = MalwareScanner()
    app.mainloop()
