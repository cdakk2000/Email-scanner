import imaplib
import email
from email.header import decode_header
import requests
import base64
from bs4 import BeautifulSoup
import csv
from datetime import datetime

# Konfiguracja
VIRUSTOTAL_API_KEY = "d05425343df1c3131a6fa0fc946c0eb7dd0b1792aed439bc31e193bcd83b9b44"
EMAIL_ACCOUNT = "basia.grzana.test@wp.pl"
EMAIL_PASSWORD = "Grzanka123"
IMAP_SERVER = "imap.wp.pl"
CSV_LOG_FILE = "analiza_maili.csv"
PHISHING_KEYWORDS = [
    "kliknij tutaj", "twoje konto zostało zablokowane", "pilna wiadomość",
    "natychmiastowe działanie", "zaloguj się", "zresetuj hasło", "potwierdź swoje dane",
    "transakcja została wstrzymana", "wyciek danych", "twój bank", "potwierdzenie tożsamości"
]

# Sprawdzenie czy link jest podejrzany

def is_suspicious_link(link):
    try:
        url_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0
        else:
            print(f"Błąd sprawdzania linku: {response.status_code}, {response.text}")
    except Exception as e:
        print(f"❗ Błąd analizy linku: {e}")
    return False

# Ekstrakcja linków z HTML

def extract_links_from_email(msg):
    links = []
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))
        if "text/html" in content_type and "attachment" not in content_disposition:
            html = part.get_payload(decode=True).decode(errors="ignore")
            soup = BeautifulSoup(html, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                links.append(a_tag["href"])
    return links

# Analiza SPF/DKIM

def analyze_headers(msg):
    results = msg.items()
    auth_results = [v for k, v in results if k.lower() == "authentication-results"]
    spf_status = dkim_status = "nieznany"

    for res in auth_results:
        if "spf=fail" in res.lower():
            spf_status = "fail"
        elif "spf=pass" in res.lower():
            spf_status = "pass"
        if "dkim=fail" in res.lower():
            dkim_status = "fail"
        elif "dkim=pass" in res.lower():
            dkim_status = "pass"
    return spf_status, dkim_status

# Analiza tresci

def analyze_content(msg):
    suspicious_phrases = 0
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))
        if "text/plain" in content_type and "attachment" not in content_disposition:
            try:
                body = part.get_payload(decode=True).decode(errors="ignore").lower()
                for phrase in PHISHING_KEYWORDS:
                    if phrase in body:
                        suspicious_phrases += 1
            except Exception as e:
                print(f"❗ Błąd analizy treści: {e}")
    return suspicious_phrases

# Logowanie wyników

def log_result(date, sender, subject, total_links, suspicious_links, classification):
    with open(CSV_LOG_FILE, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow([date, sender, subject, total_links, suspicious_links, classification])

# Główna funkcja pobierająca e-mail i analizująca

def fetch_and_analyze():
    mail = imaplib.IMAP4_SSL(IMAP_SERVER)
    mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
    mail.select("inbox")

    status, messages = mail.search(None, 'ALL')
    messages = messages[0].split()
    latest_email_id = messages[-1]

    status, msg_data = mail.fetch(latest_email_id, "(RFC822)")
    for response_part in msg_data:
        if isinstance(response_part, tuple):
            msg = email.message_from_bytes(response_part[1])

            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else "utf-8")
            sender = msg.get("From")
            date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            links = extract_links_from_email(msg)
            suspicious_text = analyze_content(msg)
            suspicious_count = sum(1 for link in links if is_suspicious_link(link))

            spf_status, dkim_status = analyze_headers(msg)

            is_suspicious = (
                    suspicious_count > 0
                    or suspicious_text > 0
                    or spf_status == "fail"
                    or dkim_status == "fail"
                    )

            classification = "podejrzana" if is_suspicious else "bezpieczna"

            print(f"Data: {date}\nFrom: {sender}\nSubject: {subject}\nLiczba linków: {len(links)}\nPodejrzane: {suspicious_count}\nSPF: {spf_status}\nDKIM: {dkim_status}\nKlasyfikacja: {classification}\nPodejrzane słowa kluczowe: {suspicious_text}")

            log_result(date, sender, subject, len(links), suspicious_count, classification)

# Uruchom analizę
fetch_and_analyze()
