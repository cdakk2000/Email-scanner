import imaplib
import email
from bs4 import BeautifulSoup

# Dane logowania
IMAP_SERVER = "imap.wp.pl"
EMAIL_ACCOUNT = "basia.grzana.test@wp.pl"
EMAIL_PASSWORD = "Grzanka123"

# Połączenie z serwerem IMAP
mail = imaplib.IMAP4_SSL(IMAP_SERVER)
mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
mail.select("inbox")  

# Pobranie ID najnowszych e-maili
status, messages = mail.search(None, "ALL")
mail_ids = messages[0].split()

# Pobranie najnowszego e-maila
latest_email_id = mail_ids[-1]
status, msg_data = mail.fetch(latest_email_id, "(RFC822)")

# Przetwarzanie wiadomości
for response_part in msg_data:
    if isinstance(response_part, tuple):
        msg = email.message_from_bytes(response_part[1])
        subject = msg["subject"]
        from_email = msg["from"]
        
        # Obsługa treści wiadomości
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if "text/plain" in content_type or "text/html" in content_type:
                    body = part.get_payload(decode=True).decode()
                    if "text/html" in content_type:
                        soup = BeautifulSoup(body, "html.parser")
                        body = soup.get_text()
                    print(f"From: {from_email}\nSubject: {subject}\nBody:\n{body[:500]}")
        else:
            print(f"From: {from_email}\nSubject: {subject}\nBody:\n{msg.get_payload(decode=True).decode()}")

# Zamknięcie połączenia
mail.logout()
