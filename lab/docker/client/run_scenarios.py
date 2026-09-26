"""Client scenarios for the Docker lab (stdlib only). Certificates are lab self-signed."""
import imaplib, poplib, smtplib, ssl, sys, time
host = sys.argv[1]
time.sleep(5)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
msg = "Subject: lab\r\n\r\nlab message\r\n"
s = smtplib.SMTP(host, 25); s.starttls(context=ctx); s.sendmail("a@lab.test", ["alice@mail.lab.test"], msg); s.quit()
s = smtplib.SMTP_SSL(host, 465, context=ctx); s.quit()
m = imaplib.IMAP4(host, 143); m.starttls(ssl_context=ctx); m.login("alice", "lab-password"); m.logout()
m = imaplib.IMAP4_SSL(host, 993, ssl_context=ctx); m.login("alice", "lab-password"); m.logout()
p = poplib.POP3(host, 110); p.stls(context=ctx); p.user("alice"); p.pass_("lab-password"); p.quit()
p = poplib.POP3_SSL(host, 995, context=ctx); p.user("alice"); p.pass_("lab-password"); p.quit()
s = smtplib.SMTP(host, 25); s.sendmail("a@lab.test", ["alice@mail.lab.test"], msg); s.quit()  # plaintext
print("scenarios done")
