from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import envs



def validate_username(username):
    if not username[0].isalnum() or not username[-1].isalnum():
        return 0
    for c in username:
        if not c.isalnum():
            if c != '.' and c != '_' and c != '-':
                return 0
    return 1

def validate_password(password):
    for c in password:
        if c == " ":
            return 0
    if len(password) < 6:
        return 0
    if password.isalpha():
        return 0
    if password.isnumeric():
        return 0
    return 1



def validate_email(email):
    pos_AT = 0
    count_AT = 0
    count_DT = 0
    if email[0] == '@' or email[-1] == '@':
        return 0
    if email[0] == '.' or email[-1] == '.':
        return 0
    for c in range(len(email)):
        if email[c] == '@':
            pos_AT = c
            count_AT = count_AT + 1
    if count_AT != 1:
        return 0
        
    username = email[0:pos_AT]
    if not username[0].isalnum() or not username[-1].isalnum():
        return 0
    for d in range(len(email)):
        if email[d] == '.':
            if d == (pos_AT+1):
                return 0
            if d > pos_AT:
                word = email[(pos_AT+1):d]
                if not word.isalnum():
                    return 0
                pos_AT = d
                count_DT = count_DT + 1
    if count_DT < 1 or count_DT > 2:
        return 0
        
    return 1


def sendmail(email, subject, message):
    msg = MIMEMultipart("alternative")
    msg["From"] = envs.email_address
    msg["To"] = email
    msg["Subject"] = subject
    msg.attach(MIMEText(message, 'html'))
    server = smtplib.SMTP("smtp-mail.outlook.com", 587)
    server.starttls()
    server.login(envs.email_address, envs.email_password)
    server.sendmail(envs.email_address, email, msg.as_string())
    server.quit()