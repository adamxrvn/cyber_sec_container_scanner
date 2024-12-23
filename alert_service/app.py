# main.py
import os

import uvicorn
from fastapi import FastAPI, HTTPException
from typing import List
import smtplib
from email.message import EmailMessage

from models import init_db, SessionLocal, Alert, AuditLog
from schemas import (
    AlertCreate, AlertRead,
    AuditLogCreate, AuditLogRead
)

app = FastAPI(
    title="Alerting Microservice",
    description="Sends alert emails to users and logs them in audit logs",
    version="1.0.0"
)

init_db()

##############################################################################
# 1) Helper: send_email
##############################################################################
def send_email_alert(to_email: str, subject: str, body: str):
    """
    Send an email using smtplib.
    """

    SMTP_HOST = "smtp.mailersend.net"
    SMTP_PORT = 587  # or 25, or whatever
    FROM_EMAIL = "MS_2uUEnA@trial-pq3enl6odr5l2vwr.mlsender.net"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email
    msg.set_content(body)

    try:
        server =  smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        # If your SMTP requires login:
        server.login( "MS_2uUEnA@trial-pq3enl6odr5l2vwr.mlsender.net", "CPRA0oOvA4G8gfvW")
        server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


##############################################################################
# 2) CRUD for ALERT (tags=["Alerts"])
##############################################################################
@app.post("/alert", response_model=AlertRead, tags=["Alerts"])
def create_alert(alert_data: AlertCreate):
    """
    Create a new alert entry in the DB (without sending an email).
    """
    db = SessionLocal()
    try:
        new_alert = Alert(
            alert_type=alert_data.alert_type,
            message=alert_data.message,
            user_email=alert_data.user_email
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        return new_alert
    finally:
        db.close()


@app.get("/alert", response_model=List[AlertRead], tags=["Alerts"])
def list_alerts():
    """
    List all alerts in the DB.
    """
    db = SessionLocal()
    try:
        rows = db.query(Alert).all()
        return rows
    finally:
        db.close()


@app.get("/alert/{alert_id}", response_model=AlertRead, tags=["Alerts"])
def get_alert(alert_id: int):
    """
    Get a single alert by ID.
    """
    db = SessionLocal()
    try:
        row = db.query(Alert).get(alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        return row
    finally:
        db.close()


@app.put("/alert/{alert_id}", response_model=AlertRead, tags=["Alerts"])
def update_alert(alert_id: int, alert_data: AlertCreate):
    """
    Update an existing alert's type/message/email.
    """
    db = SessionLocal()
    try:
        row = db.query(Alert).get(alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        row.alert_type = alert_data.alert_type
        row.message = alert_data.message
        row.user_email = alert_data.user_email
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


@app.delete("/alert/{alert_id}", tags=["Alerts"])
def delete_alert(alert_id: int):
    """
    Delete an alert by ID.
    """
    db = SessionLocal()
    try:
        row = db.query(Alert).get(alert_id)
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        db.delete(row)
        db.commit()
        return {"message": f"Alert ID {alert_id} deleted."}
    finally:
        db.close()


##############################################################################
# 3) CRUD for AUDIT LOG (tags=["AuditLogs"])
##############################################################################
@app.post("/auditlog", response_model=AuditLogRead, tags=["AuditLogs"])
def create_auditlog(log_data: AuditLogCreate):
    """
    Create a new audit log entry.
    """
    db = SessionLocal()
    try:
        # Check if alert_id is valid (optional)
        if log_data.alert_id:
            alert_check = db.query(Alert).get(log_data.alert_id)
            if not alert_check:
                raise HTTPException(status_code=400, detail="Invalid alert_id")

        new_log = AuditLog(
            alert_id=log_data.alert_id,
            action=log_data.action,
            details=log_data.details
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log)
        return new_log
    finally:
        db.close()


@app.get("/auditlog", response_model=List[AuditLogRead], tags=["AuditLogs"])
def list_auditlogs():
    """
    List all audit log entries.
    """
    db = SessionLocal()
    try:
        rows = db.query(AuditLog).all()
        return rows
    finally:
        db.close()


@app.get("/auditlog/{log_id}", response_model=AuditLogRead, tags=["AuditLogs"])
def get_auditlog(log_id: int):
    """
    Get a single audit log entry by ID.
    """
    db = SessionLocal()
    try:
        row = db.query(AuditLog).get(log_id)
        if not row:
            raise HTTPException(status_code=404, detail="AuditLog not found")
        return row
    finally:
        db.close()


@app.put("/auditlog/{log_id}", response_model=AuditLogRead, tags=["AuditLogs"])
def update_auditlog(log_id: int, log_data: AuditLogCreate):
    """
    Update an audit log's action/details.
    """
    db = SessionLocal()
    try:
        row = db.query(AuditLog).get(log_id)
        if not row:
            raise HTTPException(status_code=404, detail="AuditLog not found")
        row.alert_id = log_data.alert_id
        row.action = log_data.action
        row.details = log_data.details
        db.commit()
        db.refresh(row)
        return row
    finally:
        db.close()


@app.delete("/auditlog/{log_id}", tags=["AuditLogs"])
def delete_auditlog(log_id: int):
    """
    Delete an audit log entry.
    """
    db = SessionLocal()
    try:
        row = db.query(AuditLog).get(log_id)
        if not row:
            raise HTTPException(status_code=404, detail="AuditLog not found")
        db.delete(row)
        db.commit()
        return {"message": f"AuditLog ID {log_id} deleted."}
    finally:
        db.close()


##############################################################################
# 4) Specialized endpoint: /alert/send
##############################################################################
@app.post("/alert/send", response_model=AlertRead, tags=["Alerts"])
def send_alert(alert_data: AlertCreate):
    """
    Creates an alert in the DB, attempts to send email to user_email,
    and logs the action in the audit log.
    """
    db = SessionLocal()
    try:
        # 1) Create the alert row
        new_alert = Alert(
            alert_type=alert_data.alert_type,
            message=alert_data.message,
            user_email=alert_data.user_email
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)

        # 2) Attempt to send email
        subject = f"[{alert_data.alert_type}] Alert Notification"
        body = f"{alert_data.message}\n\n"
        success = send_email_alert(
            to_email=alert_data.user_email,
            subject=subject,
            body=body
        )

        # 3) Create an audit log
        action_str = "Alert Created & Email Sent" if success else "Alert Created & Email Failed"
        new_log = AuditLog(
            alert_id=new_alert.id,
            action=action_str,
            details=f"Sent to {alert_data.user_email}"
        )
        db.add(new_log)
        db.commit()
        db.refresh(new_log)

        if not success:
            # If you want to return an error if email failed,
            # you could raise an HTTPException here.
            # Or just proceed with success. We'll proceed as "OK" but note in logs.
            pass

        return new_alert
    finally:
        db.close()


##############################################################################
# 5) Run if main
##############################################################################
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
