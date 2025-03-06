from celery import shared_task
from django.conf import settings
from .models import Appointment, Payment, Notification, Message
from twilio.rest import Client
import requests
import arrow
import logging
from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from .models import User

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_reset_email(self, user_id, uid, token):
    """
    Celery task to send a password reset email asynchronously.
    Constructs a reset URL and sends the email to the user.
    """
    try:
        user = User.objects.get(pk=user_id)
        subject = "Password Reset Request"
        # Construct the password reset URL using a frontend URL from settings.
        reset_url = f"{settings.FRONTEND_URL}/reset-password/?uid={uid}&token={token}"
        message = (
            f"Hello {user.email},\n\n"
            "We received a request to reset your password.\n"
            "Please click the link below to reset your password:\n\n"
            f"{reset_url}\n\n"
            "If you did not request a password reset, please ignore this email.\n\n"
            "Thank you."
        )
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        logger.info(f"Password reset email successfully sent to {user.email}")
    except User.DoesNotExist:
        logger.error("User does not exist in send_reset_email task.")
    except Exception as exc:
        logger.error(f"Error sending reset email: {exc}")
        raise self.retry(exc=exc)




# --- Appointment Reminder Task ---
@shared_task
def send_appointment_reminder_task(appointment_id):
    try:
        appointment = Appointment.objects.get(pk=appointment_id)
    except Appointment.DoesNotExist:
        logger.error(f"Appointment {appointment_id} not found.")
        return "Appointment not found"

    # Format scheduled time using arrow
    appt_time = arrow.get(appointment.scheduled_time, str(appointment.time_zone))
    message_body = f"Reminder: You have an appointment at {appt_time.format('h:mm A')}."

    # Send SMS via Twilio
    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    try:
        msg = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_NUMBER,
            to=appointment.patient.phone  # assuming the patient field has a 'phone' attribute
        )
        logger.info(f"Sent appointment reminder SMS: {msg.sid}")
        return msg.sid
    except Exception as e:
        logger.error(f"Error sending SMS for appointment {appointment_id}: {e}")
        return str(e)

# --- Payment Processing Task (Mpesa) ---
@shared_task
def process_mpesa_payment_task(payment_id):
    try:
        payment = Payment.objects.get(pk=payment_id)
    except Payment.DoesNotExist:
        logger.error(f"Payment {payment_id} not found.")
        return "Payment not found"

    payload = {
        "BusinessShortCode": settings.MPESA_SHORT_CODE,
        "Password": settings.MPESA_PASSWORD,
        "Timestamp": settings.MPESA_TIMESTAMP,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": payment.amount,
        "PartyA": payment.patient.phone,  # assuming patient has a phone field
        "PartyB": settings.MPESA_SHORT_CODE,
        "PhoneNumber": payment.patient.phone,
        "CallBackURL": settings.MPESA_CALLBACK_URL,
        "AccountReference": f"Payment{payment_id}",
        "TransactionDesc": "Payment for appointment",
    }
    headers = {"Authorization": f"Bearer {settings.MPESA_ACCESS_TOKEN}"}
    try:
        response = requests.post(settings.MPESA_API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            payment.status = "processed"
        else:
            payment.status = "failed"
        payment.save()
        logger.info(f"Processed payment {payment_id}: {response.json()}")
        return response.json()
    except Exception as e:
        logger.error(f"Error processing Mpesa payment {payment_id}: {e}")
        payment.status = "failed"
        payment.save()
        return str(e)

# --- Notification Task using Twilio ---
@shared_task
def send_twilio_notification_task(notification_id):
    try:
        notification = Notification.objects.get(pk=notification_id)
    except Notification.DoesNotExist:
        logger.error(f"Notification {notification_id} not found.")
        return "Notification not found"

    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message_body = f"Notification: {notification.title} - {notification.message}"
    try:
        msg = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_NUMBER,
            to=notification.user.phone  # assuming user has phone attribute
        )
        notification.status = "sent"
        notification.save()
        logger.info(f"Sent notification SMS: {msg.sid}")
        return msg.sid
    except Exception as e:
        logger.error(f"Error sending notification {notification_id}: {e}")
        return str(e)

# --- Messaging Task using Twilio ---
@shared_task
def send_twilio_message_task(message_id):
    try:
        msg_obj = Message.objects.get(pk=message_id)
    except Message.DoesNotExist:
        logger.error(f"Message {message_id} not found.")
        return "Message not found"

    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    message_body = f"New message from {msg_obj.sender.email}: {msg_obj.message_body}"
    try:
        sms = client.messages.create(
            body=message_body,
            from_=settings.TWILIO_NUMBER,
            to=msg_obj.receiver.phone  # assuming receiver has phone attribute
        )
        # Optionally update message status
        msg_obj.read_status = True
        msg_obj.save()
        logger.info(f"Sent message SMS: {sms.sid}")
        return sms.sid
    except Exception as e:
        logger.error(f"Error sending message {message_id}: {e}")
        return str(e)
