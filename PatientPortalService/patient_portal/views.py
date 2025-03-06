from rest_framework import generics
from rest_framework import generics, permissions
from .models import (Appointment, Payment, Notification, Message, 
                     User, Role, UserRole, PatientProfile, DoctorProfile,
	            Prescription, LabResult, IntegrationLog, AuditLog)
from .serializers import (
	AppointmentSerializer, PaymentSerializer,
	NotificationSerializer, MessageSerializer,
    UserSerializer, RoleSerializer, UserRoleSerializer,
	PatientProfileSerializer, DoctorProfileSerializer,
	PrescriptionSerializer, LabResultSerializer,
	IntegrationLogSerializer, AuditLogSerializer
)
from .tasks import *



import logging
from django.utils import timezone
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics, views, status, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.password_validation import validate_password
from .models import User
from .serializers import (
    UserSerializer,
    CustomTokenObtainPairSerializer,  # Custom serializer that adds extra user info
)
from .tasks import send_reset_email

logger = logging.getLogger(__name__)

# User Registration Endpoint
class UserRegistrationView(generics.CreateAPIView):
    """
    Endpoint for user registration.
    Validates user data using UserSerializer and creates a new user.
    """
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        logger.info(f"New user registered: {response.data.get('email')}")
        return response

# User List & Registration Endpoint (if you want listing capability)
class UserListCreateAPIView(generics.ListCreateAPIView):
    """
    This endpoint allows both listing users (GET) and user registration (POST).
    For production, you might restrict the listing functionality.
    """
    queryset = User.objects.all().order_by('-created_at')
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]
    

class UserRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = User.objects.all()
	serializer_class = UserSerializer
	permission_classes = [permissions.IsAuthenticated]

# User Login Endpoint using Simple JWT
class UserLoginView(TokenObtainPairView):
    """
    Endpoint to obtain JWT access and refresh tokens.
    Uses a custom serializer to include extra user details.
    """
    serializer_class = CustomTokenObtainPairSerializer

# User Logout Endpoint (Token Blacklisting)
class UserLogoutView(views.APIView):
    """
    Endpoint to logout a user by blacklisting the provided refresh token.
    Requires Simple JWT's blacklisting app.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            logger.warning("Logout attempted without refresh token.")
            return Response({"error": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User {request.user.email} logged out successfully.")
            return Response({"detail": "Logout successful."}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# Forgot Password Endpoint
class ForgotPasswordView(views.APIView):
    """
    Accepts an email and, if a user exists, generates a password reset token.
    Offloads email sending to a Celery task.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not email:
            logger.warning("Forgot password request without email.")
            return Response({"error": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning(f"Password reset requested for non-existent email: {email}")
            # Always return a success message to avoid disclosing user existence.
            return Response({"message": "If the email exists, a reset link will be sent."}, status=status.HTTP_200_OK)

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Offload email sending asynchronously
        send_reset_email.delay(user.id, uid, token)
        logger.info(f"Password reset initiated for user: {user.email}")
        return Response({"message": "If the email exists, a reset link will be sent."}, status=status.HTTP_200_OK)

# Reset Password Endpoint
class ResetPasswordView(views.APIView):
    """
    Accepts uid (base64-encoded user ID), token, and new password.
    Validates and resets the user's password.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        new_password = request.data.get("new_password")

        if not uidb64 or not token or not new_password:
            logger.warning("Reset password request missing fields.")
            return Response({"error": "uid, token, and new_password are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception as e:
            logger.error(f"Error decoding uid: {str(e)}")
            return Response({"error": "Invalid uid."}, status=status.HTTP_400_BAD_REQUEST)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            logger.warning(f"Invalid token for user: {user.email}")
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_password(new_password, user=user)
        except Exception as e:
            logger.warning(f"Password validation error: {e.messages}")
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.password_last_changed = timezone.now()
        user.save()
        logger.info(f"Password reset successfully for user: {user.email}")
        return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
  # Adjust if needed


# --- Role Views ---
class RoleListCreateAPIView(generics.ListCreateAPIView):
	queryset = Role.objects.all()
	serializer_class = RoleSerializer
	permission_classes = [permissions.IsAuthenticated]

class RoleRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = Role.objects.all()
	serializer_class = RoleSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- UserRole Views ---
class UserRoleListCreateAPIView(generics.ListCreateAPIView):
	queryset = UserRole.objects.all()
	serializer_class = UserRoleSerializer
	permission_classes = [permissions.IsAuthenticated]

class UserRoleRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = UserRole.objects.all()
	serializer_class = UserRoleSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Patient Profile Views ---
class PatientProfileListCreateAPIView(generics.ListCreateAPIView):
	queryset = PatientProfile.objects.all()
	serializer_class = PatientProfileSerializer
	permission_classes = [permissions.IsAuthenticated]

class PatientProfileRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = PatientProfile.objects.all()
	serializer_class = PatientProfileSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Doctor Profile Views ---
class DoctorProfileListCreateAPIView(generics.ListCreateAPIView):
	queryset = DoctorProfile.objects.all()
	serializer_class = DoctorProfileSerializer
	permission_classes = [permissions.IsAuthenticated]

class DoctorProfileRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = DoctorProfile.objects.all()
	serializer_class = DoctorProfileSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Appointment Views ---
class AppointmentListCreateAPIView(generics.ListCreateAPIView):
    queryset = Appointment.objects.all().order_by('-created_at')
    serializer_class = AppointmentSerializer

    def perform_create(self, serializer):
        appointment = serializer.save()
        # Enqueue an appointment reminder task
        send_appointment_reminder_task.delay(appointment.appointment_id)

class AppointmentRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Appointment.objects.all()
    serializer_class = AppointmentSerializer

    def perform_update(self, serializer):
        appointment = serializer.save()
        send_appointment_reminder_task.delay(appointment.appointment_id)

# --- Payment Views (Mpesa) ---
class PaymentListCreateAPIView(generics.ListCreateAPIView):
    queryset = Payment.objects.all().order_by('-created_at')
    serializer_class = PaymentSerializer

    def perform_create(self, serializer):
        payment = serializer.save()
        process_mpesa_payment_task.delay(payment.payment_id)

class PaymentRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Payment.objects.all()
    serializer_class = PaymentSerializer

    def perform_update(self, serializer):
        payment = serializer.save()
        process_mpesa_payment_task.delay(payment.payment_id)

# --- Notification Views (Twilio) ---
class NotificationListCreateAPIView(generics.ListCreateAPIView):
    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer

    def perform_create(self, serializer):
        notification = serializer.save()
        send_twilio_notification_task.delay(notification.notification_id)

class NotificationRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer

    def perform_update(self, serializer):
        notification = serializer.save()
        send_twilio_notification_task.delay(notification.notification_id)

# --- Message Views (Twilio) ---
class MessageListCreateAPIView(generics.ListCreateAPIView):
    queryset = Message.objects.all().order_by('-sent_at')
    serializer_class = MessageSerializer

    def perform_create(self, serializer):
        message_obj = serializer.save()
        send_twilio_message_task.delay(message_obj.message_id)

class MessageRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Message.objects.all()
    serializer_class = MessageSerializer

    def perform_update(self, serializer):
        message_obj = serializer.save()
        send_twilio_message_task.delay(message_obj.message_id)


# --- Prescription Views ---
class PrescriptionListCreateAPIView(generics.ListCreateAPIView):
	queryset = Prescription.objects.all().order_by('-request_date')
	serializer_class = PrescriptionSerializer
	permission_classes = [permissions.IsAuthenticated]

class PrescriptionRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = Prescription.objects.all()
	serializer_class = PrescriptionSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Lab Result Views ---
class LabResultListCreateAPIView(generics.ListCreateAPIView):
	queryset = LabResult.objects.all().order_by('-result_date')
	serializer_class = LabResultSerializer
	permission_classes = [permissions.IsAuthenticated]

class LabResultRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = LabResult.objects.all()
	serializer_class = LabResultSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Integration Log Views ---
class IntegrationLogListCreateAPIView(generics.ListCreateAPIView):
	queryset = IntegrationLog.objects.all().order_by('-last_sync_date')
	serializer_class = IntegrationLogSerializer
	permission_classes = [permissions.IsAuthenticated]

class IntegrationLogRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = IntegrationLog.objects.all()
	serializer_class = IntegrationLogSerializer
	permission_classes = [permissions.IsAuthenticated]

# --- Audit Log Views ---
class AuditLogListCreateAPIView(generics.ListCreateAPIView):
	queryset = AuditLog.objects.all().order_by('-event_timestamp')
	serializer_class = AuditLogSerializer
	permission_classes = [permissions.IsAuthenticated]

class AuditLogRetrieveUpdateDestroyAPIView(generics.RetrieveUpdateDestroyAPIView):
	queryset = AuditLog.objects.all()
	serializer_class = AuditLogSerializer
	permission_classes = [permissions.IsAuthenticated]
