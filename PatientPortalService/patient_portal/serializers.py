from rest_framework import serializers
from django.utils import timezone
from django.contrib.auth.password_validation import validate_password
from .models import (
    User, Role, UserRole, PatientProfile, DoctorProfile,
    Appointment, Message, Payment, Prescription, Notification,
    LabResult, IntegrationLog, AuditLog
)

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        # Add extra user details to the token response
        data.update({
            'user': {
                'id': self.user.id,
                'email': self.user.email,
                'account_status': self.user.account_status,
            }
        })
        return data


# Custom User Serializer with password validation
class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    roles = serializers.SlugRelatedField(
        many=True, read_only=True, slug_field='role_name'
    )

    class Meta:
        model = User
        fields = (
            'id', 'email', 'phone', 'account_status', 'last_login',
            'password_last_changed', 'created_at', 'updated_at',
            'is_staff', 'password', 'roles'
        )
        read_only_fields = ('last_login', 'password_last_changed', 'created_at', 'updated_at', 'is_staff')

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user

# Role Serializer
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ('id', 'role_name', 'description')

# UserRole Serializer
class UserRoleSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())

    class Meta:
        model = UserRole
        fields = ('user', 'role', 'assigned_at')
        read_only_fields = ('assigned_at',)

# Patient Profile Serializer
class PatientProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = PatientProfile
        fields = ('user', 'first_name', 'last_name', 'date_of_birth', 'address', 'emergency_contact')
    
    def validate_first_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("First name cannot be empty.")
        return value

    def validate_last_name(self, value):
        if not value.strip():
            raise serializers.ValidationError("Last name cannot be empty.")
        return value

# Doctor Profile Serializer
class DoctorProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = DoctorProfile
        fields = ('user', 'first_name', 'last_name', 'specialization', 'bio', 'working_hours')
    
    def validate_specialization(self, value):
        if value and not value.strip():
            raise serializers.ValidationError("Specialization cannot be blank if provided.")
        return value

# Appointment Serializer with custom validations
class AppointmentSerializer(serializers.ModelSerializer):
    patient = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='patient'))
    doctor = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='doctor'))

    class Meta:
        model = Appointment
        fields = (
            'appointment_id', 'patient', 'doctor', 'scheduled_time',
            'duration_minutes', 'status', 'reason', 'cancellation_reason',
            'created_at', 'updated_at'
        )
        read_only_fields = ('appointment_id', 'created_at', 'updated_at')

    def validate_scheduled_time(self, value):
        if value < timezone.now():
            raise serializers.ValidationError("Scheduled time must be in the future.")
        return value

    def validate_duration_minutes(self, value):
        if value is not None and value <= 0:
            raise serializers.ValidationError("Duration must be a positive integer.")
        return value

# Message Serializer
class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    receiver = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Message
        fields = ('message_id', 'sender', 'receiver', 'message_body', 'sent_at', 'read_status')
        read_only_fields = ('message_id', 'sent_at')

    def validate_message_body(self, value):
        if not value.strip():
            raise serializers.ValidationError("Message body cannot be empty.")
        return value

# Payment Serializer with validations
class PaymentSerializer(serializers.ModelSerializer):
    patient = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='patient'))
    appointment = serializers.PrimaryKeyRelatedField(queryset=Appointment.objects.all(), allow_null=True, required=False)

    class Meta:
        model = Payment
        fields = ('payment_id', 'patient', 'appointment', 'amount', 'payment_method', 'status', 'created_at')
        read_only_fields = ('payment_id', 'created_at')

    def validate_amount(self, value):
        if value <= 0:
            raise serializers.ValidationError("Payment amount must be positive.")
        return value

# Prescription Serializer with validations
class PrescriptionSerializer(serializers.ModelSerializer):
    patient = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='patient'))
    doctor = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='doctor'))

    class Meta:
        model = Prescription
        fields = (
            'prescription_id', 'patient', 'doctor', 'medication', 'dosage',
            'frequency', 'instructions', 'refill_requested', 'request_date', 'approved_date'
        )
        read_only_fields = ('prescription_id', 'request_date')

    def validate_medication(self, value):
        if not value.strip():
            raise serializers.ValidationError("Medication name is required.")
        return value

# Notification Serializer
class NotificationSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Notification
        fields = ('notification_id', 'user', 'title', 'message', 'type', 'status', 'created_at')
        read_only_fields = ('notification_id', 'created_at')

    def validate_title(self, value):
        if not value.strip():
            raise serializers.ValidationError("Notification title cannot be empty.")
        return value

    def validate_message(self, value):
        if not value.strip():
            raise serializers.ValidationError("Notification message cannot be empty.")
        return value

# Lab Result Serializer with validation
class LabResultSerializer(serializers.ModelSerializer):
    patient = serializers.PrimaryKeyRelatedField(queryset=User.objects.filter(roles__role_name='patient'))
    physician = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.filter(roles__role_name='doctor'),
        allow_null=True, required=False
    )

    class Meta:
        model = LabResult
        fields = ('lab_result_id', 'patient', 'test_type', 'result_value', 'result_date', 'physician', 'comments')
        read_only_fields = ('lab_result_id',)

    def validate_result_date(self, value):
        if value > timezone.now():
            raise serializers.ValidationError("Result date cannot be in the future.")
        return value

# Integration Log Serializer
class IntegrationLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegrationLog
        fields = ('log_id', 'system_name', 'data_type', 'data_reference', 'sync_status', 'last_sync_date')
        read_only_fields = ('log_id', 'last_sync_date')

# Audit Log Serializer
class AuditLogSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = AuditLog
        fields = ('audit_id', 'user', 'action', 'target_table', 'target_id', 'ip_address', 'event_timestamp', 'details')
        read_only_fields = ('audit_id', 'event_timestamp')
