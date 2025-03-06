from django.db import models
from django.contrib.auth.models import (
	AbstractBaseUser, PermissionsMixin, BaseUserManager
)
from django.utils import timezone

# Custom User Manager
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('account_status', 'active')
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

# Custom User Model
class User(AbstractBaseUser, PermissionsMixin):
    class AccountStatus(models.TextChoices):
        ACTIVE = 'active', 'Active'
        SUSPENDED = 'suspended', 'Suspended'
        DEACTIVATED = 'deactivated', 'Deactivated'

    email = models.EmailField(unique=True, max_length=255, db_index=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    account_status = models.CharField(
        max_length=20,
        choices=AccountStatus.choices,
        default=AccountStatus.ACTIVE,
        db_index=True
    )
    password_last_changed = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email

    class Meta:
        indexes = [
            models.Index(fields=['last_login']),
        ]

# Role Model
class Role(models.Model):
    role_name = models.CharField(max_length=50, unique=True, db_index=True)
    description = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.role_name

# Junction Table: UserRoles
class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'role')
        indexes = [
            models.Index(fields=['assigned_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.role.role_name}"

User.add_to_class('roles', models.ManyToManyField(Role, through=UserRole, related_name='users'))

# Patient Profile
class PatientProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='patient_profile')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)
    address = models.CharField(max_length=255, blank=True)
    emergency_contact = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name}"

    class Meta:
        indexes = [
            models.Index(fields=['last_name', 'first_name']),
        ]

# Doctor Profile
class DoctorProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='doctor_profile')
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    specialization = models.CharField(max_length=150, blank=True, db_index=True)
    bio = models.TextField(blank=True)
    working_hours = models.JSONField(blank=True, null=True)

    def __str__(self):
        return f"Dr. {self.first_name} {self.last_name}"

    class Meta:
        indexes = [
            models.Index(fields=['specialization']),
        ]

# Appointment Model
class Appointment(models.Model):
    class AppointmentStatus(models.TextChoices):
        SCHEDULED = 'scheduled', 'Scheduled'
        CANCELLED = 'cancelled', 'Cancelled'
        COMPLETED = 'completed', 'Completed'
        RESCHEDULED = 'rescheduled', 'Rescheduled'

    appointment_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='appointments_as_patient')
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='appointments_as_doctor')
    scheduled_time = models.DateTimeField(db_index=True)
    duration_minutes = models.IntegerField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=AppointmentStatus.choices,
        default=AppointmentStatus.SCHEDULED,
        db_index=True
    )
    reason = models.TextField(blank=True)
    cancellation_reason = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Appointment {self.appointment_id} - {self.patient.email} with {self.doctor.email}"

    class Meta:
        indexes = [
            models.Index(fields=['scheduled_time', 'status']),
            models.Index(fields=['patient', 'doctor']),
        ]

# Message Model
class Message(models.Model):
    message_id = models.AutoField(primary_key=True)
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    message_body = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True, db_index=True)
    read_status = models.BooleanField(default=False, db_index=True)

    def __str__(self):
        return f"Message {self.message_id} from {self.sender.email} to {self.receiver.email}"

    class Meta:
        indexes = [
            models.Index(fields=['sent_at']),
        ]

# Payment Model
class Payment(models.Model):
    class PaymentStatus(models.TextChoices):
        PENDING = 'pending', 'Pending'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    payment_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    appointment = models.ForeignKey(Appointment, on_delete=models.SET_NULL, null=True, blank=True, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50, blank=True)
    status = models.CharField(
        max_length=20,
        choices=PaymentStatus.choices,
        default=PaymentStatus.PENDING,
        db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"Payment {self.payment_id} - {self.amount}"

# Prescription Model
class Prescription(models.Model):
    prescription_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='prescriptions')
    doctor = models.ForeignKey(User, on_delete=models.CASCADE, related_name='prescriptions_given')
    medication = models.CharField(max_length=150)
    dosage = models.CharField(max_length=50, blank=True)
    frequency = models.CharField(max_length=50, blank=True)
    instructions = models.TextField(blank=True)
    refill_requested = models.BooleanField(default=False, db_index=True)
    request_date = models.DateTimeField(auto_now_add=True, db_index=True)
    approved_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Prescription {self.prescription_id} for {self.patient.email}"

    class Meta:
        indexes = [
            models.Index(fields=['request_date']),
        ]

# Notification Model
class Notification(models.Model):
    class NotificationType(models.TextChoices):
        APPOINTMENT = 'appointment', 'Appointment'
        PAYMENT = 'payment', 'Payment'
        PRESCRIPTION = 'prescription', 'Prescription'
        GENERAL = 'general', 'General'

    class NotificationStatus(models.TextChoices):
        UNREAD = 'unread', 'Unread'
        READ = 'read', 'Read'

    notification_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=150)
    message = models.TextField()
    type = models.CharField(
        max_length=20,
        choices=NotificationType.choices,
        default=NotificationType.GENERAL,
        db_index=True
    )
    status = models.CharField(
        max_length=20,
        choices=NotificationStatus.choices,
        default=NotificationStatus.UNREAD,
        db_index=True
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"Notification {self.notification_id} for {self.user.email}"

# Lab Result Model
class LabResult(models.Model):
    lab_result_id = models.AutoField(primary_key=True)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='lab_results')
    test_type = models.CharField(max_length=100, db_index=True)
    result_value = models.CharField(max_length=100, blank=True)
    result_date = models.DateTimeField(db_index=True)
    physician = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='lab_results_reviewed')
    comments = models.TextField(blank=True)

    def __str__(self):
        return f"LabResult {self.lab_result_id} for {self.patient.email}"

    class Meta:
        indexes = [
            models.Index(fields=['result_date']),
        ]

# Integration Log Model
class IntegrationLog(models.Model):
    class SyncStatus(models.TextChoices):
        SUCCESS = 'success', 'Success'
        FAILURE = 'failure', 'Failure'

    log_id = models.AutoField(primary_key=True)
    system_name = models.CharField(max_length=100)
    data_type = models.CharField(max_length=100, blank=True)
    data_reference = models.CharField(max_length=100, blank=True)
    sync_status = models.CharField(
        max_length=20,
        choices=SyncStatus.choices,
        default=SyncStatus.SUCCESS,
        db_index=True
    )
    last_sync_date = models.DateTimeField(auto_now_add=True, db_index=True)

    def __str__(self):
        return f"IntegrationLog {self.log_id} - {self.system_name}"

# Audit Log Model
class AuditLog(models.Model):
    audit_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    action = models.CharField(max_length=100, db_index=True)  # e.g., 'login', 'view_lab_result'
    target_table = models.CharField(max_length=100, blank=True)
    target_id = models.IntegerField(null=True, blank=True)
    ip_address = models.CharField(max_length=45, blank=True)
    event_timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    details = models.TextField(blank=True)

    def __str__(self):
        return f"AuditLog {self.audit_id} - {self.action} by {self.user.email}"

    class Meta:
        indexes = [
            models.Index(fields=['event_timestamp']),
        ]

