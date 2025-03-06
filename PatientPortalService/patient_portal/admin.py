from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
	User, Role, UserRole, PatientProfile, DoctorProfile,
	Appointment, Message, Payment, Prescription, Notification,
	LabResult, IntegrationLog, AuditLog
)

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    exclude = ('created_at',)
    list_display = ('email', 'phone', 'account_status', 'is_staff', 'created_at')
    list_filter = ('account_status', 'is_staff')
    ordering = ('email',)
    search_fields = ('email', 'phone')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('phone',)}),
        ('Permissions', {'fields': ('account_status', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'password_last_changed', 'created_at', 'updated_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
	list_display = ('role_name', 'description')
	search_fields = ('role_name',)

@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
	list_display = ('user', 'role', 'assigned_at')
	list_filter = ('role__role_name',)
	search_fields = ('user__email',)

@admin.register(PatientProfile)
class PatientProfileAdmin(admin.ModelAdmin):
	list_display = ('user', 'first_name', 'last_name', 'date_of_birth')
	search_fields = ('first_name', 'last_name', 'user__email')

@admin.register(DoctorProfile)
class DoctorProfileAdmin(admin.ModelAdmin):
	list_display = ('user', 'first_name', 'last_name', 'specialization')
	search_fields = ('first_name', 'last_name', 'specialization', 'user__email')

@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
	list_display = ('appointment_id', 'patient', 'doctor', 'scheduled_time', 'status')
	list_filter = ('status', 'scheduled_time')
	search_fields = ('patient__email', 'doctor__email')
	ordering = ('-scheduled_time',)

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
	list_display = ('message_id', 'sender', 'receiver', 'sent_at', 'read_status')
	list_filter = ('sent_at', 'read_status')
	search_fields = ('sender__email', 'receiver__email')

@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
	list_display = ('payment_id', 'patient', 'appointment', 'amount', 'status', 'created_at')
	list_filter = ('status', 'created_at')
	search_fields = ('patient__email',)

@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
	list_display = ('prescription_id', 'patient', 'doctor', 'medication', 'request_date', 'refill_requested')
	list_filter = ('request_date', 'refill_requested')
	search_fields = ('patient__email', 'doctor__email', 'medication')

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
	list_display = ('notification_id', 'user', 'title', 'type', 'status', 'created_at')
	list_filter = ('type', 'status', 'created_at')
	search_fields = ('user__email', 'title')

@admin.register(LabResult)
class LabResultAdmin(admin.ModelAdmin):
	list_display = ('lab_result_id', 'patient', 'test_type', 'result_date')
	list_filter = ('result_date', 'test_type')
	search_fields = ('patient__email', 'test_type')

@admin.register(IntegrationLog)
class IntegrationLogAdmin(admin.ModelAdmin):
	list_display = ('log_id', 'system_name', 'sync_status', 'last_sync_date')
	list_filter = ('sync_status', 'last_sync_date')
	search_fields = ('system_name',)

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
	list_display = ('audit_id', 'user', 'action', 'event_timestamp')
	list_filter = ('action', 'event_timestamp')
	search_fields = ('user__email', 'action', 'target_table')

