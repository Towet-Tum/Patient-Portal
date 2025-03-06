from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import (
    
    UserRegistrationView,
    UserListCreateAPIView,  # Optional endpoint if you want to list users
    UserLoginView,
    UserLogoutView,
    ForgotPasswordView,
    ResetPasswordView,
    
    
	AppointmentListCreateAPIView,
	AppointmentRetrieveUpdateDestroyAPIView,
	PaymentListCreateAPIView,
	PaymentRetrieveUpdateDestroyAPIView,
	NotificationListCreateAPIView,
	NotificationRetrieveUpdateDestroyAPIView,
	MessageListCreateAPIView,
	MessageRetrieveUpdateDestroyAPIView,
    UserListCreateAPIView, UserRetrieveUpdateDestroyAPIView,
	RoleListCreateAPIView, RoleRetrieveUpdateDestroyAPIView,
	UserRoleListCreateAPIView, UserRoleRetrieveUpdateDestroyAPIView,
	PatientProfileListCreateAPIView, PatientProfileRetrieveUpdateDestroyAPIView,
	DoctorProfileListCreateAPIView, DoctorProfileRetrieveUpdateDestroyAPIView,
	PrescriptionListCreateAPIView, PrescriptionRetrieveUpdateDestroyAPIView,
	LabResultListCreateAPIView, LabResultRetrieveUpdateDestroyAPIView,
	IntegrationLogListCreateAPIView, IntegrationLogRetrieveUpdateDestroyAPIView,
	AuditLogListCreateAPIView, AuditLogRetrieveUpdateDestroyAPIView,
)

urlpatterns = [
    
    #jwt authentications
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
     path('register/', UserRegistrationView.as_view(), name='user-register'),
   

    # JWT authentication endpoints provided by Simple JWT
    path('login/', UserLoginView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Custom endpoints for logout and password reset functionality
    path('logout/', UserLogoutView.as_view(), name='user-logout'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
	# Users
	path('users/', UserListCreateAPIView.as_view(), name='user-list-create'),
	path('users/<int:pk>/', UserRetrieveUpdateDestroyAPIView.as_view(), name='user-detail'),

	# Roles
	path('roles/', RoleListCreateAPIView.as_view(), name='role-list-create'),
	path('roles/<int:pk>/', RoleRetrieveUpdateDestroyAPIView.as_view(), name='role-detail'),

	# UserRoles
	path('userroles/', UserRoleListCreateAPIView.as_view(), name='userrole-list-create'),
	path('userroles/<int:pk>/', UserRoleRetrieveUpdateDestroyAPIView.as_view(), name='userrole-detail'),

	# Patient Profiles
	path('patients/', PatientProfileListCreateAPIView.as_view(), name='patientprofile-list-create'),
	path('patients/<int:pk>/', PatientProfileRetrieveUpdateDestroyAPIView.as_view(), name='patientprofile-detail'),

	# Doctor Profiles
	path('doctors/', DoctorProfileListCreateAPIView.as_view(), name='doctorprofile-list-create'),
	path('doctors/<int:pk>/', DoctorProfileRetrieveUpdateDestroyAPIView.as_view(), name='doctorprofile-detail'),

	# Appointments
	path('appointments/', AppointmentListCreateAPIView.as_view(), name='appointment-list-create'),
	path('appointments/<int:pk>/', AppointmentRetrieveUpdateDestroyAPIView.as_view(), name='appointment-detail'),

	# Payments
	path('payments/', PaymentListCreateAPIView.as_view(), name='payment-list-create'),
	path('payments/<int:pk>/', PaymentRetrieveUpdateDestroyAPIView.as_view(), name='payment-detail'),

	# Notifications
	path('notifications/', NotificationListCreateAPIView.as_view(), name='notification-list-create'),
	path('notifications/<int:pk>/', NotificationRetrieveUpdateDestroyAPIView.as_view(), name='notification-detail'),

	# Messages
	path('messages/', MessageListCreateAPIView.as_view(), name='message-list-create'),
	path('messages/<int:pk>/', MessageRetrieveUpdateDestroyAPIView.as_view(), name='message-detail'),

	# Prescriptions
	path('prescriptions/', PrescriptionListCreateAPIView.as_view(), name='prescription-list-create'),
	path('prescriptions/<int:pk>/', PrescriptionRetrieveUpdateDestroyAPIView.as_view(), name='prescription-detail'),

	# Lab Results
	path('labresults/', LabResultListCreateAPIView.as_view(), name='labresult-list-create'),
	path('labresults/<int:pk>/', LabResultRetrieveUpdateDestroyAPIView.as_view(), name='labresult-detail'),

	# Integration Logs
	path('integrationlogs/', IntegrationLogListCreateAPIView.as_view(), name='integrationlog-list-create'),
	path('integrationlogs/<int:pk>/', IntegrationLogRetrieveUpdateDestroyAPIView.as_view(), name='integrationlog-detail'),

	# Audit Logs
	path('auditlogs/', AuditLogListCreateAPIView.as_view(), name='auditlog-list-create'),
	path('auditlogs/<int:pk>/', AuditLogRetrieveUpdateDestroyAPIView.as_view(), name='auditlog-detail'),
]

