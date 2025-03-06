# myproject/celery.py
import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PatientPortalService.settings')

app = Celery('PatientPortalService')
# Use a string here so the worker doesn’t have to serialize the configuration object.
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
