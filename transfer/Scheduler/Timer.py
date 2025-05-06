from apscheduler.schedulers.background import BackgroundScheduler
from django.apps import AppConfig
from django_apscheduler.jobstores import DjangoJobStore

from transfer.views import delete_expired_file


def timer():
    scheduler = BackgroundScheduler()
    scheduler.add_jobstore(DjangoJobStore(), "default")
    scheduler.add_job(delete_expired_file,  'cron', hour=0, minute=0, id='my_job')
    scheduler.start()


    def ready(self):
        timer()
