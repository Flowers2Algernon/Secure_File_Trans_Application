from django.urls import path
from . import views

urlpatterns = [
    path('api/generate_code/',views.generate_code_api,name='generate_code_api'),
]