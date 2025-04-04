from django.urls import path
from . import views
from .views import FileUploadView,upload_page

urlpatterns = [
    # index page
    path('',views.index,name='index'),
    path('api/generate_code/',views.generate_code_api,name='generate_code_api'),
    path('upload_api/',FileUploadView.as_view(),name='upload'),
    path('upload/',upload_page,name='upload_page'),
    path('file_list/',views.file_list,name='file_list'),
]