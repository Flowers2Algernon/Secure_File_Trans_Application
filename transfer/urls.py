from django.urls import path
from .views import index, upload_page, download_page, file_list, delete_expired_file, request_send_page, sso_login, register
from django.conf import settings
from django.conf.urls.static import static
from .file_views import FileUploadView, GetEncryptedFileView, CreateFileRequestView

urlpatterns = [
    path('', index, name='index'),
    path('upload/', upload_page, name='upload'),
    path('download/', download_page, name='download'),
    path('request_send/', request_send_page, name='request_send'),
    path('file_list/', file_list, name='file_list'),
    path('delete_expired_file/', delete_expired_file, name='delete_expired_file'),
    path('login/', sso_login, name='login'),
    path('register/', register, name='register'),
    # API endpoints
    path('upload_api/', FileUploadView.as_view(), name='file_upload_api'),
    path('api/files/get_encrypted_file_api/', GetEncryptedFileView.as_view(), name='get_encrypted_file_api'),
    path('api/file-requests/', CreateFileRequestView.as_view(), name='create_file_request'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)