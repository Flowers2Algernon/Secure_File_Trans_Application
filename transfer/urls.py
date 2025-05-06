from django.conf import settings
from django.conf.urls.static import static
from django.urls import path

from .file_views import FileUploadView, GetEncryptedFileView, CreateFileRequestView
from .views import index, upload_page, download_page, file_list, request_send_page, \
    after_user_login_page, search_encrypted_files, delete_file

app_name = 'transfer'
urlpatterns = [
    path('', index, name='index'),
    path('upload/', upload_page, name='upload'),
    path('download/', download_page, name='download'),
    path('request_send/', request_send_page, name='request_send'),
    path('file_list/', file_list, name='file_list'),
    # path('delete_expired_file/', delete_expired_file, name='delete_expired_file'),

    # API endpoints
    path('upload_api/', FileUploadView.as_view(), name='file_upload_api'),
    path('api/files/get_encrypted_file_api/', GetEncryptedFileView.as_view(), name='get_encrypted_file_api'),
    path('api/file-requests/', CreateFileRequestView.as_view(), name='create_file_request'),

    path('after_user_login_page/', after_user_login_page, name='after_user_login_page'),
    # # google sso
    # path('auth/', include('social_django.urls', namespace='social')),
    # path('', include('account.urls')),  # 引入登录功能
    path("api/search_files/", search_encrypted_files, name="search_encrypted_files"),
    path("delete_file/<str:file_id>/", delete_file, name="delete_file"),

    # path("api/query_approach_expired_files_count/",query_approach_expired_files_count,name="query_approach_expired_files_count"),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
