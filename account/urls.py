from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from account.views import sso_login, register, login_page, register_page, sign_out

app_name = 'account'
urlpatterns = [
    path('register/', register, name='register'),
    path('register_page/', register_page, name='register_page'),
    # google sso
    path('auth/', include('social_django.urls', namespace='social')),
    path('login_page/', login_page, name='login_page'),
    path('login/', sso_login, name='login'),
    path('sign_out/', sign_out, name='sign_out'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
