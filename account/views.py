from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, user_logged_in
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.dispatch import receiver
from django.shortcuts import render, redirect

from transfer.models import UserProfile
from transfer.views import query_approach_expired_files_count


# Create your views here.

def login_page(request):
    return render(request, 'login.html')
def sso_login(request):

    print('*****************************')
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            # redirect to after logined page
            # print("success")
            request.session['approach_expired_count'] = query_approach_expired_files_count()
            return redirect('transfer:after_user_login_page')
        else:
            # print("shibai")
            messages.error(request, 'Invalid credentials/username or password.')

    return render(request, "login.html")

# @receiver(user_logged_in)
# def after_user_login(request):
#     # query_approach_expired_files_count()


def sign_out(request):
    logout(request)
    return redirect('account:login')


@login_required
def dashboard_view(request):
    return render(request, 'transfer/account/dashboard.html', {'user': request.user})

def register_page(request):
    return render(request, 'register.html')

def register(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        password_hash = make_password(password)
        email = request.POST.get('email')

        save = UserProfile(username=username, password=password_hash, email=email).save()
        print(save)
    return render(request, "register.html")
