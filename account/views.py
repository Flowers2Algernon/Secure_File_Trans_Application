from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from django.db.utils import IntegrityError

from transfer.models import UserProfile
from transfer.views import query_approach_expired_files_count
from django.core.validators import validate_email
from django.core.exceptions import ValidationError


# ✔️ Login Page View
def login_page(request):
    return render(request, "login.html")


# ✔️ SSO Login Handler
def sso_login(request):
    print("*****************************")
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            request.session["approach_expired_count"] = (
                query_approach_expired_files_count()
            )
            return redirect("transfer:after_user_login_page")
        else:
            messages.error(
                request, "Invalid username or password."
            )  # ✔️ Clearer message ✔️

    return render(request, "login.html")


# ✔️ Logout Handler
def sign_out(request):
    logout(request)
    return redirect("account:login")


# ✔️ Dashboard View (Login Protected)
@login_required
def dashboard_view(request):
    return render(request, "transfer/account/dashboard.html", {"user": request.user})


# ✔️ Register Page Display
def register_page(request):
    return render(request, "register.html")


# ✔️ Register Form Submission Handler
def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        email = request.POST.get("email")

        # ✔️ Basic empty field check
        if not username or not password or not email:
            messages.error(request, "All fields are required.")
            return render(request, "register.html")

        # ✔️ Email format validation
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, "Enter a valid email address.")
            return render(request, "register.html")

        # ✔️ Check for duplicates
        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return render(request, "register.html")
        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return render(request, "register.html")

        try:
            password_hash = make_password(password)
            UserProfile.objects.create(
                username=username, password=password_hash, email=email
            )
            messages.success(
                request, "Registration successful. You can now log in."
            )  # ✔️
            return redirect("account:login")  # ✔️
        except IntegrityError:
            messages.error(request, "A database error occurred. Please try again.")

    return render(request, "register.html")
