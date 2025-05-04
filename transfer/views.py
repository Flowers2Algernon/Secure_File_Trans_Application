import os
import random
from datetime import datetime, timedelta

from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, views, parsers
from rest_framework.response import Response

from .models import EncrptedFile
from .utils import generate_code, hash_access_code, verify_access_code


@csrf_exempt  # Disable CSRF protection for this view
def generate_code_api(request):
    if request.method == 'POST':  # Only allow POST requests for code generation
        code = generate_code()
        # Don't save to database since we don't have a file yet
        return JsonResponse({'code': code})  # Return the code as a JSON response
    else:
        return JsonResponse({'error': 'Method not allowed'},
                            status=405)  # Respond with 405 Method Not Allowed for GET or other methods


def index(request):
    return render(request, 'front_end/index.html')


# In views.py or api_views.py
@method_decorator(csrf_exempt, name='dispatch')
class FileUploadView(views.APIView):
    parser_classes = [parsers.MultiPartParser]

    def post(self, request):
        try:
            print("==== DEBUG: FileUploadView.post() called ====")
            print(f"Request FILES: {request.FILES}")
            print(f"Request POST keys: {list(request.POST.keys())}")

            # Rest of your view code...

        except Exception as e:
            import traceback
            print("==== ERROR IN FILE UPLOAD ====")
            print(f"Error type: {type(e).__name__}")
            print(f"Error message: {str(e)}")
            print("Traceback:")
            print(traceback.format_exc())
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



def upload_page(request):
    return render(request, "front_end/send_file.html")



def delete_expired_file(request):
    """
    Delete expired file view function.删除过期文件的视图函数。
    """
    # get current date 获取当前时间
    now = datetime.now()

    try:
        # get all expired files获取所有过期的文件
        expired_files = EncrptedFile.objects.filter(code_expire__lte=now)

        if not expired_files.exists():
            return JsonResponse({'message': 'No expired files found.'}, status=404)

        # delete expired files 删除过期文件
        deleted_count = 0
        for expired_file in expired_files:
            try:
                # 删除文件
                if expired_file.file and os.path.isfile(expired_file.file.path):
                    os.remove(expired_file.file.path)  # delete file    删除文件
                    expired_file.delete()  # delete from database   删除数据库中的记录
                    deleted_count += 1
            except ObjectDoesNotExist:
                continue

        return JsonResponse({'message': f'{deleted_count} expired files deleted successfully.'}, status=200)

    except Exception as e:
        # error handle  错误处理
        return JsonResponse({'error': str(e)}, status=500)


def file_list(request):
    Files = EncrptedFile.objects.all()
    return render(request, "front_end/file_list.html", {'files': Files})


def ai_monitor_access_code_request(request_data):
    # This function is a placeholder for AI monitoring of access code requests.
    # for now, simulate a random response
    if random.random() < 0.05:  # 5% chance of suspicious activity
        return "suspicious", "AI detected suspicious activity in access code request."
    else:
        return "normal", "AI detected normal activity in access code request."


@method_decorator(csrf_exempt, name='dispatch')
class GetEncryptedFileView(views.APIView):
    def post(self, request, *args, **kwargs):
        access_code = request.data.get('access_code')

        if not access_code:
            return Response({'error': 'Access code is required'}, status=status.HTTP_400_BAD_REQUEST)
        # prepare data for AI
        request_data_for_ai = {
            "timestamp": datetime.now(),
            "ipaddress": request.META.get('REMOTE_ADDR'),
            "access_code": access_code,
            "user_agent": request.META.get('HTTP_USER_AGENT'),
        }

        ai_decision, ai_reason = ai_monitor_access_code_request(request_data_for_ai)

        if ai_decision == "suspicious":
            print(f"AI detected suspicious activity: {ai_reason}")
            return Response({'error': 'Suspicious activity detected. Access denied.'}, status=status.HTTP_403_FORBIDDEN)
        elif ai_decision == "normal":
            hashed_code = hash_access_code(access_code)  # hash the access code
            try:
                # search for the file using the hashed code in database
                file_instance = None
                for enc_file in EncrptedFile.objects.all():
                    if verify_access_code(enc_file.code_hash,
                                          hashed_code):  # compare the hashed code with the stored hash
                        file_instance = enc_file
                        break

                if file_instance is None:
                    return Response({'error': 'Invalid access code'}, status=status.HTTP_404_NOT_FOUND)
                if file_instance.code_expire < timezone.now():
                    return Response({'error': 'Access code expired'}, status=status.HTTP_410_GONE)

                # Access code is valid and not expired, serve the ENCRYPTED file
                try:
                    with file_instance.uploaded_file.open('rb') as f:
                        encrypted_file_content = f.read()

                    response = HttpResponse(encrypted_file_content, content_type='application/octet-stream')
                    response[
                        'Content-Disposition'] = f"attachment; filename=\"{file_instance.uploaded_file.name.split('/')[-1]}\""
                    return response
                except Exception as e:
                    return Response({'error': 'Error reading the file'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as e:
                print(f"Download error: {str(e)}")  # Log the actual error
                return Response({'error': f'Error processing download request: {str(e)}'},
                                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:  # unknown decision for ai
            return Response({'error': 'Error processing download request due to AI monitoring - unknown decision.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def download_page(request):
    return render(request, "front_end/download_file.html")


def request_send_page(request):
    return render(request, "front_end/requestSend.html")



def after_user_login_page(request):
    return render(request, "front_end/after_user_login_page.html")


def search_encrypted_files(request):
    query = request.GET.get("query", "").lower()
    date_filter = request.GET.get("date", "all")

    files = EncrptedFile.objects.all()

    if query:
        files = files.filter(original_filename__icontains=query)

    if date_filter == "today":
        files = files.filter(uploaded_date__date=now().date())
    elif date_filter == "week":
        week_ago = now() - timedelta(days=7)
        files = files.filter(uploaded_date__gte=week_ago)
    elif date_filter == "month":
        month_start = now().replace(day=1)
        files = files.filter(uploaded_date__gte=month_start)
    elif date_filter == "year":
        year_start = now().replace(month=1, day=1)
        files = files.filter(uploaded_date__gte=year_start)

    data = [
        {
            "file_id": str(f.file_id),
            "filename": f.original_filename,
            "size": f.file_size,
            "uploaded": f.uploaded_date.strftime("%Y-%m-%d %H:%M"),
            "url": f.uploaded_file.url,
            "status": "Available" if f.code_expire > now() else "Expired",
        }
        for f in files
    ]

    return JsonResponse({"files": data})
