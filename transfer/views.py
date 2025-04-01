import os
from datetime import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from .utils import generate_code, hash_access_code, get_code_expire_time
from .models import EncrptedFile
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, views, parsers
from rest_framework.response import Response
from celery import shared_task


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
    return render(request, 'index.html', {'index': index})


class FileUploadView(views.APIView):
    parser_classes = [parsers.MultiPartParser]  # Enable multipart form data parsing for file uploads

    def post(self, request):
        uploaded_file = request.FILES.get('file')

        if not uploaded_file:
            return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a 6-digit code
        access_code = generate_code()
        hashed_code = hash_access_code(access_code)
        expiry_time = get_code_expire_time()

        # store unencrypted file and access code hash and matedata
        encrypted_file_instance = EncrptedFile.objects.create(
            # attention: alrough here is named as encrypted file, but we don't implement encryption yet TODO: implement encryption
            uploaded_file=uploaded_file,
            original_filename=uploaded_file.name,  # Add the filename
            file_size=uploaded_file.size,  # Add the file size
            code_hash=hashed_code,
            code_expire=expiry_time,
        )

        # prepare response
        response_data = {
            "file_id": str(encrypted_file_instance.file_id),
            "access_code": access_code,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)


def upload_page(request):
    return render(request, "front_end/upload.html")


# @shared_task #定时任务 Scheduled task
def delete_expired_file(request):
    """
    Delete expired file view function.删除过期文件的视图函数。
    """
    # 获取当前时间
    now = datetime.now()

    try:
        # get all expired files获取所有过期的文件
        expired_files = EncrptedFile.objects.filter(code_expire__lte=now)

        if not expired_files.exists():
            return JsonResponse({'message': 'No expired files found.'}, status=404)

        # 删除过期文件
        deleted_count = 0
        for expired_file in expired_files:
            try:
                # 删除文件
                if expired_file.file and os.path.isfile(expired_file.file.path):
                    os.remove(expired_file.file.path)  # 删除文件
                    expired_file.delete()  # 删除数据库中的记录
                    deleted_count += 1
            except ObjectDoesNotExist:
                continue

        return JsonResponse({'message': f'{deleted_count} expired files deleted successfully.'}, status=200)

    except Exception as e:
        # 错误处理
        return JsonResponse({'error': str(e)}, status=500)

def file_list(request):
    Files = EncrptedFile.objects.all()
    return render(request, "front_end/file_list.html", {'files': Files})
