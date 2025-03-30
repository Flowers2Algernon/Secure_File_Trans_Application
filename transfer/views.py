from django.shortcuts import render
from django.http import HttpResponse,JsonResponse
from .utils import generate_code,hash_access_code, get_code_expire_time
from .models import EncrptedFile
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status, views, parsers
from rest_framework.response import Response

@csrf_exempt # Disable CSRF protection for this view
def generate_code_api(request):
    if request.method == 'POST': # Only allow POST requests for code generation
        code = generate_code()
        # Don't save to database since we don't have a file yet
        return JsonResponse({'code': code}) # Return the code as a JSON response
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405) # Respond with 405 Method Not Allowed for GET or other methods

def index(request):
    return render(request,'index.html',{'index':index})
    

class FileUploadView(views.APIView):
    parser_classes = [parsers.MultiPartParser] # Enable multipart form data parsing for file uploads
    
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
            uploaded_file=uploaded_file,# store the unencrypted file for now TODO: after encrption implement, change this model.
            code_hash=hashed_code,
            code_expire=expiry_time

        )

        # prepare response
        response_data = {
            "file_id": str(encrypted_file_instance.file_id),
            "access_code": access_code,
        }

        return Response(response_data, status=status.HTTP_201_CREATED)

def upload_page(request):
    return render(request, "front_end/upload.html")