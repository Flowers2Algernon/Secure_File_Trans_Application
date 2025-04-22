import os
import base64
import json
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.core.files.base import ContentFile
from rest_framework import status, views, parsers
from rest_framework.response import Response

from .models import EncrptedFile, FileLog
from .utils import generate_code, hash_access_code, get_code_expire_time, verify_access_code
from .crypto_utils import (
    encrypt_file_with_aes, decrypt_file_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa,
    calculate_file_hash, verify_file_hash
)

@method_decorator(csrf_exempt, name='dispatch')
class FileUploadView(views.APIView):
    parser_classes = [parsers.MultiPartParser]
    
    def post(self, request):
        try:
            print("FileUploadView.post() called")
            print(f"Request FILES: {request.FILES}")
            print(f"Request POST: {request.POST}")
            
            # Get the uploaded file
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                print("No file uploaded")
                return Response({'error': 'No file uploaded'}, status=status.HTTP_400_BAD_REQUEST)
            
            print(f"Uploaded file: {uploaded_file.name}, size: {uploaded_file.size}")
            
            # Get the recipient's public key
            recipient_public_key = request.POST.get('recipient_public_key')
            encrypted_aes_key_b64 = request.POST.get('encrypted_aes_key')
            iv_b64 = request.POST.get('iv')
            file_hash = request.POST.get('file_hash')
            
            print(f"Recipient public key: {recipient_public_key is not None}")
            print(f"Encrypted AES key: {encrypted_aes_key_b64 is not None}")
            print(f"IV: {iv_b64 is not None}")
            print(f"File hash: {file_hash is not None}")
            
            # Generate an access code
            access_code = generate_code()
            hashed_code = hash_access_code(access_code)
            expiry_time = get_code_expire_time()
            
            # Create a new encrypted file object
            encrypted_file = EncrptedFile()
            encrypted_file.original_filename = uploaded_file.name
            encrypted_file.file_size = uploaded_file.size
            encrypted_file.code_hash = hashed_code
            encrypted_file.code_expire = expiry_time
            
            # If encryption metadata is provided, store it
            if recipient_public_key:
                encrypted_file.recipient_public_key = recipient_public_key
            
            if encrypted_aes_key_b64 and iv_b64:
                try:
                    # Convert base64 to binary
                    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                    iv = base64.b64decode(iv_b64)
                    
                    encrypted_file.encrypted_aes_key = encrypted_aes_key
                    encrypted_file.iv = iv
                    encrypted_file.encryption_algorithm = "AES-256-GCM"
                except Exception as e:
                    print(f"Error decoding base64: {str(e)}")
                    return Response({'error': f'Error decoding base64: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
            
            if file_hash:
                encrypted_file.file_hash = file_hash
            
            # Save the file
            print("Saving file...")
            encrypted_file.uploaded_file = uploaded_file
            encrypted_file.save()
            print(f"File saved with ID: {encrypted_file.file_id}")
            
            # Return the file ID and access code
            return Response({
                'file_id': str(encrypted_file.file_id),
                'access_code': access_code,
                'expires_at': expiry_time.isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            import traceback
            print(f"Error in FileUploadView.post(): {str(e)}")
            print(traceback.format_exc())
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@method_decorator(csrf_exempt, name='dispatch')
class GetEncryptedFileView(views.APIView):
    def post(self, request):
        try:
            # Get the access code and private key
            data = json.loads(request.body)
            access_code = data.get('access_code')
            private_key_pem = data.get('private_key')
            
            if not access_code or not private_key_pem:
                return Response({'error': 'Access code and private key are required'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Hash the access code
            hashed_code = hash_access_code(access_code)
            
            # Find the file by access code hash
            try:
                file_instance = None
                for enc_file in EncrptedFile.objects.all():
                    if verify_access_code(enc_file.code_hash, hashed_code):
                        file_instance = enc_file
                        break
                
                if file_instance is None:
                    return Response({'error': 'Invalid access code'}, status=status.HTTP_404_NOT_FOUND)
                
                # Check if the access code has expired
                if file_instance.code_expire < timezone.now():
                    return Response({'error': 'Access code expired'}, status=status.HTTP_410_GONE)
                
                # Read the encrypted file
                with file_instance.uploaded_file.open('rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the AES key with the private key
                try:
                    aes_key = decrypt_aes_key_with_rsa(file_instance.encrypted_aes_key, private_key_pem)
                except Exception as e:
                    return Response({'error': 'Invalid private key'}, status=status.HTTP_400_BAD_REQUEST)
                
                # Decrypt the file with the AES key
                decrypted_data = decrypt_file_with_aes(
                     encrypted_data,
                     aes_key,
                     file_instance.iv
                     )
                
                # Verify the file hash
                if not verify_file_hash(decrypted_data, file_instance.file_hash):
                    return Response({'error': 'File integrity check failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                # Log the download
                FileLog.objects.create(
                    encrypted_file=file_instance,
                    download_time=FileLog.objects.filter(encrypted_file=file_instance).count() + 1,
                    download_final_datetime=timezone.now(),
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
                
                # Return the decrypted file
                response = HttpResponse(decrypted_data, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{file_instance.original_filename}"'
                return response
                
            except Exception as e:
                return Response({'error': f'Error processing download request: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)