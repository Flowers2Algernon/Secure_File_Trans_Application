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

from .models import EncrptedFile, FileLog, FileRequest  # Added FileRequest import
from .utils import generate_code, hash_access_code, get_code_expire_time, verify_access_code
from .crypto_utils import (
    encrypt_file_with_aes, decrypt_file_with_aes,
    encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa,
    calculate_file_hash, verify_file_hash, generate_rsa_key_pair
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
            access_code = request.data.get('accessCode')
            private_key_pem = request.data.get('privateKey')

            if not access_code:
                return Response({'error': 'Access code is required'}, status=status.HTTP_400_BAD_REQUEST)
            if not private_key_pem:
                return Response({'error': 'Private key is required'}, status=status.HTTP_400_BAD_REQUEST)

            hashed_code = hash_access_code(access_code)
            file_instance = EncrptedFile.objects.filter(code_hash=hashed_code).first()

            if not file_instance:
                return Response({'error': 'Invalid access code'}, status=status.HTTP_404_NOT_FOUND)
            if file_instance.code_expire and file_instance.code_expire < timezone.now():
                return Response({'error': 'This file has expired'}, status=status.HTTP_410_GONE)

            # Logging the download
            FileLog.objects.create(
                encrptedFile=file_instance,
                download_time=1,
                download_final_datetime=timezone.now(),
                ip_address=self.get_client_ip(request)
            )

            try:
                encrypted_aes_key = file_instance.encrypted_aes_key
                iv = file_instance.iv
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem)

                with file_instance.uploaded_file.open('rb') as f:
                    encrypted_file_data = f.read()
                decrypted_file_data = decrypt_file_with_aes(encrypted_file_data, aes_key, iv)

                # Save decrypted file to temp location
                temp_filename = f"decrypted_{file_instance.file_id}.bin"
                temp_file_path = os.path.join("media", "temp_downloads", temp_filename)
                os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)

                with open(temp_file_path, 'wb') as out_file:
                    out_file.write(decrypted_file_data)

                file_url = request.build_absolute_uri(f"/media/temp_downloads/{temp_filename}")

                return Response({
                    'fileUrl': file_url,
                    'fileName': file_instance.original_filename
                })

            except Exception as e:
                print(f"Decryption failed: {str(e)}")
                return Response({'error': f'Decryption failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            print(f"Error in GetEncryptedFileView: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        return x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

@method_decorator(csrf_exempt, name='dispatch')
class CreateFileRequestView(views.APIView):
    """API view to create a file request with key generation"""
    
    def post(self, request):
        try:
            # Parse request data
            data = json.loads(request.body)
            requester_email = data.get('senderEmail')
            message = data.get('message', '')
            purpose = data.get('purpose', '')
            
            # Validate data
            if not requester_email:
                return Response({'error': 'Requester email is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate an RSA key pair
            key_pair = generate_rsa_key_pair()
            #print(key_pair)
            
            # Create a FileRequest object with 7 days expiry
            expiry_date = timezone.now() + timezone.timedelta(days=7)
            file_request = FileRequest.objects.create(
                requester_email=requester_email,
                requester_name=requester_email.split('@')[0],  # Use email username as name
                request_message=message,
                public_key=key_pair['public_key'],
                expires_at=expiry_date
            )
            
            # Generate a request URL
            request_url = f"{request.build_absolute_uri('/upload/')}?request={file_request.request_id}"
            
            # Return the key pair and request URL
            return Response({
                'success': True,
                'publicKey': key_pair['public_key'],
                'privateKey': key_pair['private_key'],
                'requestUrl': request_url,
                'expiresAt': expiry_date.isoformat()
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            import traceback
            print(f"Error in CreateFileRequestView.post(): {str(e)}")
            print(traceback.format_exc())  # Add traceback for better debugging
            return Response({'error': str(e), 'success': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)