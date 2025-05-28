import os
import base64
import json
import tempfile
import uuid
import traceback
import hashlib
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from rest_framework import status, views, parsers
from rest_framework.response import Response
import mimetypes  # Make sure this is at the top of your file
from malware_scan.malware_detector import scan_file

from .models import EncrptedFile, FileLog, FileRequest  # Added FileRequest import
from .utils import (
    generate_code,
    hash_access_code,
    get_code_expire_time,
    # verify_access_code,  # noqa: F401
)
from .crypto_utils import (
    # encrypt_file_with_aes,  # noqa: F401
    decrypt_file_with_aes,
    # encrypt_aes_key_with_rsa,  # noqa: F401
    decrypt_aes_key_with_rsa,
    # calculate_file_hash,  # noqa: F401
    # verify_file_hash,  # noqa: F401
    generate_rsa_key_pair,
)


@method_decorator(csrf_exempt, name="dispatch")
class FileUploadView(views.APIView):
    parser_classes = [parsers.MultiPartParser]

    def post(self, request):
        saved_path = None
        try:
            print("FileUploadView.post() called")
            uploaded_file = request.FILES.get("file")
            if not uploaded_file:
                print("No file uploaded")
                return Response({"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST)

            print(f"Received file: {uploaded_file.name}, size: {uploaded_file.size}")

            # === 关键修复：在使用uploaded_file之前，先保存文件指针位置 ===
            original_position = uploaded_file.tell()
            print(f"Original file pointer position: {original_position}")

            # === Step 1: Create a secure temp file location and save for scanning ===
            temp_dir = os.path.join(tempfile.gettempdir(), "pdf_uploads")
            os.makedirs(temp_dir, exist_ok=True)
            unique_name = str(uuid.uuid4()) + "_" + os.path.basename(uploaded_file.name)
            saved_path = os.path.join(temp_dir, unique_name)

            print(f"Saving file temporarily to: {saved_path}")
            
            # 确保从文件开头读取
            uploaded_file.seek(0)
            with open(saved_path, "wb+") as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            print("Temporary save complete.")

            # === 重要：重置文件指针到原始位置 ===
            uploaded_file.seek(original_position)
            print(f"Reset file pointer to position: {uploaded_file.tell()}")

            # === Step 2: Scan the temporarily saved file ===
            print(f"Scanning file: {saved_path}")
            prediction, score = scan_file(saved_path)
            print(f"[DEBUG] Scan Result - Prediction: {prediction}, Score: {score}")

            # === Step 3: Clean up the temporary file AFTER scanning ===
            print(f"Removing temporary file: {saved_path}")
            if os.path.exists(saved_path):
                os.remove(saved_path)
            saved_path = None

            # === Step 4: Handle scan results ===
            if prediction == 1:
                file_ext = os.path.splitext(uploaded_file.name)[1].lower()
                print(f"Malicious file detected! Score: {score}")
                return Response({
                    "status": "blocked", 
                    "message": f"Malicious PDF file detected! This file appears to contain dangerous content.",
                    "malicious_score": round(score, 3),
                    "file_type": "PDF"
                }, status=status.HTTP_400_BAD_REQUEST)
            else:
                if score == 0.0:
                    print("Non-PDF file approved without scanning.")
                else:
                    print(f"PDF file approved. Safety score: {1-score:.3f}")

            # === Step 5: 在保存到数据库之前，验证文件数据完整性 ===
            print("File scan passed. Processing request...")

            # 验证uploaded_file当前状态
            uploaded_file.seek(0)
            current_file_data = uploaded_file.read()
            uploaded_file.seek(0)  # 重置供后续使用
            
            print(f"Current uploaded_file data length: {len(current_file_data)}")
            
            # 验证这个数据的哈希是否与前端发送的匹配
            current_hash = base64.b64encode(hashlib.sha256(current_file_data).digest()).decode()
            expected_hash = request.POST.get("file_hash")
            
            print(f"Current file data hash: {current_hash}")
            print(f"Expected hash from frontend: {expected_hash}")
            
            if current_hash != expected_hash:
                print("❌ ERROR: File data integrity check failed!")
                return Response({
                    "error": "File data corruption detected during processing."
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                print("✅ File data integrity verified")

            # 获取其他POST数据
            recipient_public_key = request.POST.get("recipient_public_key")
            encrypted_aes_key_b64 = request.POST.get("encrypted_aes_key")
            iv_b64 = request.POST.get("iv")
            file_hash = request.POST.get("file_hash")

            print(f"Recipient public key received: {recipient_public_key is not None}")
            print(f"Encrypted AES key received: {encrypted_aes_key_b64 is not None}")
            print(f"IV received: {iv_b64 is not None}")
            print(f"File hash received: {file_hash is not None}")

            if not all([recipient_public_key, encrypted_aes_key_b64, iv_b64, file_hash]):
                print("Missing required encryption metadata in POST request.")
                return Response({
                    "error": "Missing required encryption metadata after successful scan."
                }, status=status.HTTP_400_BAD_REQUEST)

            # 生成访问码
            access_code = generate_code()
            hashed_code = hash_access_code(access_code)
            expiry_time = get_code_expire_time()
            print("Generated access code and expiry.")

            # 创建加密文件对象
            encrypted_file = EncrptedFile()
            encrypted_file.original_filename = uploaded_file.name
            encrypted_file.file_size = uploaded_file.size
            encrypted_file.code_hash = hashed_code
            encrypted_file.code_expire = expiry_time
            encrypted_file.recipient_public_key = recipient_public_key
            encrypted_file.file_hash = file_hash
            encrypted_file.encryption_algorithm = "AES-256-GCM"

            print("Populated basic EncrptedFile fields.")

            # 解码二进制字段
            try:
                print("Attempting base64 decode...")
                encrypted_file.encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
                encrypted_file.iv = base64.b64decode(iv_b64)
                print("Base64 decode successful.")
            except Exception as e:
                print(f"Error decoding base64: {str(e)}")
                return Response({
                    "error": f"Invalid base64 encoding for keys/IV: {str(e)}"
                }, status=status.HTTP_400_BAD_REQUEST)

            # 确保文件指针在开头再保存
            uploaded_file.seek(0)
            print(f"File pointer before saving: {uploaded_file.tell()}")
            print("Assigning uploaded file to model field...")
            encrypted_file.uploaded_file = uploaded_file

            # 保存模型实例
            print("Attempting encrypted_file.save()...")
            encrypted_file.save()
            print(f"File and metadata saved with ID: {encrypted_file.file_id}")

            return Response({
                "file_id": str(encrypted_file.file_id),
                "access_code": access_code,
                "expires_at": expiry_time.isoformat(),
                "message": "File uploaded and encrypted successfully.",
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            print(f"Error in FileUploadView.post(): {str(e)}")
            print(traceback.format_exc())
            if saved_path and os.path.exists(saved_path):
                try:
                    print(f"Cleaning up temporary file due to error: {saved_path}")
                    os.remove(saved_path)
                except OSError as cleanup_error:
                    print(f"Error removing temporary file during cleanup: {cleanup_error}")

            return Response({
                "error": "An internal server error occurred."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name="dispatch")
class GetEncryptedFileView(views.APIView):
    def post(self, request):
        try:
            access_code = request.data.get("accessCode")
            private_key_pem = request.data.get("privateKey")

            if not access_code:
                return Response({"error": "Access code is required"}, status=status.HTTP_400_BAD_REQUEST)
            if not private_key_pem:
                return Response({"error": "Private key is required"}, status=status.HTTP_400_BAD_REQUEST)

            hashed_code = hash_access_code(access_code)
            file_instance = EncrptedFile.objects.filter(code_hash=hashed_code).first()

            if not file_instance:
                return Response({"error": "Invalid access code"}, status=status.HTTP_404_NOT_FOUND)
            if file_instance.code_expire and file_instance.code_expire < timezone.now():
                return Response({"error": "This file has expired"}, status=status.HTTP_410_GONE)

            # Logging the download
            FileLog.objects.create(
                encrptedFile=file_instance,
                download_time=1,
                download_final_datetime=timezone.now(),
                ip_address=self.get_client_ip(request),
            )

            try:
                print(f"🔍 [DEBUG] Starting decryption process...")
                print(f"🔍 [DEBUG] Original filename: '{file_instance.original_filename}'")
                print(f"🔍 [DEBUG] File size in DB: {file_instance.file_size}")
                print(f"🔍 [DEBUG] Stored file hash: {file_instance.file_hash}")
                
                encrypted_aes_key = file_instance.encrypted_aes_key
                iv = file_instance.iv
                
                print(f"🔍 [DEBUG] Encrypted AES key length: {len(encrypted_aes_key) if encrypted_aes_key else 'None'}")
                print(f"🔍 [DEBUG] IV length: {len(iv) if iv else 'None'}")

                # 解密AES密钥
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem)
                print(f"🔍 [DEBUG] Decrypted AES key length: {len(aes_key)}")

                # 读取存储的加密文件数据
                with file_instance.uploaded_file.open("rb") as f:
                    encrypted_file_data = f.read()
                
                print(f"🔍 [DEBUG] Read encrypted file data length: {len(encrypted_file_data)}")
                
                # 验证存储的加密数据哈希
                
                stored_encrypted_hash = base64.b64encode(hashlib.sha256(encrypted_file_data).digest()).decode()
                print(f"🔍 [DEBUG] Calculated hash of stored encrypted data: {stored_encrypted_hash}")
                print(f"🔍 [DEBUG] Expected hash from upload: {file_instance.file_hash}")
                
                if stored_encrypted_hash == file_instance.file_hash:
                    print("✅ [DEBUG] Stored encrypted data hash matches - storage integrity confirmed")
                else:
                    print("⚠️ [DEBUG] Hash mismatch - stored data may be corrupted")

                # 解密文件数据
                print(f"🔍 [DEBUG] Attempting AES decryption...")
                decrypted_file_data = decrypt_file_with_aes(encrypted_file_data, aes_key, iv)
                print(f"🔍 [DEBUG] Decrypted file data length: {len(decrypted_file_data)}")
                
                # 计算解密后数据的哈希用于调试
                decrypted_hash = hashlib.sha256(decrypted_file_data).hexdigest()
                print(f"🔍 [DEBUG] Decrypted file SHA256: {decrypted_hash}")

                # 确保文件名正确
                filename = file_instance.original_filename
                if not filename or filename.strip() == "":
                    filename = "decrypted_file"

                # 清理文件名
                import re
                from urllib.parse import quote

                # 移除非法字符但保留扩展名
                safe_filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
                safe_filename = safe_filename.strip()

                if not safe_filename:
                    safe_filename = "decrypted_file"

                print(f"🔍 [DEBUG] Original filename from DB: '{file_instance.original_filename}'")
                print(f"🔍 [DEBUG] Cleaned safe filename: '{safe_filename}'")

                # 确定内容类型
                content_type, _ = mimetypes.guess_type(safe_filename)
                content_type = content_type or "application/octet-stream"

                # 创建响应
                response = HttpResponse(decrypted_file_data, content_type=content_type)

                # 多种方式设置文件名，提高兼容性
                try:
                    # 方法1: ASCII文件名（用于兼容性）
                    ascii_filename = safe_filename.encode('ascii', 'ignore').decode('ascii')
                    if not ascii_filename:
                        ascii_filename = "decrypted_file"
                    
                    # 方法2: UTF-8编码文件名（用于国际化支持）
                    utf8_filename = quote(safe_filename.encode('utf-8'))
                    
                    # 设置多种Content-Disposition格式
                    disposition = f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{utf8_filename}'
                    response["Content-Disposition"] = disposition
                    
                    print(f"🔍 [DEBUG] ASCII filename: '{ascii_filename}'")
                    print(f"🔍 [DEBUG] UTF-8 filename: '{utf8_filename}'")
                    print(f"🔍 [DEBUG] Content-Disposition: {disposition}")
                    
                except Exception as e:
                    print(f"⚠️ Warning: Error setting advanced filename: {e}")
                    # 降级到简单文件名
                    response["Content-Disposition"] = f'attachment; filename="{safe_filename}"'

                # 设置额外的下载提示头
                response["Content-Transfer-Encoding"] = "binary"
                response["Content-Length"] = str(len(decrypted_file_data))

                # 强制下载相关的头
                response["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
                response["Pragma"] = "no-cache"
                response["Expires"] = "0"

                # 添加自定义头来帮助调试
                response["X-Original-Filename"] = safe_filename
                response["X-File-Size"] = str(len(decrypted_file_data))

                print(f"🔍 [DEBUG] All response headers:")
                for header, value in response.items():
                    print(f"🔍 [DEBUG] - {header}: {value}")

                return response

            except Exception as e:
                print(f"❌ [ERROR] Decryption failed: {str(e)}")
                import traceback
                print(f"❌ [ERROR] Full traceback:")
                print(traceback.format_exc())
                return Response(
                    {"error": f"Decryption failed: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except Exception as e:
            print(f"❌ [ERROR] Error in GetEncryptedFileView: {str(e)}")
            import traceback
            print(traceback.format_exc())
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return x_forwarded_for.split(",")[0] if x_forwarded_for else request.META.get("REMOTE_ADDR")


@method_decorator(csrf_exempt, name="dispatch")
class CreateFileRequestView(views.APIView):
    """API view to create a file request with key generation"""

    def post(self, request):
        try:
            # Parse request data
            data = json.loads(request.body)
            requester_email = data.get("senderEmail")
            message = data.get("message", "")
            # purpose = data.get("purpose", "")  # nopa: F841

            # Validate data
            if not requester_email:
                return Response(
                    {"error": "Requester email is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Generate an RSA key pair
            key_pair = generate_rsa_key_pair()
            # print(key_pair)

            # Create a FileRequest object with 7 days expiry
            expiry_date = timezone.now() + timezone.timedelta(days=7)
            file_request = FileRequest.objects.create(
                requester_email=requester_email,
                requester_name=requester_email.split("@")[0],  # Use email username as name
                request_message=message,
                public_key=key_pair["public_key"],
                expires_at=expiry_date,
            )

            # Generate a request URL
            request_url = f"{request.build_absolute_uri('/upload/')}?request={file_request.request_id}"

            # Return the key pair and request URL
            return Response(
                {
                    "success": True,
                    "publicKey": key_pair["public_key"],
                    "privateKey": key_pair["private_key"],
                    "requestUrl": request_url,
                    "expiresAt": expiry_date.isoformat(),
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            import traceback

            print(f"Error in CreateFileRequestView.post(): {str(e)}")
            print(traceback.format_exc())  # Add traceback for better debugging
            return Response(
                {"error": str(e), "success": False},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
