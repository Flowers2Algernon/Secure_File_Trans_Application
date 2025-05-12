import os
import base64
import json
import tempfile
import uuid
import traceback
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from rest_framework import status, views, parsers
from rest_framework.response import Response
import mimetypes  # Make sure this is at the top of your file
from malware_scan.malware_detector import scan_pdf

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
        saved_path = None  # Initialize path for cleanup in case of errors
        try:
            print("FileUploadView.post() called")
            uploaded_file = request.FILES.get("file")
            if not uploaded_file:
                print("No file uploaded")
                return Response(
                    {"error": "No file uploaded"}, status=status.HTTP_400_BAD_REQUEST
                )

            print(f"Received file: {uploaded_file.name}, size: {uploaded_file.size}")

            # === Step 1: Create a secure temp file location and save for scanning ===
            temp_dir = os.path.join(tempfile.gettempdir(), "pdf_uploads")
            os.makedirs(temp_dir, exist_ok=True)
            # Use a unique name for the temp file, sanitize original name
            unique_name = str(uuid.uuid4()) + "_" + os.path.basename(uploaded_file.name)
            saved_path = os.path.join(temp_dir, unique_name)

            print(f"Saving file temporarily to: {saved_path}")
            with open(saved_path, "wb+") as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            print("Temporary save complete.")

            # === Step 2: Scan the temporarily saved file ===
            print(f"Scanning file: {saved_path}")
            prediction, score = scan_pdf(saved_path)  # Call the scan function
            print(f"[DEBUG] Scan Result - Prediction: {prediction}, Score: {score}")

            # === Step 3: Clean up the temporary file AFTER scanning ===
            print(f"Removing temporary file: {saved_path}")
            if os.path.exists(saved_path):
                os.remove(saved_path)
            saved_path = None  # Reset path after deletion

            # === Step 4: Handle MALICIOUS file ===
            if prediction == 1:
                print("Malicious file detected! Rejecting upload.")
                return Response(
                    {
                        "status": "blocked",
                        "message": "Malicious file detected!",
                        "malicious_score": round(score, 3),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # === Step 5: If file is CLEAN, proceed with saving metadata and file ===
            print("File scan passed. Processing request...")

            # Get the rest of the POST data needed for saving
            recipient_public_key = request.POST.get("recipient_public_key")
            encrypted_aes_key_b64 = request.POST.get("encrypted_aes_key")
            iv_b64 = request.POST.get("iv")
            file_hash = request.POST.get("file_hash")

            print(f"Recipient public key received: {recipient_public_key is not None}")
            print(f"Encrypted AES key received: {encrypted_aes_key_b64 is not None}")
            print(f"IV received: {iv_b64 is not None}")
            print(f"File hash received: {file_hash is not None}")

            # --- Optional: Validate that required metadata was received ---
            if not all(
                [recipient_public_key, encrypted_aes_key_b64, iv_b64, file_hash]
            ):
                print("Missing required encryption metadata in POST request.")
                # Consider if this case should be 400 or 500
                return Response(
                    {
                        "error": "Missing required encryption metadata after successful scan."
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Generate an access code
            # Replace with your actual implementation:
            access_code = generate_code()
            hashed_code = hash_access_code(access_code)
            expiry_time = get_code_expire_time()
            print("Generated access code and expiry.")

            # Create a new encrypted file object
            encrypted_file = EncrptedFile()
            encrypted_file.original_filename = uploaded_file.name
            encrypted_file.file_size = uploaded_file.size
            encrypted_file.code_hash = hashed_code
            encrypted_file.code_expire = expiry_time
            encrypted_file.recipient_public_key = recipient_public_key
            encrypted_file.file_hash = file_hash
            encrypted_file.encryption_algorithm = "AES-256-GCM"  # Set algorithm

            print("Populated basic EncrptedFile fields.")

            # Decode and store binary fields
            try:
                print("Attempting base64 decode...")
                encrypted_file.encrypted_aes_key = base64.b64decode(
                    encrypted_aes_key_b64
                )
                encrypted_file.iv = base64.b64decode(iv_b64)
                print("Base64 decode successful.")
            except Exception as e:
                print(f"Error decoding base64: {str(e)}")
                # This indicates a client-side data format error
                return Response(
                    {"error": f"Invalid base64 encoding for keys/IV: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Assign the *original* uploaded file (in memory or temp) to the FileField.
            # Django's FileField handling will save it to the correct 'uploaded_files/' location.
            print("Assigning uploaded file to model field...")
            encrypted_file.uploaded_file = uploaded_file

            # Save the model instance (which also saves the file to storage)
            print("Attempting encrypted_file.save()...")
            encrypted_file.save()
            print(f"File and metadata saved with ID: {encrypted_file.file_id}")

            # Return the success response with details needed by the client
            return Response(
                {
                    "file_id": str(encrypted_file.file_id),
                    "access_code": access_code,
                    "expires_at": expiry_time.isoformat(),
                    "message": "File uploaded and encrypted successfully.",  # Add success message
                },
                status=status.HTTP_201_CREATED,
            )  # Use 201 Created status

        except Exception as e:
            # Catch-all for unexpected errors
            print(f"Error in FileUploadView.post(): {str(e)}")
            print(traceback.format_exc())
            # Ensure temp file is cleaned up if error occurs after it was created
            if saved_path and os.path.exists(saved_path):
                try:
                    print(f"Cleaning up temporary file due to error: {saved_path}")
                    os.remove(saved_path)
                except OSError as cleanup_error:
                    print(
                        f"Error removing temporary file during cleanup: {cleanup_error}"
                    )

            # Return a generic 500 error
            return Response(
                {"error": "An internal server error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


@method_decorator(csrf_exempt, name="dispatch")
class GetEncryptedFileView(views.APIView):
    def post(self, request):
        try:
            access_code = request.data.get("accessCode")
            private_key_pem = request.data.get("privateKey")

            if not access_code:
                return Response(
                    {"error": "Access code is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not private_key_pem:
                return Response(
                    {"error": "Private key is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            hashed_code = hash_access_code(access_code)
            file_instance = EncrptedFile.objects.filter(code_hash=hashed_code).first()

            if not file_instance:
                return Response(
                    {"error": "Invalid access code"}, status=status.HTTP_404_NOT_FOUND
                )
            if file_instance.code_expire and file_instance.code_expire < timezone.now():
                return Response(
                    {"error": "This file has expired"}, status=status.HTTP_410_GONE
                )

            # Logging the download
            FileLog.objects.create(
                encrptedFile=file_instance,
                download_time=1,
                download_final_datetime=timezone.now(),
                ip_address=self.get_client_ip(request),
            )

            try:
                encrypted_aes_key = file_instance.encrypted_aes_key
                iv = file_instance.iv
                aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem)

                with file_instance.uploaded_file.open("rb") as f:
                    encrypted_file_data = f.read()
                decrypted_file_data = decrypt_file_with_aes(
                    encrypted_file_data, aes_key, iv
                )

                # Determine content type
                filename = file_instance.original_filename
                content_type, _ = mimetypes.guess_type(filename)
                content_type = content_type or "application/octet-stream"

                response = HttpResponse(decrypted_file_data, content_type=content_type)
                response["Content-Disposition"] = f'attachment; filename="{filename}"'
                return response

            except Exception as e:
                print(f"Decryption failed: {str(e)}")
                return Response(
                    {"error": f"Decryption failed: {str(e)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except Exception as e:
            print(f"Error in GetEncryptedFileView: {str(e)}")
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        return (
            x_forwarded_for.split(",")[0]
            if x_forwarded_for
            else request.META.get("REMOTE_ADDR")
        )


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
                requester_name=requester_email.split("@")[
                    0
                ],  # Use email username as name
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
