from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework import status, views
from rest_framework.response import Response
import json

from .models import KeyPair
from .crypto_utils import generate_rsa_key_pair, encrypt_private_key


@method_decorator(csrf_exempt, name="dispatch")
class GenerateKeyPairView(views.APIView):
    """API view to generate an RSA key pair"""

    def post(self, request):
        try:
            # Generate a new RSA key pair
            key_pair = generate_rsa_key_pair()

            # Get the password from the request (for encrypting the private key)
            data = json.loads(request.body)
            password = data.get("password")

            if not password:
                return Response(
                    {"error": "Password is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Encrypt the private key with the password
            encrypted_key_data = encrypt_private_key(key_pair["private_key"], password)

            # Create a new KeyPair object
            key_pair_obj = KeyPair.objects.create(
                user=request.user if request.user.is_authenticated else None,
                public_key=key_pair["public_key"],
                private_key_salt=encrypted_key_data["salt"],
                encrypted_private_key=encrypted_key_data["encrypted_key"],
            )

            # Return the public key and key pair ID
            return Response(
                {
                    "key_pair_id": str(key_pair_obj.id),
                    "public_key": key_pair["public_key"],
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_exempt, name="dispatch")
class GetPublicKeyView(views.APIView):
    """API view to get a public key by ID"""

    def get(self, request, key_id):
        try:
            # Get the key pair by ID
            key_pair = KeyPair.objects.get(id=key_id)

            # Return the public key
            return Response(
                {"public_key": key_pair.public_key}, status=status.HTTP_200_OK
            )

        except KeyPair.DoesNotExist:
            return Response(
                {"error": "Key pair not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
