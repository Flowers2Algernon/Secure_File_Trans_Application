from django.shortcuts import render
from django.http import HttpResponse
from .utils import generate_code
from .models import FileShare

def generat_code_api(request):
    if request.method == 'POST': # Only allow POST requests for code generation
        code = generate_code()
        file_share = FileShare(code=code) # Create a new FileShare object and set the code
        file_share.save() # Save the object to the database
        return JsonResponse({'code': code}) # Return the code as a JSON response
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405) # Respond with 405 Method Not Allowed for GET or other methods
