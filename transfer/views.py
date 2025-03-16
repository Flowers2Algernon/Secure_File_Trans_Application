from django.shortcuts import render
from django.http import HttpResponse,JsonResponse
from .utils import generate_code
from .models import FileShare
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt # Disable CSRF protection for this view
def generate_code_api(request):
    if request.method == 'POST': # Only allow POST requests for code generation
        code = generate_code()
        # Don't save to database since we don't have a file yet
        return JsonResponse({'code': code}) # Return the code as a JSON response
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405) # Respond with 405 Method Not Allowed for GET or other methods
    
