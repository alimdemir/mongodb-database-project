import json

def user_data(request):
    try:
        cookie_data = request.COOKIES.get('user_data')
        if cookie_data:
            print("Raw cookie data:", cookie_data)  # Debug için
            user_data = json.loads(cookie_data)
            print("Parsed user data:", user_data)  # Debug için
            if user_data and user_data.get('is_authenticated'):
                return {'user_data': user_data}
        return {'user_data': {'is_authenticated': False}}
    except Exception as e:
        print(f"Context processor error: {str(e)}")  # Debug için
        return {'user_data': {'is_authenticated': False}} 