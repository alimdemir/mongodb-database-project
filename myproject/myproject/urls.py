# myproject/urls.py
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('myapp.urls')),  # Tüm myapp URL'lerini include et
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)



