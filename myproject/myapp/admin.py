from django.contrib import admin
from .models import Kaza  # Sadece Kaza modelini import ediyoruz

# Admin site'ı özelleştirme
admin.site.site_header = 'TTKA Yönetim Paneli'
admin.site.site_title = 'TTKA Admin'
admin.site.index_title = 'Yönetim Paneli'

# Kaza modelini admin paneline kaydedin
@admin.register(Kaza)
class KazaAdmin(admin.ModelAdmin):
    list_display = ['yil', 'ay', 'kaza_olus_turu', 'kaza_sayisi']
    list_filter = ['yil', 'ay']
    search_fields = ['kaza_olus_turu']
