from django.urls import path
from . import views

app_name = 'yonetici'  # Namespace ekliyoruz

urlpatterns = [
    path('', views.yonetici_view, name='panel'),
    path('veri-yonetimi/', views.veri_yonetimi_view, name='veri_yonetimi'),
    path('kullanici-yonetimi/', views.kullanici_yonetimi_view, name='kullanici_yonetimi'),
    path('veri-ekle/', views.veri_ekle, name='veri_ekle'),
    path('veri-sil/<str:koleksiyon>/<str:id>/', views.veri_sil, name='veri_sil'),
    path('veri-guncelle/', views.veri_guncelle, name='veri_guncelle'),
    path('kullanici-sil/<str:id>/', views.kullanici_sil, name='kullanici_sil'),
    path('kullanici-guncelle/', views.kullanici_guncelle, name='kullanici_guncelle'),
    path('json-veri-yukle/', views.json_veri_yukle, name='json_veri_yukle'),
    path('toplu-veri-sil/', views.toplu_veri_sil, name='toplu_veri_sil'),
] 