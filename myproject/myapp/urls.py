from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index_view, name='index'),
    path('giris/', views.giris_view, name='giris'),
    path('kayit/', views.kayit_view, name='kayit'),
    path('hakkinda/', views.hakkinda_view, name='hakkinda'),
    path('yonetici/', include(('myapp.urls_yonetici', 'yonetici'), namespace='yonetici')),
    path('iller/', views.iller_view, name='iller'),
    path('olumlu-yaralanmali/', views.olumlu_yaralanmali_view, name='olumlu_yaralanmali'),
    path('cikis/', views.cikis_view, name='cikis'),
    path('ceza/', views.ceza_view, name='ceza'),
    path('get-il-kaza-verileri/', views.get_il_kaza_verileri, name='get_il_kaza_verileri'),
    path('turkiye-geneli/', views.turkiye_geneli_view, name='turkiye_geneli'),
] 