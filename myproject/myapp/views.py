from django.shortcuts import render, redirect
from pymongo import MongoClient
from django.contrib import messages
from datetime import datetime, timedelta
import json
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm
from bson import ObjectId
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
import bcrypt
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth.decorators import user_passes_test
import traceback
from django.core.exceptions import ValidationError
from django.http import JsonResponse

def get_user_data(request):
    try:
        user_data = json.loads(request.COOKIES.get('user_data', '{}'))
        return user_data
    except:
        return {}

def login_required_custom(view_func):
    def wrapped_view(request, *args, **kwargs):
        user_data = get_user_data(request)
        if not user_data.get('is_authenticated'):
            next_url = request.path
            return redirect(f"{settings.LOGIN_URL}?next={next_url}")
        return view_func(request, *args, **kwargs)
    return wrapped_view

def admin_required_custom(view_func):
    def wrapped_view(request, *args, **kwargs):
        print("\n=== Admin Required Decorator Başladı ===")
        user_data = get_user_data(request)
        print(f"Kullanıcı verileri: {user_data}")
        
        # Kullanıcı giriş yapmamışsa
        if not user_data or not user_data.get('is_authenticated'):
            print("Kullanıcı giriş yapmamış")
            messages.warning(request, 'Lütfen önce giriş yapın.')
            return redirect('giris')
        
        # Kullanıcı admin değilse
        if user_data.get('username') != 'alim':
            print("Yetkisiz erişim denemesi")
            messages.error(request, 'Bu sayfaya erişim yetkiniz yok!')
            return redirect('index')
        
        print("Yetkilendirme başarılı")
        return view_func(request, *args, **kwargs)
    
    return wrapped_view

def index_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        
        # Genel kaza verilerini çek
        genel_collection = db['genel']
        
        # 2024 Aralık ayı verilerini sorgula
        kaza_verileri = genel_collection.find_one({
            'yil': 2024,
            'ay': 'aralik'
        })
        
        if kaza_verileri:
            # Ay ismini düzgün formata çevir
            ay_isimleri = {
                'ocak': 'Ocak', 'subat': 'Şubat', 'mart': 'Mart',
                'nisan': 'Nisan', 'mayis': 'Mayıs', 'haziran': 'Haziran',
                'temmuz': 'Temmuz', 'agustos': 'Ağustos', 'eylul': 'Eylül',
                'ekim': 'Ekim', 'kasim': 'Kasım', 'aralik': 'Aralık'
            }
            
            # Kaza verilerini hazırla
            kaza_verileri = {
                'yil': kaza_verileri.get('yil'),
                'ay': ay_isimleri.get(kaza_verileri.get('ay', ''), kaza_verileri.get('ay', '').capitalize()),
                'yerlesim_yeri': {
                    'toplam_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('toplam_kaza_sayisi', 0),
                    'olumlu_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('olumlu_kaza_sayisi', 0),
                    'yaralanmali_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('yaralanmali_kaza_sayisi', 0),
                    'maddi_hasarli_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('maddi_hasarli_kaza_sayisi', 0),
                    'olu_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('olu_sayisi', 0),
                    'yarali_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri', {}).get('yarali_sayisi', 0)
                },
                'yerlesim_yeri_disi': {
                    'toplam_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('toplam_kaza_sayisi', 0),
                    'olumlu_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('olumlu_kaza_sayisi', 0),
                    'yaralanmali_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('yaralanmali_kaza_sayisi', 0),
                    'maddi_hasarli_kaza_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('maddi_hasarli_kaza_sayisi', 0),
                    'olu_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('olu_sayisi', 0),
                    'yarali_sayisi': kaza_verileri.get('veriler', {}).get('yerlesim_yeri_disi', {}).get('yarali_sayisi', 0)
                },
                'toplam': {
                    'toplam_kaza_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('toplam_kaza_sayisi', 0),
                    'olumlu_kaza_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('olumlu_kaza_sayisi', 0),
                    'yaralanmali_kaza_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('yaralanmali_kaza_sayisi', 0),
                    'maddi_hasarli_kaza_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('maddi_hasarli_kaza_sayisi', 0),
                    'olu_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('olu_sayisi', 0),
                    'yarali_sayisi': kaza_verileri.get('veriler', {}).get('toplam', {}).get('yarali_sayisi', 0)
                }
            }
            
            print(f"Aralık ayı genel kaza verileri: {kaza_verileri}")  # Debug için
        else:
            print("2024 Aralık ayı verileri bulunamadı!")
            kaza_verileri = None

        # En fazla kazalı il verilerini al
        en_fazla_kazali_il = anasayfa_enfazla_kaza_il()
        
        context = {
            'user_data': get_user_data(request),
            'kaza_verileri': kaza_verileri,
            'en_fazla_kazali_il': en_fazla_kazali_il
        }
        
        return render(request, 'index.html', context)
        
    except Exception as e:
        print(f"Index sayfası hatası: {str(e)}")
        print(f"Hata detayı: {traceback.format_exc()}")  # Detaylı hata mesajı
        return render(request, 'index.html', {
            'user_data': get_user_data(request),
            'kaza_verileri': None,
            'en_fazla_kazali_il': None
        })
    finally:
        if 'client' in locals():
            client.close()

def giris_view(request):
    if request.method == 'POST':
        try:
            print("\n=== Giriş İşlemi Başladı ===")
            
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            users_collection = db['kullanicilar']  # Koleksiyon adını değiştirdik

            username = request.POST.get('username')
            password = request.POST.get('password')

            print(f"Giriş denemesi - Kullanıcı: {username}")

            # Kullanıcıyı bul
            user = users_collection.find_one({'username': username})
            print(f"Bulunan kullanıcı: {user}")

            if user:
                # Şifre kontrolü - sadece hash'li karşılaştırma yap
                stored_password = user.get('password', '')
                
                if check_password(password, stored_password):
                    print("Şifre doğrulandı")
                    
                    # Kullanıcı bilgilerini cookie'de sakla
                    user_data = {
                        'username': user['username'],
                        'is_authenticated': True,
                        'is_admin': user.get('is_admin', False)
                    }
                    
                    # Son giriş zamanını güncelle
                    users_collection.update_one(
                        {'_id': user['_id']},
                        {'$set': {'last_login': datetime.now()}}
                    )
                    
                    response = redirect('index')
                    response.set_cookie('user_data', json.dumps(user_data), max_age=86400)
                    
                    messages.success(request, f'Hoş geldiniz, {username}!')
                    return response
                else:
                    print("Şifre eşleşmedi")
                    messages.error(request, 'Kullanıcı adı veya şifre hatalı!')
            else:
                print("Kullanıcı bulunamadı")
                messages.error(request, 'Kullanıcı adı veya şifre hatalı!')

        except Exception as e:
            print(f"Giriş hatası: {str(e)}")
            print(f"Hata detayı: {traceback.format_exc()}")
            messages.error(request, f'Giriş yapılırken bir hata oluştu: {str(e)}')
        finally:
            if 'client' in locals():
                client.close()
                print("MongoDB bağlantısı kapatıldı")
            print("=== Giriş İşlemi Tamamlandı ===\n")

    return render(request, 'giris.html')

def kayit_view(request):
    if request.method == 'POST':
        try:
            print("\n=== Kayıt İşlemi Başladı ===")
            
            # MongoDB bağlantısı
            print("MongoDB bağlantısı kuruluyor...")
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            users_collection = db['kullanicilar']
            print("MongoDB bağlantısı başarılı")

            # Form verilerini al
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            password2 = request.POST.get('password2')
            
            print(f"Alınan form verileri:")
            print(f"Username: {username}")
            print(f"Email: {email}")
            print(f"Password length: {len(password) if password else 0}")
            print(f"Password2 length: {len(password2) if password2 else 0}")

            # Temel doğrulamalar
            if not all([username, email, password, password2]):
                print("Hata: Eksik form verileri")
                messages.error(request, 'Tüm alanları doldurunuz!')
                return render(request, 'kayit.html')

            if password != password2:
                print("Hata: Şifreler eşleşmiyor")
                messages.error(request, 'Şifreler eşleşmiyor!')
                return render(request, 'kayit.html')

            # Kullanıcı adı kontrolü
            existing_user = users_collection.find_one({'username': username})
            if existing_user:
                print(f"Hata: Kullanıcı adı '{username}' zaten kullanımda")
                messages.error(request, 'Bu kullanıcı adı zaten kullanılıyor!')
                return render(request, 'kayit.html')

            # Email kontrolü
            existing_email = users_collection.find_one({'email': email})
            if existing_email:
                print(f"Hata: Email '{email}' zaten kullanımda")
                messages.error(request, 'Bu email adresi zaten kullanılıyor!')
                return render(request, 'kayit.html')

            # Yeni kullanıcı oluştur
            hashed_password = make_password(password)
            new_user = {
                '_id': ObjectId(),
                'username': username,
                'email': email,
                'password': hashed_password,
                'is_active': True,
                'is_admin': False,
                'date_joined': datetime.now(),
                'last_login': None
            }
            
            print("\nOluşturulan kullanıcı verisi:")
            print(f"Username: {new_user['username']}")
            print(f"Email: {new_user['email']}")
            print(f"Is Active: {new_user['is_active']}")
            print(f"Is Admin: {new_user['is_admin']}")
            print(f"Date Joined: {new_user['date_joined']}")

            # Kullanıcıyı veritabanına ekle
            print("\nVeritabanına ekleniyor...")
            result = users_collection.insert_one(new_user)
            
            if result.inserted_id:
                print(f"Başarılı! Kullanıcı ID: {result.inserted_id}")
                messages.success(request, 'Kayıt başarılı! Şimdi giriş yapabilirsiniz.')
                return redirect('giris')
            else:
                print("Hata: insert_one başarısız oldu")
                messages.error(request, 'Kayıt sırasında bir hata oluştu.')
                return render(request, 'kayit.html')

        except Exception as e:
            print(f"\nKRİTİK HATA: {str(e)}")
            print(f"Hata detayı: {traceback.format_exc()}")
            messages.error(request, f'Kayıt olurken bir hata oluştu: {str(e)}')
            return render(request, 'kayit.html')
        finally:
            if 'client' in locals():
                print("\nMongoDB bağlantısı kapatılıyor...")
                client.close()
                print("MongoDB bağlantısı kapatıldı")
            print("=== Kayıt İşlemi Tamamlandı ===\n")

    return render(request, 'kayit.html')

@admin_required_custom
def veri_yonetimi_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        
        # Ay sıralama sözlüğü
        ay_siralama = {
            'ocak': 1, 'subat': 2, 'mart': 3, 'nisan': 4,
            'mayis': 5, 'haziran': 6, 'temmuz': 7, 'agustos': 8,
            'eylul': 9, 'ekim': 10, 'kasim': 11, 'aralik': 12
        }
        
        # Ay isimleri sözlüğü
        ay_isimleri = {
            'ocak': 'Ocak', 'subat': 'Şubat', 'mart': 'Mart',
            'nisan': 'Nisan', 'mayis': 'Mayıs', 'haziran': 'Haziran',
            'temmuz': 'Temmuz', 'agustos': 'Ağustos', 'eylul': 'Eylül',
            'ekim': 'Ekim', 'kasim': 'Kasım', 'aralik': 'Aralık'
        }
        
        # Seçili filtreleri al
        selected_koleksiyon = request.GET.get('koleksiyon', '')
        selected_yil = request.GET.get('yil', '')
        selected_ay = request.GET.get('ay', '')
        search_query = request.GET.get('search', '').lower()  # Arama sorgusunu al
        
        # Seçili ayı küçük harfe çevir
        if selected_ay:
            selected_ay = selected_ay.lower()
            # Türkçe karakter düzeltmeleri
            selected_ay = selected_ay.replace('ş', 's').replace('ı', 'i').replace('ğ', 'g').replace('ü', 'u').replace('ö', 'o')
        
        all_years = set()
        all_months = set()
        
        koleksiyonlar = [
            'genel', 'iller', 'kaza_arac_cinsleri', 'kaza_arac_sayisi',
            'kaza_olus_turleri', 'kaza_unsurlari', 'surucu_kusurlari',
            'trafik_cezalari'
        ]
        
        veriler = []
        
        if selected_koleksiyon:
            koleksiyonlar = [selected_koleksiyon]
        
        for koleksiyon in koleksiyonlar:
            collection = db[koleksiyon]
            
            # Filtreleme için query oluştur
            query = {}
            if selected_yil:
                query['yil'] = int(selected_yil)
            if selected_ay:
                query['ay'] = selected_ay
            
            # Verileri çek
            cursor = collection.find(query)
            
            # Her veriyi işle ve arama filtresini uygula
            for veri in cursor:
                veri_dict = {
                    'id': str(veri['_id']),
                    'koleksiyon_adi': koleksiyon,
                    'yil': veri.get('yil'),
                    'ay': veri.get('ay'),
                    'veriler': veri.get('veriler', {}),
                    'veriler_json': json.dumps(veri.get('veriler', {}))
                }
                
                # Arama sorgusu varsa filtrele
                if search_query:
                    # Koleksiyon adında ara
                    if search_query in koleksiyon.lower():
                        veriler.append(veri_dict)
                        continue
                        
                    # Verilerin içinde ara
                    veriler_str = str(veri.get('veriler', {})).lower()
                    if search_query in veriler_str:
                        veriler.append(veri_dict)
                        continue
                        
                    # Yıl ve ay içinde ara
                    if (search_query in str(veri.get('yil', '')) or 
                        search_query in str(veri.get('ay', '')).lower()):
                        veriler.append(veri_dict)
                        continue
                else:
                    veriler.append(veri_dict)

        # Yılları al (2020'den şu ana kadar)
        current_year = datetime.now().year
        years = range(2020, current_year + 1)
        
        # Seçili yıl
        selected_yil = request.GET.get('yil', '')
        
        # Filtreleme
        if selected_yil:
            veriler = [veri for veri in veriler if veri['yil'] == int(selected_yil)]

        context = {
            'veriler': veriler,
            'koleksiyonlar': koleksiyonlar,
            'available_years': years,
            'available_months': [ay_isimleri.get(ay, ay.title()) for ay in all_months],
            'selected_koleksiyon': selected_koleksiyon,
            'selected_yil': selected_yil,
            'selected_ay': selected_ay,
            'search_query': search_query  # Arama sorgusunu context'e ekle
        }
        
        return render(request, 'veri_yonetimi.html', context)
        
    except Exception as e:
        print(f"Veri yönetimi hatası: {str(e)}")
        return render(request, 'veri_yonetimi.html', {
            'veriler': [],
            'koleksiyonlar': [],
            'available_years': [],
            'available_months': [],
            'error': str(e)
        })
    finally:
        if 'client' in locals():
            client.close()

def cikis_view(request):
    try:
        # Tüm mesajları temizle
        storage = messages.get_messages(request)
        storage.used = True
        
        # Cookie'yi temizle
        response = redirect('giris')  # Doğrudan giriş sayfasına yönlendir
        response.delete_cookie('user_data')
        
        # Yeni bir başarılı çıkış mesajı ekle
        messages.success(request, 'Başarıyla çıkış yaptınız!')
        
        return response
        
    except Exception as e:
        print(f"Çıkış hatası: {str(e)}")
        messages.error(request, 'Çıkış yaparken bir hata oluştu.')
        return redirect('index')

def iller_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        il_collection = db['iller']
        
        # Ay isimleri sözlüğü - sıralı olarak
        ay_mapping = {
            'Ocak': 'ocak',
            'Şubat': 'subat',
            'Mart': 'mart',
            'Nisan': 'nisan',
            'Mayıs': 'mayis',
            'Haziran': 'haziran',
            'Temmuz': 'temmuz',
            'Ağustos': 'agustos',
            'Eylül': 'eylul',
            'Ekim': 'ekim',
            'Kasım': 'kasim',
            'Aralık': 'aralik'
        }
        
        # Ters ay mapping
        ters_ay_mapping = {v: k for k, v in ay_mapping.items()}
        
        # Mevcut yılları ve ayları al
        available_years = sorted(list(il_collection.distinct('yil')), reverse=True)
        
        # Ayları sıralı şekilde hazırla
        sirali_aylar = [
            'Ocak', 'Şubat', 'Mart', 'Nisan', 'Mayıs', 'Haziran',
            'Temmuz', 'Ağustos', 'Eylül', 'Ekim', 'Kasım', 'Aralık'
        ]
        
        # Seçili yıl ve ay değerlerini al
        selected_yil = request.GET.get('yil', '')
        selected_ay_display = request.GET.get('ay', '')
        selected_ay = ay_mapping.get(selected_ay_display, '')
        
        # Arama filtresi
        search_query = request.GET.get('search', '').lower()
        
        # Filtreleme kriterleri
        filter_criteria = {}
        if selected_yil:
            filter_criteria['yil'] = int(selected_yil)
        if selected_ay:
            filter_criteria['ay'] = selected_ay
        
        # Verileri çek
        il_verileri = list(il_collection.find(filter_criteria))
        
        # Ay isimlerini düzgün formata çevir
        for il in il_verileri:
            il['ay'] = ters_ay_mapping.get(il['ay'], il['ay'])
        
        # Arama filtresi uygula
        if search_query:
            il_verileri = [il for il in il_verileri if search_query in il['veriler']['il'].lower()]
        
        context = {
            'il_verileri': il_verileri,
            'available_years': available_years,
            'available_months': sirali_aylar,  # Sıralı ayları kullan
            'selected_yil': selected_yil,
            'selected_ay': selected_ay_display,
            'user_data': get_user_data(request)
        }
        
        return render(request, 'iller.html', context)
        
    except Exception as e:
        print(f"İller sayfası hatası: {str(e)}")
        messages.error(request, 'Veriler yüklenirken bir hata oluştu.')
        return render(request, 'iller.html', {
            'user_data': get_user_data(request),
            'il_verileri': [],
            'available_years': [],
            'available_months': [],
            'selected_yil': '',
            'selected_ay': ''
        })
    finally:
        if 'client' in locals():
            client.close()

def login_view(request):
    # Önceki mesajları temizle
    storage = messages.get_messages(request)
    storage.used = True
    
    # Eğer kullanıcı zaten giriş yapmışsa
    user_data = get_user_data(request)
    if user_data.get('is_authenticated'):
        next_url = request.GET.get('next', 'index')
        return redirect(next_url)

    if request.method == 'POST':
        try:
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            users = db['kullanicilar']
            
            username = request.POST.get('username')
            password = request.POST.get('password')
            
            user = users.find_one({'username': username})
            
            if user and check_password(password, user.get('password', '')):
                # Kullanıcı bilgilerini cookie'ye kaydet
                user_data = {
                    'is_authenticated': True,
                    'username': username,
                    'user_id': str(user['_id']),
                    'is_superuser': username == 'alim'
                }
                
                # Yönlendirme URL'sini belirle
                next_url = request.GET.get('next', 'index')
                response = redirect(next_url)
                
                # Cookie'yi ayarla
                response.set_cookie(
                    'user_data',
                    json.dumps(user_data),
                    max_age=1209600,
                    httponly=False,
                    secure=False,
                    samesite='Lax'
                )
                
                messages.success(request, f'Hoş geldiniz, {username}!')
                return response
            else:
                messages.error(request, 'Kullanıcı adı veya şifre hatalı!')
                
        except Exception as e:
            print(f"Login error: {str(e)}")
            messages.error(request, 'Giriş sırasında bir hata oluştu!')
        finally:
            if 'client' in locals():
                client.close()
            
    return render(request, 'giris.html')

@admin_required_custom
def yonetici_view(request):
    try:
        user_data = get_user_data(request)
        
        # MongoDB bağlantısı
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        users_collection = db['kullanicilar']
        
        # Basit context
        context = {
            'user_data': user_data,
            'user_count': users_collection.count_documents({}),
            'accident_count': 1000,
            'monthly_data': 150,
            'active_users': 50
        }
        
        return render(request, 'yonetici.html', context)
        
    except Exception as e:
        print(f"Yönetici paneli hatası: {str(e)}")
        messages.error(request, 'Bir hata oluştu: ' + str(e))
        return redirect('index')
    finally:
        if 'client' in locals():
            client.close()

@admin_required_custom
def kullanici_yonetimi_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        users_collection = db['kullanicilar']
        
        # Tüm kullanıcıları çek
        users = list(users_collection.find())
        
        # Her kullanıcı için verileri hazırla
        for user in users:
            # ObjectId'yi string'e çevir
            user['id'] = str(user['_id'])
            
            # Varsayılan değerleri ayarla
            user['is_active'] = user.get('is_active', True)
            user['is_admin'] = user.get('is_admin', False)
            user['email'] = user.get('email', '')
            
            # Son giriş tarihini formatlı göster
            if 'last_login' in user:
                try:
                    if isinstance(user['last_login'], str):
                        last_login = datetime.strptime(user['last_login'], "%Y-%m-%d %H:%M:%S")
                    else:
                        last_login = user['last_login']
                    user['last_login'] = last_login.strftime("%d.%m.%Y %H:%M")
                except:
                    user['last_login'] = None
            else:
                user['last_login'] = None
        
        context = {
            'user_data': get_user_data(request),
            'users': users
        }
        
        return render(request, 'kullanici_yonetimi.html', context)
        
    except Exception as e:
        print(f"Kullanıcı yönetimi hatası: {str(e)}")
        print(f"Hata detayı: {traceback.format_exc()}")
        messages.error(request, 'Kullanıcı listesi alınırken bir hata oluştu.')
        return redirect('yonetici:panel')
    finally:
        if 'client' in locals():
            client.close()

@admin_required_custom
def veri_ekle(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            koleksiyon = data.get('koleksiyon')
            veri = data.get('veri')
            
            if not koleksiyon or not veri:
                return JsonResponse({
                    'success': False,
                    'error': 'Eksik veri'
                })
            
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            collection = db[koleksiyon]
            
            # Veriyi ekle
            result = collection.insert_one(veri)
            
            return JsonResponse({
                'success': True,
                'message': 'Veri başarıyla eklendi'
            })
            
        except Exception as e:
            print(f"Veri ekleme hatası: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
        finally:
            if 'client' in locals():
                client.close()
    
    return JsonResponse({
        'success': False,
        'error': 'Geçersiz istek'
    })

@admin_required_custom
def veri_sil(request, koleksiyon, id):
    if request.method == 'POST':
        try:
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            collection = db[koleksiyon]
            
            # ObjectId'yi string'den ObjectId'ye çevir
            from bson.objectid import ObjectId
            result = collection.delete_one({'_id': ObjectId(id)})
            
            if result.deleted_count > 0:
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'error': 'Veri bulunamadı'})
                
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
        finally:
            if 'client' in locals():
                client.close()

@admin_required_custom
def toplu_veri_sil(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            veriler = data.get('veriler', [])
            
            if not veriler:
                return JsonResponse({
                    'success': False,
                    'error': 'Silinecek veri seçilmedi'
                })
            
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            
            silinen_sayisi = 0
            
            for veri in veriler:
                koleksiyon = veri.get('koleksiyon')
                veri_id = veri.get('id')
                yil = int(veri.get('yil'))
                ay = veri.get('ay')
                
                if not koleksiyon or not veri_id:
                    continue
                
                collection = db[koleksiyon]
                
                if koleksiyon == 'genel':
                    # Genel koleksiyonu için doğrudan silme işlemi
                    result = collection.delete_one({
                        '_id': ObjectId(veri_id),
                        'yil': yil,
                        'ay': ay
                    })
                    print(f"Silme sonucu: {result.deleted_count}")  # Debug için
                    if result.deleted_count > 0:
                        silinen_sayisi += 1
                else:
                    # Diğer koleksiyonlar için normal silme
                    result = collection.delete_one({'_id': ObjectId(veri_id)})
                    if result.deleted_count > 0:
                        silinen_sayisi += 1
            
            return JsonResponse({
                'success': True,
                'message': f'{silinen_sayisi} veri başarıyla silindi'
            })
            
        except Exception as e:
            print(f"Toplu silme hatası: {str(e)}")
            return JsonResponse({
                'success': False,
                'error': str(e)
            })
        finally:
            if 'client' in locals():
                client.close()
    
    return JsonResponse({
        'success': False,
        'error': 'Geçersiz istek'
    })

@admin_required_custom
def veri_guncelle(request):
    if request.method == 'POST':
        try:
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            
            # Form verilerini al
            veri_id = request.POST.get('id')
            koleksiyon = request.POST.get('koleksiyon')
            yil = int(request.POST.get('yil'))
            ay = request.POST.get('ay').lower()
            
            # Koleksiyonu seç
            collection = db[koleksiyon]
            
            # Veri yapısını oluştur
            veri_data = {
                'yil': yil,
                'ay': ay,
                'veriler': {}
            }
            
            # Koleksiyona göre veri yapısını oluştur
            if koleksiyon == 'genel':
                veri_data['veriler'] = {
                    'yerlesim_yeri': {
                        'toplam_kaza_sayisi': int(request.POST.get('yerlesim_toplam_kaza', 0)),
                        'olumlu_kaza_sayisi': int(request.POST.get('yerlesim_olumlu', 0)),
                        'yaralanmali_kaza_sayisi': int(request.POST.get('yerlesim_yaralanmali', 0)),
                        'maddi_hasarli_kaza_sayisi': int(request.POST.get('yerlesim_maddi', 0))
                    },
                    'yerlesim_yeri_disi': {
                        'toplam_kaza_sayisi': int(request.POST.get('disi_toplam_kaza', 0)),
                        'olumlu_kaza_sayisi': int(request.POST.get('disi_olumlu', 0)),
                        'yaralanmali_kaza_sayisi': int(request.POST.get('disi_yaralanmali', 0)),
                        'maddi_hasarli_kaza_sayisi': int(request.POST.get('disi_maddi', 0))
                    }
                }
            elif koleksiyon == 'iller':
                veri_data['veriler'] = {
                    'il': request.POST.get('il', ''),
                    'olumlu_yarali_kaza': int(request.POST.get('olumlu_yarali_kaza', 0)),
                    'maddi_hasarli_kaza': int(request.POST.get('maddi_hasarli_kaza', 0)),
                    'olu_sayisi': int(request.POST.get('olu_sayisi', 0)),
                    'yarali_sayisi': int(request.POST.get('yarali_sayisi', 0))
                }
            elif koleksiyon in ['kaza_arac_cinsleri', 'kaza_olus_turleri']:
                veri_data['veriler'] = {
                    koleksiyon.split('_')[1]: request.POST.get(f"{koleksiyon.split('_')[1]}", ''),
                    'kaza_sayisi': int(request.POST.get('kaza_sayisi', 0))
                }
            elif koleksiyon == 'kaza_arac_sayisi':
                veri_data['veriler'] = {
                    'arac_turu': request.POST.get('arac_turu', ''),
                    'arac_sayisi': int(request.POST.get('arac_sayisi', 0))
                }
            elif koleksiyon == 'kaza_unsurlari':
                veri_data['veriler'] = {
                    'kaza_unsuru': request.POST.get('kaza_unsuru', ''),
                    'kusur_sayisi': int(request.POST.get('kusur_sayisi', 0))
                }
            elif koleksiyon == 'surucu_kusurlari':
                veri_data['veriler'] = {
                    'kusur_turu': request.POST.get('kusur_turu', ''),
                    'kusur_sayisi': int(request.POST.get('kusur_sayisi', 0))
                }
            elif koleksiyon == 'trafik_cezalari':
                veri_data['veriler'] = {
                    'ceza_turu': request.POST.get('ceza_turu', ''),
                    'ceza_sayisi': int(request.POST.get('ceza_sayisi', 0))
                }
            
            # Veriyi güncelle
            result = collection.update_one(
                {'_id': ObjectId(veri_id)},
                {'$set': veri_data}
            )
            
            if result.modified_count > 0:
                messages.success(request, 'Veri başarıyla güncellendi.')
            else:
                messages.warning(request, 'Veri güncellenemedi veya değişiklik yapılmadı.')
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            print(f"Veri güncelleme hatası: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)})
        finally:
            if 'client' in locals():
                client.close()
    
    return JsonResponse({'success': False, 'error': 'Geçersiz istek metodu'})

@admin_required_custom
def kullanici_sil(request, id):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        users_collection = db['kullanicilar']
        
        # Kullanıcıyı sil
        result = users_collection.delete_one({'_id': ObjectId(id)})
        
        if result.deleted_count > 0:
            messages.success(request, 'Kullanıcı başarıyla silindi.')
        else:
            messages.error(request, 'Kullanıcı bulunamadı.')
            
    except Exception as e:
        messages.error(request, f'Kullanıcı silinirken hata oluştu: {str(e)}')
    finally:
        client.close()
    
    return redirect('yonetici:kullanici_yonetimi')

@admin_required_custom
def kullanici_guncelle(request):
    if request.method == 'POST':
        try:
            print("\n=== Kullanıcı Güncelleme Başladı ===")
            
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            users_collection = db['kullanicilar']

            user_id = request.POST.get('user_id')
            username = request.POST.get('username')
            email = request.POST.get('email')
            is_active = request.POST.get('is_active') == 'true'
            is_admin = request.POST.get('is_admin') == 'true'

            print(f"Güncelleme verileri:")
            print(f"User ID: {user_id}")
            print(f"Username: {username}")
            print(f"Email: {email}")
            print(f"Is Active: {is_active}")
            print(f"Is Admin: {is_admin}")

            # ObjectId'ye çevir
            user_id = ObjectId(user_id)

            # Mevcut kullanıcıyı kontrol et
            existing_user = users_collection.find_one({'_id': user_id})
            if not existing_user:
                print(f"Hata: {user_id} ID'li kullanıcı bulunamadı")
                messages.error(request, 'Kullanıcı bulunamadı!')
                return redirect('yonetici:kullanici_yonetimi')

            # Kullanıcı adı benzersizlik kontrolü
            username_exists = users_collection.find_one({
                '_id': {'$ne': user_id},
                'username': username
            })
            if username_exists:
                print(f"Hata: {username} kullanıcı adı başka bir kullanıcı tarafından kullanılıyor")
                messages.error(request, 'Bu kullanıcı adı başka bir kullanıcı tarafından kullanılıyor!')
                return redirect('yonetici:kullanici_yonetimi')

            # Email benzersizlik kontrolü
            email_exists = users_collection.find_one({
                '_id': {'$ne': user_id},
                'email': email
            })
            if email_exists:
                print(f"Hata: {email} email adresi başka bir kullanıcı tarafından kullanılıyor")
                messages.error(request, 'Bu email adresi başka bir kullanıcı tarafından kullanılıyor!')
                return redirect('yonetici:kullanici_yonetimi')

            # Güncelleme verilerini hazırla
            update_data = {
                'username': username,
                'email': email,
                'is_active': is_active,
                'is_admin': is_admin,
                'updated_at': datetime.now()
            }

            # Güncelleme işlemini gerçekleştir
            result = users_collection.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )

            if result.modified_count > 0:
                print(f"Başarılı! Kullanıcı güncellendi: {username}")
                messages.success(request, f'{username} kullanıcısı başarıyla güncellendi.')
            else:
                print("Uyarı: Herhangi bir değişiklik yapılmadı")
                messages.info(request, 'Herhangi bir değişiklik yapılmadı.')

        except Exception as e:
            print(f"\nKRİTİK HATA: {str(e)}")
            print(f"Hata detayı: {traceback.format_exc()}")
            messages.error(request, f'Güncelleme sırasında bir hata oluştu: {str(e)}')
        finally:
            if 'client' in locals():
                print("\nMongoDB bağlantısı kapatılıyor...")
                client.close()
                print("MongoDB bağlantısı kapatıldı")
            print("=== Kullanıcı Güncelleme Tamamlandı ===\n")

    return redirect('yonetici:kullanici_yonetimi')

def hakkinda_view(request):
    return render(request, 'hakkinda.html', {
        'user_data': get_user_data(request)
    })

def ceza_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        collection = db['trafik_cezalari']
        user_data = get_user_data(request)
        
        # Mevcut yılları ve ayları al (en başta alıyoruz)
        available_years = sorted(list(collection.distinct('yil')), reverse=True)
        available_months = sorted(list(collection.distinct('ay')))
        
        # Varsayılan değerleri belirle
        default_year = str(max(available_years)) if available_years else '2024'
        default_month = 'ocak'  # veya available_months[0] if available_months else 'ocak'
        
        # Ay isimleri sözlüğü
        ay_mapping = {
            'Ocak': 'ocak',
            'Şubat': 'subat',
            'Mart': 'mart',
            'Nisan': 'nisan',
            'Mayıs': 'mayis',
            'Haziran': 'haziran',
            'Temmuz': 'temmuz',
            'Ağustos': 'agustos',
            'Eylül': 'eylul',
            'Ekim': 'ekim',
            'Kasım': 'kasim',
            'Aralık': 'aralik'
        }
        
        # Ters ay mapping
        ters_ay_mapping = {v: k for k, v in ay_mapping.items()}
        
        # Filtreleme parametrelerini al
        selected_yil = request.GET.get('yil', default_year)
        selected_ay_display = request.GET.get('ay', ters_ay_mapping.get(default_month, 'Ocak'))
        selected_ay = ay_mapping.get(selected_ay_display, default_month)
        search_query = request.GET.get('search', '').lower()
        
        # Filtreleme kriterleri
        filter_criteria = {
            'yil': int(selected_yil),
            'ay': selected_ay
        }
            
        # Verileri çek
        cezalar = list(collection.find(filter_criteria))
        
        # Arama filtresi uygula
        if search_query:
            cezalar = [ceza for ceza in cezalar if 
                      search_query in ceza['veriler']['ceza_turu'].lower()]
        
        # Ayları Türkçe formata çevir
        display_months = [ters_ay_mapping[ay] for ay in available_months]
        
        context = {
            'user_data': user_data,
            'cezalar': cezalar,
            'available_years': available_years,
            'available_months': sorted(display_months),
            'selected_yil': selected_yil,
            'selected_ay': selected_ay_display,
            'search_query': search_query
        }
        
        return render(request, 'ceza.html', context)
        
    except Exception as e:
        print(f"Trafik cezaları sayfası hatası: {str(e)}")
        messages.error(request, 'Veriler yüklenirken bir hata oluştu.')
        return render(request, 'ceza.html', {
            'user_data': user_data,
            'cezalar': [],
            'available_years': [],
            'available_months': [],
            'selected_yil': '2024',
            'selected_ay': 'Ocak',
            'search_query': ''
        })
    finally:
        if 'client' in locals():
            client.close()

@admin_required_custom
def json_veri_yukle(request):
    if request.method == 'POST':
        try:
            json_files = request.FILES.getlist('json_files[]')
            koleksiyon_adi = request.POST.get('koleksiyon')
            
            if not json_files:
                messages.error(request, 'Lütfen en az bir JSON dosyası seçin.')
                return redirect('veri_yonetimi')
            if not koleksiyon_adi:
                messages.error(request, 'Lütfen bir koleksiyon seçin.')
                return redirect('veri_yonetimi')
            
            client = MongoClient('mongodb://localhost:27017/')
            db = client['trafik_kaza']
            
            basarili_yukleme = 0
            toplam_veri = 0
            koleksiyon = db[koleksiyon_adi]
            
            for json_file in json_files:
                try:
                    # JSON dosyasını oku ve decode et
                    content = json_file.read().decode('utf-8')
                    data = json.loads(content)
                    
                    # Veri yapısını kontrol et
                    if isinstance(data, dict) and 'veriler' in data:
                        veriler = data['veriler']
                    elif isinstance(data, list):
                        veriler = data
                    else:
                        veriler = [data]  # Tek bir veri objesi ise
                    
                    # Her bir veriyi ayrı ayrı ekle
                    for veri in veriler:
                        if not isinstance(veri, dict):
                            continue
                            
                        # Veri yapısını kontrol et ve gerekli alanları ekle
                        if 'yil' not in veri or 'ay' not in veri:
                            continue
                            
                        try:
                            # Veriyi ekle
                            result = koleksiyon.insert_one(veri)
                            if result.inserted_id:
                                toplam_veri += 1
                        except Exception as e:
                            print(f"Veri ekleme hatası: {str(e)}")
                            continue
                    
                    basarili_yukleme += 1
                    messages.success(request, f'{json_file.name}: Başarıyla yüklendi.')
                    
                except json.JSONDecodeError:
                    messages.error(request, f'{json_file.name}: Geçersiz JSON formatı.')
                except Exception as e:
                    messages.error(request, f'{json_file.name}: Yükleme hatası - {str(e)}')
            
            if basarili_yukleme > 0:
                messages.success(request, f'Toplam {basarili_yukleme} dosya ve {toplam_veri} veri başarıyla yüklendi.')
            else:
                messages.warning(request, 'Hiçbir veri yüklenemedi.')
            
        except Exception as e:
            messages.error(request, f'Hata oluştu: {str(e)}')
        finally:
            if 'client' in locals():
                client.close()
    
    return redirect('veri_yonetimi')

def olumlu_yaralanmali_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        
        # Koleksiyonları tanımla
        kaza_olus_collection = db['kaza_olus_turleri']
        arac_cins_collection = db['kaza_arac_cinsleri']
        arac_sayisi_collection = db['kaza_arac_sayisi']
        kaza_unsur_collection = db['kaza_unsurlari']
        surucu_kusur_collection = db['surucu_kusurlari']

        # Tüm koleksiyonlardan yılları al ve birleştir
        years_from_collections = set()
        for collection in [kaza_olus_collection, arac_cins_collection, 
                         arac_sayisi_collection, kaza_unsur_collection, 
                         surucu_kusur_collection]:
            years = collection.distinct('yil')
            years_from_collections.update(years)

        # Yılları sırala
        available_years = sorted(list(years_from_collections), reverse=True)
        
        if not available_years:  # Eğer hiç yıl bulunamadıysa
            available_years = [2023]  # Varsayılan yıl
            print("Uyarı: Veritabanında hiç yıl verisi bulunamadı!")

        print(f"\nBulunan Yıllar: {available_years}")

        available_months = ['Ocak', 'Şubat', 'Mart', 'Nisan', 'Mayıs', 'Haziran', 
                          'Temmuz', 'Ağustos', 'Eylül', 'Ekim', 'Kasım', 'Aralık']

        # Ay isimlerini MongoDB formatına çevir
        ay_mapping = {
            'Ocak': 'ocak', 'Şubat': 'subat', 'Mart': 'mart',
            'Nisan': 'nisan', 'Mayıs': 'mayis', 'Haziran': 'haziran',
            'Temmuz': 'temmuz', 'Ağustos': 'agustos', 'Eylül': 'eylul',
            'Ekim': 'ekim', 'Kasım': 'kasim', 'Aralık': 'aralik'
        }

        # Filtreleme parametrelerini al
        selected_yil = request.GET.get('yil', str(available_years[0]) if available_years else '2023')
        selected_ay_display = request.GET.get('ay', 'Aralık')
        selected_ay = ay_mapping.get(selected_ay_display, 'aralik')

        # MongoDB sorguları - her koleksiyon için özel filtreler
        kaza_olus_query = {
            'yil': int(selected_yil),
            'ay': selected_ay,
            'veriler.kaza_olus_turu': {'$exists': True, '$ne': ''},
            'veriler.kaza_sayisi': {'$exists': True, '$ne': 0}
        }

        arac_cins_query = {
            'yil': int(selected_yil),
            'ay': selected_ay,
            'veriler.arac_cinsi': {'$exists': True, '$ne': ''},
            'veriler.arac_sayisi': {'$exists': True, '$ne': 0}
        }

        kaza_arac_query = {
            'yil': int(selected_yil),
            'ay': selected_ay,
            'veriler.arac_turu': {'$exists': True, '$ne': ''},
            'veriler.arac_sayisi': {'$exists': True, '$ne': 0}
        }

        kaza_unsur_query = {
            'yil': int(selected_yil),
            'ay': selected_ay,
            'veriler.kusur_unsuru': {'$exists': True, '$ne': ''},
            'veriler.kusur_sayisi': {'$exists': True, '$ne': 0}
        }

        surucu_kusur_query = {
            'yil': int(selected_yil),
            'ay': selected_ay,
            'veriler.kusur_turu': {'$exists': True, '$ne': ''},
            'veriler.kusur_sayisi': {'$exists': True, '$ne': 0}
        }

        # Verileri çek
        kazalar = list(kaza_olus_collection.find(kaza_olus_query))
        arac_verileri = list(arac_cins_collection.find(arac_cins_query))
        kaza_arac_verileri = list(arac_sayisi_collection.find(kaza_arac_query))
        kaza_unsurlari_verileri = list(kaza_unsur_collection.find(kaza_unsur_query))
        surucu_kusurlari_verileri = list(surucu_kusur_collection.find(surucu_kusur_query))

        print(f"\nBulunan Veri Sayıları:")
        print(f"Kazalar: {len(kazalar)}")
        print(f"Araç Verileri: {len(arac_verileri)}")
        print(f"Kaza Araç Verileri: {len(kaza_arac_verileri)}")
        print(f"Kaza Unsurları: {len(kaza_unsurlari_verileri)}")
        print(f"Sürücü Kusurları: {len(surucu_kusurlari_verileri)}")

        # Eğer hiç veri bulunamadıysa
        if not any([kazalar, arac_verileri, kaza_arac_verileri, kaza_unsurlari_verileri, surucu_kusurlari_verileri]):
            print(f"\nHiç veri bulunamadı!")
            # MongoDB'deki mevcut verileri kontrol et
            print("\nMongoDB'deki Veriler:")
            print(f"Kaza Oluş Türleri: {list(kaza_olus_collection.find())}")
            print(f"Araç Cinsleri: {list(arac_cins_collection.find())}")
            print(f"Kaza Araç Sayısı: {list(arac_sayisi_collection.find())}")
            print(f"Kaza Unsurları: {list(kaza_unsur_collection.find())}")
            print(f"Sürücü Kusurları: {list(surucu_kusur_collection.find())}")

        # Grafik verilerini hazırla
        bar_chart_data = {
            'kaza_olus_turleri': [],
            'kaza_sayilari': []
        }
        
        # Kaza oluş türleri verilerini hazırla
        for kaza in kazalar:
            if 'veriler' in kaza and 'kaza_olus_turu' in kaza['veriler'] and kaza['veriler']['kaza_sayisi']:
                bar_chart_data['kaza_olus_turleri'].append(kaza['veriler']['kaza_olus_turu'])
                bar_chart_data['kaza_sayilari'].append(kaza['veriler']['kaza_sayisi'])

        # Araç cinsleri verilerini hazırla
        donut_chart_data = {
            'arac_cinsi': [],
            'kaza_sayisi': []
        }
        for arac in arac_verileri:
            if ('veriler' in arac and 
                'arac_cinsi' in arac['veriler'] and 
                'arac_sayisi' in arac['veriler'] and 
                arac['veriler']['arac_cinsi'] and 
                arac['veriler']['arac_sayisi']):
                donut_chart_data['arac_cinsi'].append(arac['veriler']['arac_cinsi'])
                donut_chart_data['kaza_sayisi'].append(arac['veriler']['arac_sayisi'])

        # Kaza araç sayısı verilerini hazırla
        kaza_arac_sayisi_data = {
            'labels': [],
            'values': []
        }
        for veri in kaza_arac_verileri:
            if ('veriler' in veri and 
                'arac_turu' in veri['veriler'] and 
                'arac_sayisi' in veri['veriler'] and 
                veri['veriler']['arac_turu'] and 
                veri['veriler']['arac_sayisi']):
                kaza_arac_sayisi_data['labels'].append(veri['veriler']['arac_turu'])
                kaza_arac_sayisi_data['values'].append(veri['veriler']['arac_sayisi'])

        # Kaza unsurları verilerini hazırla
        kaza_unsurlari_data = {
            'labels': [],
            'values': []
        }
        for veri in kaza_unsurlari_verileri:
            if ('veriler' in veri and 
                'kusur_unsuru' in veri['veriler'] and 
                'kusur_sayisi' in veri['veriler'] and 
                veri['veriler']['kusur_unsuru'] and 
                veri['veriler']['kusur_sayisi']):
                kaza_unsurlari_data['labels'].append(veri['veriler']['kusur_unsuru'])
                kaza_unsurlari_data['values'].append(veri['veriler']['kusur_sayisi'])

        # Sürücü kusurları verilerini hazırla
        surucu_kusurlari_data = {
            'labels': [],
            'values': []
        }
        for veri in surucu_kusurlari_verileri:
            if ('veriler' in veri and 
                'kusur_turu' in veri['veriler'] and 
                'kusur_sayisi' in veri['veriler'] and 
                veri['veriler']['kusur_turu'] and 
                veri['veriler']['kusur_sayisi']):
                surucu_kusurlari_data['labels'].append(veri['veriler']['kusur_turu'])
                surucu_kusurlari_data['values'].append(veri['veriler']['kusur_sayisi'])

        context = {
            'user_data': get_user_data(request),
            'selected_yil': selected_yil,
            'selected_ay': selected_ay_display,
            'available_years': available_years,
            'available_months': available_months,
            'kazalar': kazalar,
            'arac_verileri': arac_verileri,
            'kaza_arac_verileri': kaza_arac_verileri,
            'kaza_unsurlari_verileri': kaza_unsurlari_verileri,
            'surucu_kusurlari_verileri': surucu_kusurlari_verileri,
            'bar_chart_data': json.dumps(bar_chart_data),
            'donut_chart_data': json.dumps(donut_chart_data),
            'kaza_arac_sayisi_data': json.dumps(kaza_arac_sayisi_data),
            'kaza_unsurlari_data': json.dumps(kaza_unsurlari_data),
            'surucu_kusurlari_data': json.dumps(surucu_kusurlari_data)
        }

        return render(request, 'olumlu-yaralanmali.html', context)

    except Exception as e:
        print(f"Hata: {str(e)}")
        traceback.print_exc()
        # Hata durumunda varsayılan aylar listesini ekleyelim
        default_months = ['Ocak', 'Şubat', 'Mart', 'Nisan', 'Mayıs', 'Haziran', 
                         'Temmuz', 'Ağustos', 'Eylül', 'Ekim', 'Kasım', 'Aralık']
        return render(request, 'olumlu-yaralanmali.html', {
            'error': str(e),
            'user_data': get_user_data(request),
            'selected_yil': '2023',
            'selected_ay': 'Aralık',
            'available_years': [],
            'available_months': default_months,  # Varsayılan aylar listesi
            # Boş grafik verileri
            'bar_chart_data': json.dumps({'kaza_olus_turleri': [], 'kaza_sayilari': []}),
            'donut_chart_data': json.dumps({'arac_cinsi': [], 'kaza_sayisi': []}),
            'kaza_arac_sayisi_data': json.dumps({'labels': [], 'values': []}),
            'kaza_unsurlari_data': json.dumps({'labels': [], 'values': []}),
            'surucu_kusurlari_data': json.dumps({'labels': [], 'values': []})
        })
    finally:
        if 'client' in locals():
            client.close()

def get_il_kaza_verileri(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        iller_collection = db['iller']
        
        # Aralık 2024 için sabit sorgu
        yil = 2024
        ay = 'aralik'
        
        # İl adları eşleştirme sözlüğü
        il_mapping = {
            'D.BAKIR': 'DIYARBAKIR',
            'K.MARAS': 'KAHRAMANMARAS',
            'Ş.URFA': 'SANLIURFA',
            'G.ANTEP': 'GAZIANTEP',
            'AFYONKARAHİSAR': 'AFYONKARAHISAR',
            'KAHRAMANMARAŞ': 'KAHRAMANMARAS',
            'İSTANBUL': 'ISTANBUL',
            'İZMİR': 'IZMIR',
            'ŞANLIURFA': 'SANLIURFA',
            'GAZİANTEP': 'GAZIANTEP',
            'DİYARBAKIR': 'DIYARBAKIR'
        }

        # İl adını standartlaştırma fonksiyonu
        def standardize_il_adi(il_adi):
            if not il_adi:
                return ''
            # Boşlukları temizle ve büyük harfe çevir
            il_adi = il_adi.strip().upper()
            # Türkçe karakterleri İngilizce karakterlere çevir
            tr_to_en = str.maketrans('ÇĞİÖŞÜçğıöşü', 'CGIOSUcgiosu')
            il_adi = il_adi.translate(tr_to_en)
            # Eşleştirme sözlüğünden kontrol et
            return il_mapping.get(il_adi, il_adi)

        # Aralık 2024 verilerini çek
        iller = list(iller_collection.find({
            'yil': yil,
            'ay': ay
        }))
        
        # Debug için verileri kontrol et
        print(f"Toplam il sayısı: {len(iller)}")
        print(f"Yıl: {yil}, Ay: {ay}")
        
        # İl verilerini işle
        il_verileri = {}
        for il in iller:
            if 'veriler' in il and 'il' in il['veriler']:
                il_adi = standardize_il_adi(il['veriler']['il'])
                
                print(f"Orijinal il adı: {il['veriler']['il']}, Standartlaştırılmış: {il_adi}")  # Debug için
                
                toplam_kaza = (
                    il['veriler'].get('olumlu_yarali_kaza', 0) +
                    il['veriler'].get('maddi_hasarli_kaza', 0)
                )
                
                il_verileri[il_adi] = {
                    'toplam_kaza': toplam_kaza,
                    'olumlu_yarali_kaza': il['veriler'].get('olumlu_yarali_kaza', 0),
                    'maddi_hasarli_kaza': il['veriler'].get('maddi_hasarli_kaza', 0),
                    'olu_sayisi': il['veriler'].get('olu_sayisi', 0),
                    'yarali_sayisi': il['veriler'].get('yarali_sayisi', 0)
                }
        
        # Debug için il verilerini kontrol et
        print("İşlenen iller:")
        for il in sorted(il_verileri.keys()):
            print(f"{il}: {il_verileri[il]['toplam_kaza']} kaza")
        
        return JsonResponse({
            'success': True,
            'il_verileri': il_verileri,
            'yil': yil,
            'ay': ay
        })
            
    except Exception as e:
        print(f"İl kaza verileri çekilirken hata: {str(e)}")
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': str(e)
        })
    finally:
        if 'client' in locals():
            client.close()

def anasayfa_enfazla_kaza_il():
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        il_collection = db['iller']
        
        # İstanbul'un verilerini direkt sorgula
        query = {
            'yil': 2024,
            'ay': 'aralik',
            'veriler.il': {'$in': ['İSTANBUL', 'ISTANBUL']}  # Türkçe karakter ve normal hali
        }
        
        # İstanbul verilerini çek
        istanbul = il_collection.find_one(query)
        
        if not istanbul:
            print("İstanbul'un Aralık ayı verileri bulunamadı!")
            # Debug için mevcut verileri kontrol et
            print("Mevcut veriler:")
            tum_veriler = list(il_collection.find())
            for veri in tum_veriler:
                print(f"Yıl: {veri.get('yil')}, Ay: {veri.get('ay')}, İl: {veri.get('veriler', {}).get('il')}")
            return None
            
        # İl verilerini hazırla
        il_verileri = {
            'il_adi': 'İSTANBUL',
            'toplam_kaza': (
                istanbul.get('veriler', {}).get('olumlu_yarali_kaza', 0) +
                istanbul.get('veriler', {}).get('maddi_hasarli_kaza', 0)
            ),
            'olumlu_yarali_kaza': istanbul.get('veriler', {}).get('olumlu_yarali_kaza', 0),
            'maddi_hasarli_kaza': istanbul.get('veriler', {}).get('maddi_hasarli_kaza', 0),
            'olu_sayisi': istanbul.get('veriler', {}).get('olu_sayisi', 0),
            'yarali_sayisi': istanbul.get('veriler', {}).get('yarali_sayisi', 0)
        }
        
        print(f"İstanbul'un Aralık ayı verileri: {il_verileri}")  # Debug için
        return il_verileri
        
    except Exception as e:
        print(f"İstanbul verilerini çekme hatası: {str(e)}")
        print(f"Hata detayı: {traceback.format_exc()}")  # Detaylı hata mesajı
        return None
    finally:
        if 'client' in locals():
            client.close()

def index(request):
    try:
        # En fazla kazalı il verilerini al
        en_fazla_kazali_il = anasayfa_enfazla_kaza_il()
        
        return render(request, 'index.html', {
            'user_data': get_user_data(request),
            'en_fazla_kazali_il': en_fazla_kazali_il
        })
    except Exception as e:
        print(f"Index sayfası hatası: {str(e)}")
        return render(request, 'index.html', {
            'user_data': get_user_data(request)
        })

def turkiye_geneli_view(request):
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['trafik_kaza']
        genel_collection = db['genel']
        
        # Mevcut yılları ve ayları al
        available_years = sorted(list(genel_collection.distinct('yil')), reverse=True)
        
        # Ay isimleri sözlüğü
        ay_mapping = {
            'Ocak': 'ocak', 'Şubat': 'subat', 'Mart': 'mart',
            'Nisan': 'nisan', 'Mayıs': 'mayis', 'Haziran': 'haziran',
            'Temmuz': 'temmuz', 'Ağustos': 'agustos', 'Eylül': 'eylul',
            'Ekim': 'ekim', 'Kasım': 'kasim', 'Aralık': 'aralik'
        }
        
        # Ters ay mapping
        ters_ay_mapping = {v: k for k, v in ay_mapping.items()}
        
        # Ayları sıralı şekilde hazırla
        sirali_aylar = [
            'Ocak', 'Şubat', 'Mart', 'Nisan', 'Mayıs', 'Haziran',
            'Temmuz', 'Ağustos', 'Eylül', 'Ekim', 'Kasım', 'Aralık'
        ]
        
        # Seçili yıl ve ay değerlerini al
        selected_yil = request.GET.get('yil', str(available_years[0]) if available_years else '2024')
        selected_ay_display = request.GET.get('ay', 'Aralık')
        selected_ay = ay_mapping.get(selected_ay_display, 'aralik')
        
        # Verileri çek
        query = {
            'yil': int(selected_yil),
            'ay': selected_ay
        }
        
        genel_veri = genel_collection.find_one(query)
        
        if genel_veri:
            genel_veri['ay'] = ters_ay_mapping.get(genel_veri['ay'], genel_veri['ay'].capitalize())
        
        context = {
            'user_data': get_user_data(request),
            'genel_veri': genel_veri,
            'available_years': available_years,
            'available_months': sirali_aylar,
            'selected_yil': selected_yil,
            'selected_ay': selected_ay_display
        }
        
        return render(request, 'turkiye_geneli.html', context)
        
    except Exception as e:
        print(f"Türkiye geneli sayfası hatası: {str(e)}")
        messages.error(request, 'Veriler yüklenirken bir hata oluştu.')
        return render(request, 'turkiye_geneli.html', {
            'user_data': get_user_data(request),
            'genel_veri': None,
            'available_years': [],
            'available_months': sirali_aylar,
            'selected_yil': '2024',
            'selected_ay': 'Aralık'
        })
    finally:
        if 'client' in locals():
            client.close()

def veri_yonetimi(request):
    # Mevcut kodlar...

    # Yılları al (2020'den şu ana kadar)
    current_year = datetime.now().year
    years = range(2020, current_year + 1)
    
    # Seçili yıl
    selected_yil = request.GET.get('yil', '')
    
    # Filtreleme
    if selected_yil:
        veriler = veriler.filter(yil=selected_yil)

    context = {
        'veriler': veriler,
        'available_years': years,
        'selected_yil': selected_yil,
        # ... diğer context verileri
    }



