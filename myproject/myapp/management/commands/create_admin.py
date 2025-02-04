from django.core.management.base import BaseCommand
from django.contrib.auth.models import User

class Command(BaseCommand):
    help = 'Creates a superuser'

    def handle(self, *args, **kwargs):
        if not User.objects.filter(username='alim').exists():
            User.objects.create_superuser('alim', 'alim@example.com', 'alim12353')
            self.stdout.write(self.style.SUCCESS('Admin kullanıcısı başarıyla oluşturuldu')) 