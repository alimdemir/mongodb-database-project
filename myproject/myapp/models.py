# myapp/models.py
from djongo import models

class SensorData(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    temperature = models.FloatField()
    humidity = models.FloatField()

    def __str__(self):
        return f"Sensor Data at {self.timestamp}"

class Kaza(models.Model):
    yil = models.IntegerField()
    ay = models.CharField(max_length=20)
    kaza_olus_turu = models.CharField(max_length=100)
    kaza_sayisi = models.IntegerField()

    def __str__(self):
        return f"{self.yil} - {self.ay} - {self.kaza_olus_turu}"
