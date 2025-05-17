from django.urls import path

from . import views

urlpatterns = [
    path("", views.upload_pcap, name="upload_pcap"),
    path("results/", views.results, name="results"),
]
