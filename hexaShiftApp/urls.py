from django.urls import path
from . import views

urlpatterns = [
    path("api/logs/", views.receive_log, name="receive_log"),
    path("", views.dashboard, name="dashboard"),  
]
