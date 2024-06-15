from django.urls import path
from .views import check_website

urlpatterns = [
    path('check/<str:url>/', check_website, name='check_website'),
]
