from django.urls import path
from . import views

app_name = 'lab_5_app'
urlpatterns = [
    path('', views.index, name='index'),
    path('entities/', views.entity_list, name='entity_list'),
    path('entities/<int:pk>/', views.entity_detail, name='entity_detail'),
    path('entities/create/', views.entity_create, name='entity_create'),
    path('entities/<int:pk>/update/', views.entity_update, name='entity_update'),
    path('entities/<int:pk>/delete/', views.entity_delete, name='entity_delete'),
]