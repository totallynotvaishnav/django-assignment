from django.urls import path

from .views import RegisterUserView, LoginUserView, UserDetailView, UserEditView

urlpatterns = [
    path('register', RegisterUserView.as_view(), name='register'),
    path('login', LoginUserView.as_view(), name='login'),
    path('profile/view', UserDetailView.as_view(), name='profile-view'),
    path('profile/edit', UserEditView.as_view(), name='profile-edit'),
]