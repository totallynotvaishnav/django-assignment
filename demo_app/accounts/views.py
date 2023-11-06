from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.http import HttpResponseRedirect
from django.urls import reverse
from firebase_admin import auth

from .serializers import UserRegistrationSerializer, UserLoginSerializer, UserDetailSerializer, UserEditSerializer
from .middleware import FirebaseAuthenticationMiddleware 

User = get_user_model()

class ErrorHandlingMixin:
    def handle_exception(self, exc):
        if hasattr(exc, 'status_code') and exc.status_code == 400:
            errors = exc.detail
            res_data = {
                "message": errors
            }
            print(errors)
            return Response(res_data, status=status.HTTP_400_BAD_REQUEST)
        elif hasattr(exc, 'status_code') and exc.status_code == 403:
            errors = exc.detail
            res_data = {
                "message": errors
            }
            print(errors)
            return Response(res_data, status=status.HTTP_403_FORBIDDEN)
        elif hasattr(exc, 'status_code') and exc.status_code == 401:
            errors = exc.detail
            res_data = {
                "message": errors
            }
            print(errors)
            return Response(res_data, status=status.HTTP_401_UNAUTHORIZED)
        elif hasattr(exc, 'status_code') and exc.status_code == 500:
            errors = exc.detail
            res_data = {
                "message": errors
            }
            print(errors)
            return Response(res_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RegisterUserView(ErrorHandlingMixin, generics.CreateAPIView):
    serializer_class = UserRegistrationSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        serialized_data = serializer.data
        res_data = {
            "data": serialized_data
        }
        return Response(res_data, status=status.HTTP_200_OK, headers=headers)
    
@method_decorator(FirebaseAuthenticationMiddleware, name='get')  
class LoginUserView(ErrorHandlingMixin, generics.CreateAPIView):
    serializer_class = UserLoginSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            full_name = f"{user.first_name} {user.last_name}"
            token=auth.create_custom_token(f"{user.id}")
            headers = self.get_success_headers(serializer.data)

        res_data = {
            "data": {
                "token": token,
                "username": user.username,
                "full_name": full_name,
                "email": user.email
            }
        }
        return Response(res_data, status=status.HTTP_200_OK, headers=headers)
    
    def get(self, request, *args, **kwargs):
        user = request.user
        full_name = f"{user.first_name} {user.last_name}"
        res_data = {
            "data": {
                "username": user.username,
                "full_name": full_name,
                "email": user.email
            }
        }
        return Response(res_data, status=status.HTTP_200_OK)


@method_decorator(FirebaseAuthenticationMiddleware, name='get') 
class UserDetailView(ErrorHandlingMixin, generics.RetrieveUpdateDestroyAPIView):
    serializer_class = UserDetailSerializer

    def get_queryset(self):
        return User.objects.get(username=self.request.user.username)
    
    def get(self, request, *args, **kwargs):
        serializer= self.get_serializer(request.user)
        res_data = {
            "data": serializer.data
        }
        return Response(res_data, status=status.HTTP_200_OK)
    

@method_decorator(FirebaseAuthenticationMiddleware, name='post') 
class UserEditView(ErrorHandlingMixin, generics.UpdateAPIView):
    serializer_class = UserEditSerializer
    success_url='profile-view'
    
    def get_queryset(self):
        return User.objects.get(username=self.request.user.username)
    
    def post(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        user = self.get_queryset()
        serializer = self.get_serializer(user, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        success_url = reverse(self.success_url)
        return HttpResponseRedirect(success_url)
       
