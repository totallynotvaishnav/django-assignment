from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate

import random
import string


User = get_user_model()

def generate_username():
        # Generates a unique username (e.g., "wishfulPanda23")
        random_part = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        return f'wishfulPanda{random_part}'

class UserRegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100, required=False, error_messages={
            'max_length': 'Only 100 characters are allowed for the username.',
        })
    email = serializers.EmailField(
        error_messages={
            'required': 'Email is required.',
            'invalid': 'Enter a valid email address.',
        }
    )
    password = serializers.CharField(min_length=8, write_only=True, error_messages={
            'min_length': 'This password is too short. It must contain at least 8 characters.',
        })
    first_name = serializers.CharField(max_length=100, required=False, allow_blank=True, error_messages={
            'max_length': 'Only 100 characters are allowed for the first name.',
        })
    last_name = serializers.CharField(max_length=100, required=False, allow_blank=True, error_messages={
            'max_length': 'Only 100 characters are allowed for the first name.',
        })

    def validate(self, data):
        super().validate(data)

        if User.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError('A user with that username already exists')
        
        if not data.get('username'):
            while True:
                username = generate_username()
                if not User.objects.filter(username=username).exists():
                    break

            data['username'] = username

        if User.objects.filter(username=data['username']).exists():
            raise serializers.ValidationError('A user with that username already exists')

        return data   


    def create(self, validated_data):
        user= User.objects.create_user(**validated_data)
        user.save()
        return user
    
    def to_representation(self, instance):
        res={}
        res['username']=instance.username
        res['email']=instance.email
        return res
    
class UserLoginSerializer(serializers.Serializer):
    id=serializers.IntegerField(read_only=True)
    username=serializers.CharField()
    password=serializers.CharField(write_only=True)

    def validate(self, data):
        super().validate(data)
        username=data.get('username',None)
        password=data.get('password',None)
        if username is None:
            raise serializers.ValidationError('Username is required')
        if password is None:
            raise serializers.ValidationError('Password is required')
        user=authenticate(username=username,password=password)
        if user is None:
            raise serializers.ValidationError('Username or password is invalid')
        data['user']=user
        return data
    
class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=('username','email','first_name','last_name')
        extra_kwargs={'username':{'read_only':True},
                        'email':{'read_only':True},
                        'first_name':{'read_only':True},
                        'last_name':{'read_only':True}}
        
    def to_representation(self, instance):
        res={
            'username': instance.username,
            'email': instance.email,
            'full_name':f'{instance.first_name} {instance.last_name}'
        }
        return res
    
class UserEditSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=('username','first_name','last_name')
        extra_kwargs={'username':{'required':False},
                        'first_name':{'required':False},
                        'email':{'read_only':True},
                        'last_name':{'required':False}}
        
    def validate(self, data):
        super().validate(data)
        username=data.get('username',None)

        if username and User.objects.filter(username=username).exists():
            raise serializers.ValidationError(f'User already exist with the username ${username}')
        
        return data
       
    def update(self, instance, validated_data):
        if 'username' in validated_data:
            instance.username=validated_data['username']
        
        if 'first_name' in validated_data:
            instance.first_name=validated_data['first_name']

        if 'last_name' in validated_data:
            instance.last_name=validated_data['last_name']

        instance.save()
        
        return instance
    
         
    def to_representation(self, instance):
        res={
            'username': instance.username,
            'email': instance.email,
            'full_name':f'{instance.first_name} {instance.last_name}'
        }
        return res
               