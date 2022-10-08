from rest_framework import viewsets
from core.models import Image, Album, Post_Image
from . import serializers
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated , AllowAny
from .serializers import UserLoginSerializer
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework_simplejwt import authentication
from rest_framework_simplejwt.views import TokenObtainPairView
from django.views.decorators.csrf import csrf_exempt
User = get_user_model()

class UserProfileView(RetrieveAPIView):

    permission_classes = (IsAuthenticated,)
    authentication_class = authentication.JWTAuthentication()
    serializer_class = serializers.UserSerializer

    def get(self, request):
        try:
            status_code = status.HTTP_200_OK
            response = {
                'success': 'true',
                'status code': status_code,
                'message': 'User profile fetched successfully',
                'data': [{
                    'first_name': self.request.user.first_name,
                    'last_name': self.request.user.last_name,
                    'phone_number': self.request.user.phone_number,
                    'age': self.request.user.age,
                    'gender': self.request.user.gender,
                    }]
                }

        except Exception as e:
            status_code = status.HTTP_400_BAD_REQUEST
            response = {
                'success': 'false',
                'status code': status.HTTP_400_BAD_REQUEST,
                'message': 'User does not exists',
                'error': str(e)
                }
        return Response(response, status=status_code)

    def post(self, request):
        profile = User.objects.get(user=request.user)
        serializer = self.serializer_class(data=profile)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        status_code = status.HTTP_201_CREATED
        return Response(serializer.data, status=status_code)

@csrf_exempt
class UserRegistrationViewSet(viewsets.GenericViewSet):

    serializer_class = serializers.UserRegistrationSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        status_code = status.HTTP_201_CREATED
        response = {
            'success' : 'True',
            'status code' : status_code,
            'message': 'User registered  successfully',
            }

        return Response(response, status=status_code)


@csrf_exempt
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = UserLoginSerializer
@csrf_exempt
class UserLoginView(TokenObtainPairView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer
    queryset = User.objects.all()
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        response = {
            'a' : serializer.data['token'],
            }
        status_code = status.HTTP_200_OK
        print("Signal Sent")
        return Response(response, status=status_code)

class ImageViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    authentication_class = authentication.JWTAuthentication
    serializer_class = serializers.ImageSerializer
    queryset = Image.objects.all()
    def get_queryset(self):
        queryset = self.queryset
        query_set = queryset.filter(owner=self.request.user)
        return query_set

class ProfileFeed(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    authentication_class = authentication.JWTAuthentication
    serializer_class = serializers.UserSerializer
    queryset = User.objects.all()

    @api_view(['GET'])
    def feed(self,request):
        queryset = self.queryset
        query_set = queryset.filter(owner=self.request.user)
        return query_set

class AlbumViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    authentication_class = authentication.JWTAuthentication
    serializer_class = serializers.AlbumSerializer
    queryset = Album.objects.all()
    def get_queryset(self):
        queryset = self.queryset
        query_set = queryset.filter(owner=self.request.user)
        return query_set

class ImagePostViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    authentication_class = authentication.JWTAuthentication
    serializer_class = serializers.ImagePostSerializer
    queryset = Post_Image.objects.all()


