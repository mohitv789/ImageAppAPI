from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ImageViewSet,AlbumViewSet, ImagePostViewSet, ProfileFeed, UserRegistrationViewSet
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

from .views import LogoutAPIView, SetNewPasswordAPIView, VerifyEmail, LoginAPIView, PasswordTokenCheckAPI, RequestPasswordResetEmail


router = DefaultRouter()
router.register('images', ImageViewSet,basename="images")
router.register('albums', AlbumViewSet,basename="albums")
router.register('posts', ImagePostViewSet,basename="posts")
router.register('feed', ProfileFeed,basename="feed")

urlpatterns = [
    path('api/', include(router.urls)),
    path('register/', UserRegistrationViewSet.as_view(), name="register"),
    path('login/', LoginAPIView.as_view(), name="login"),
    path('logout/', LogoutAPIView.as_view(), name="logout"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(),
         name='password-reset-complete')
]
