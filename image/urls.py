from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ImageViewSet,AlbumViewSet,UserProfileView, ImagePostViewSet, ProfileFeed, UserRegistrationViewSet
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


router = DefaultRouter()
router.register('images', ImageViewSet,basename="images")
router.register('albums', AlbumViewSet,basename="albums")
router.register('posts', ImagePostViewSet,basename="posts")
router.register('feed', ProfileFeed,basename="feed")

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/signup/', UserRegistrationViewSet,name="signup"),
    path('api/profile/', UserProfileView,name="profile"),
    path('api/token/access/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/',TokenRefreshView.as_view(), name='token_refresh'),
]
