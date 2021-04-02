from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ImageViewSet,AlbumViewSet,UserRegistrationView,UserProfileView, UserLoginView, ImagePostViewSet, ProfileFeed


router = DefaultRouter()
router.register('images', ImageViewSet,basename="images")
router.register('albums', AlbumViewSet,basename="albums")
router.register('posts', ImagePostViewSet,basename="posts")
router.register('feed', ProfileFeed,basename="feed")
urlpatterns = [
    path('api/', include(router.urls)),
    path('signup/', UserRegistrationView.as_view(),name="signup"),
    path('profile/', UserProfileView.as_view(),name="profile"),
    path('login/', UserLoginView.as_view(),name="login"),
]
