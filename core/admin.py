from django.contrib import admin
from core.models import Image, Album, User, UserManager, Post_Image, Action_Album



admin.site.register(User)
admin.site.register(Image)
admin.site.register(Album)
admin.site.register(Post_Image)
admin.site.register(Action_Album)
