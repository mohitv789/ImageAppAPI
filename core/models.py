from django.db import models
import uuid
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.template.defaultfilters import slugify
from django.conf import settings

class UserManager(BaseUserManager):

    def create_user(self, email,password=None):
        if not email:
            raise ValueError('Users Must Have an email address')

        user = self.model(
            email = self.normalize_email(email)
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):

        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


class User(AbstractBaseUser,PermissionsMixin):
    slug = models.CharField(max_length=100, unique=True)
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
    )
    email = models.EmailField(
        verbose_name='email address',
        max_length=255,
        unique=True
        )
    first_name = models.CharField(max_length=50, unique=False)
    last_name = models.CharField(max_length=50, unique=False)
    phone_number = models.CharField(max_length=15, unique=True)
    age = models.PositiveIntegerField()
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    objects = UserManager()

    def __str__(self):
        return self.email

    def save(self,*args,**kwargs):
        email_str = self.email.split("@")[0]
        slug_str = "%s" % (email_str)
        self.slug = slugify(slug_str)
        super(User, self).save(*args, **kwargs)
        

class Image(models.Model):
    name = models.CharField(max_length=255)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,related_name='image_posted_by', blank=False,on_delete=models.CASCADE)
    description = models.TextField()
    imagePath = models.CharField(max_length=255)
    def __str__(self):
        return self.name


class Album(models.Model):
    title = models.CharField(max_length=255)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,related_name='album_posted_by', blank=False,on_delete=models.CASCADE)
    published_on = models.CharField(max_length=255)

    def __str__(self):
        return self.title


class Post_Image(models.Model):
    commented_by = models.ForeignKey(User,on_delete=models.CASCADE, related_name="commented_by")
    content = models.CharField(max_length=250, unique=False)
    image_post = models.ForeignKey(Image,on_delete=models.CASCADE, related_name="image_post")
    created = models.DateTimeField(auto_now_add=True)

    def save(self,*args,**kwargs):
        super().save(*args,**kwargs)

    def __str__(self):
        return self.content[:25]

    class Meta:
        ordering = ['created']
        unique_together = ['commented_by','content']

class Action_Album(models.Model):
    commented_by = models.ForeignKey(User,on_delete=models.CASCADE, related_name="action_by")
    album_post = models.ForeignKey(Album,on_delete=models.CASCADE, related_name="album_post")
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content[:25]

    class Meta:
        ordering = ['created']
