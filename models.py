
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.timezone import now
# from .models import RegisterUser

class RegisterUser(AbstractUser):
    first_name = models.TextField(max_length=20)
    last_name = models.TextField(max_length=20)
    email = models.EmailField(unique=True)
    address = models.TextField(max_length=20)
    mobile_number = models.TextField(max_length=20,blank=True, null=True)
    role = models.TextField(max_length=20, default="General")
    department = models.TextField(max_length=40, default="General")
    position = models.TextField(max_length=40,default="General" )

    city = models.TextField(max_length=40,blank=True, null=True)
    state = models.TextField(max_length=40,blank=True, null=True )
    country = models.TextField(max_length=40,blank=True, null=True )
    zip_code = models.TextField(max_length=40,blank=True, null=True )

    username = models.CharField(max_length=150, unique=True)
    USERNAME_FIELD = 'username'  # Use username for authentication
    REQUIRED_FIELDS = ['email']  # Email is a required field too

    def __str__(self):
        return self.email


class Attendance(models.Model):
    user = models.ForeignKey(RegisterUser, on_delete=models.CASCADE, related_name="attendances")
    username = models.CharField(max_length=255, blank=True, null=True)  # Add username field
    date = models.DateField(default=now)
    check_in_time = models.TimeField(blank=True, null=True)
    check_out_time = models.TimeField(blank=True, null=True)
    status = models.CharField(
        max_length=10,
        choices=[('Present', 'Present'), ('Absent', 'Absent')],
        default='Absent'
    )

    def save(self, *args, **kwargs):
        # Set the username to be the user's username when saving the attendance
        if self.user:
            self.username = self.user.username
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.status}"




class UserFeedback(models.Model):
    user = models.ForeignKey(RegisterUser, on_delete=models.CASCADE, related_name="userfeedback")
    username = models.CharField(max_length=255, blank=True, null=True)  # Add username field
    date = models.DateField(default=now)
    feedback = models.CharField(max_length=100, blank=True, null=True)
    department = models.TextField(max_length=40, blank=True, null=True)

    def save(self, *args, **kwargs):
        # Set the username to be the user's username when saving the attendance
        if self.user:
            self.username = self.user.username
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.date} - {self.feedback}"