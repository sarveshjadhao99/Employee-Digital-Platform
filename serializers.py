from rest_framework import serializers
from django.contrib.auth.models import User

from rest_framework import serializers
from .models import RegisterUser
from .models import Attendance
from .models import UserFeedback

from django.core.mail import send_mail
from django.utils.crypto import get_random_string

from django.conf import settings
import threading


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegisterUser
        fields = ['first_name', 'last_name', 'email', 'address','mobile_number','username', 'password', 'role', 'department','is_active', 'position', 'city', 'state', 'country', 'zip_code']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].required = True
        self.fields['password'].required = False  # Password will be auto-generated
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False
        self.fields['address'].required = False
        self.fields['mobile_number'].required = False
        self.fields['role'].required = True
        self.fields['department'].required = True
        self.fields['position'].required = True
        self.fields['is_active'].required = False
        self.fields['username'].required = False  # Don't require username in the request
        
        self.fields['city'].required = False  
        self.fields['state'].required = False  
        self.fields['country'].required = False  
        self.fields['zip_code'].required = False  
        

        # Send the email with the generated password
    def send_welcome_email(self, user, random_password):

        send_mail(
            subject="Welcome! Your Account Has Been Successfully Created",
            # message=f"Hello {user.first_name},\n\nYour account has been created. \n\nYour Username: {username} and password is: {random_password}\n\nPlease log in and change your password.",
            message=f"""Dear {user.first_name},
        
We are pleased to inform you that your account has been successfully created. 
Below are your account details:

◉ Username: {user.username}
◉ Password: {random_password}
◉ Department: {user.department}
◉ Position: {user.position}

Please ensure you keep your login credentials secure and confidential. 
You may change your password after your first login for enhanced security.

If you have any questions or need assistance, feel free to reach out to the department.

Welcome, and we wish you all the best in your new role!

Best regards,  
Digital Employee 
Management Portal
""",
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False
        )

    def create(self, validated_data):
        # Generate a random password
        random_password = get_random_string(length=8)

        # Use email as the username
        username = validated_data.get('email')

        # Create user with the generated password and username
        user = RegisterUser.objects.create_user(
            username=username,  # Use email as the username
            email=validated_data.get('email', ''),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            address=validated_data.get('address', ''),
            mobile_number=validated_data.get('mobile_number', ''),
            role=validated_data.get('role', ''),
            department=validated_data.get('department',''),
            position=validated_data.get('position',''),

            city=validated_data.get('city',''),
            state=validated_data.get('state',''),
            country=validated_data.get('country',''),
            zip_code=validated_data.get('zip_code',''),
            password=random_password,
            is_active=True
        )
                # Run the email sending function in a separate thread
        email_thread = threading.Thread(target=self.send_welcome_email, args=(user, random_password))
        email_thread.start()

        return user

# Attendance 

# class AttendanceSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Attendance
#         fields = ['id', 'user', 'date', 'check_in_time', 'check_out_time', 'status']

class AttendanceSerializer(serializers.ModelSerializer):
    role = serializers.CharField(source='user.role', read_only=True)
    department = serializers.CharField(source='user.department', read_only=True)
    class Meta:
        model = Attendance
        fields = ['id', 'user', 'username', 'date', 'check_in_time', 'check_out_time', 'status', 'role', 'department']

    def create(self, validated_data):
        # Create Attendance record
        attendance = Attendance.objects.create(**validated_data)
        return attendance
    

class FeedBackSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    # role = serializers.CharField(source='user.role', read_only=True)
    department = serializers.CharField(source='user.department', read_only=True)

    class Meta:
        model = UserFeedback
        fields = ['id', 'username', 'date', 'feedback', 'department'] 

    def create(self, validated_data):
        userfeedback = UserFeedback.objects.create(**validated_data)

        return userfeedback
    
