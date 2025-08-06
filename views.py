from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from .serializers import RegisterUserSerializer, AttendanceSerializer, FeedBackSerializer
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from .models import Attendance, RegisterUser, UserFeedback
from rest_framework.permissions import IsAuthenticated
from django.conf import settings
import random
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication,BasicAuthentication, TokenAuthentication
from rest_framework.permissions import AllowAny
from datetime import date

import threading
from django.core.cache import cache  # Django cache to temporarily store the OTP
from django.utils.timezone import now
from datetime import datetime

class RegisterUserView(APIView):
    def post(self, request):
        serializer = RegisterUserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        email = request.data.get('username')  # Use 'username' key for email
        password = request.data.get('password')

        # Validate that email and password are provided
        if not email or not password:
            return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Manually fetch the user to check the active status
            user = RegisterUser.objects.get(username=email)
            if not user.is_active:
                return Response({'error': 'This account is Blocked.'}, status=status.HTTP_403_FORBIDDEN)
        except RegisterUser.DoesNotExist:
            return Response({'error': 'Invalid email or password.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Authenticate the user with valid credentials
        user = authenticate(username=email, password=password)

        if user:
            # Get the current date
            today = date.today()

            # Fetch today's attendance for the user
            attendance = Attendance.objects.filter(user=user, date=today).first()

            # Determine attendance status
            attendance_status = attendance.status if attendance else 'Absent'

            # Create or retrieve the token for the user
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'role': user.role,
                'username': user.username,
                'department': user.department,
                'status': attendance_status
            }, status=status.HTTP_200_OK)

        # Invalid password case
        return Response({'error': 'Invalid email or password.'}, status=status.HTTP_401_UNAUTHORIZED)

# LogOut User API
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Delete the user's token to logout
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Role and Departmwnt wise show data (Change functionality)

class AllUsersDataView(APIView):
    def get(self, request):
        # Get role and department from query parameters
        role = request.query_params.get('role', None)
        department = request.query_params.get('department', None)

        # Ensure both role and department are provided
        if not role or not department:
            return Response(
                {"error": "Both 'role' and 'department' are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Filter users based on role and department
        users = RegisterUser.objects.filter(role=role, department=department)

        # Serialize the data
        serializer = RegisterUserSerializer(users, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

# All User Show role wise

class SU_AllUsersDataView(APIView):
    def get(self, request):
        # Fetch all users
        users = RegisterUser.objects.all()

        # Group users by role
        grouped_users = {}
        for user in users:
            user_role = user.role  
            if user_role not in grouped_users:
                grouped_users[user_role] = []
            grouped_users[user_role].append(RegisterUserSerializer(user).data)

        return Response(grouped_users, status=status.HTTP_200_OK)


# Profile View using Username 

class UserProfileView(APIView):
    def get(self, request):
        username = request.query_params.get('username')  # Extract 'username' from query parameters
        
        if not username:
            return Response(
                {"error": "Username query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = RegisterUser.objects.get(username=username)
            
            # Serialize the user data
            serializer = RegisterUserSerializer(user)
            
            # Additional related data (if applicable)
            profile_data = serializer.data
            profile_data.pop('password', None)
            token = Token.objects.filter(user=user).first()
            profile_data['token'] = token.key if token else None

            # Get today's attendance status
            today = date.today()
            attendance = Attendance.objects.filter(user=user, date=today).first()
            profile_data['status'] = attendance.status if attendance else 'Absent'

            return Response(profile_data, status=status.HTTP_200_OK)
        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

# Update Profile

    def put(self, request):
        username = request.query_params.get('username')

        if not username:
            return Response(
                {"error": "Username query parameter is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = RegisterUser.objects.get(username=username)
        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = RegisterUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Change PassWord
class UserChangePassView(APIView):
    def post(self, request):
        # Get all the required parameters from the request body
        username = request.data.get('username')
        old_password = request.data.get('old_password')
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        # Check if all required fields are provided
        if not username or not old_password or not new_password or not confirm_new_password:
            return Response(
                {"error": "Username, old password, new password, and confirm new password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the new password and confirm password match
        if new_password != confirm_new_password:
            return Response(
                {"error": "New password and confirm new password do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Fetch the user from the database
            user = RegisterUser.objects.get(username=username)

            # Check if the old password is correct
            if not user.check_password(old_password):
                return Response(
                    {"error": "Old password is incorrect."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Set the new password and save the user
            user.set_password(new_password)
            user.save()

            return Response({"success": "Password changed successfully."}, status=status.HTTP_200_OK)
        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "User not found."},
                status=status.HTTP_404_NOT_FOUND
            )

# Forget Password OTP Sent to Mail
class ForgotPasswordView(APIView):
    def send_otp_email(self, email, firstName, lastName, otp):
        # Send OTP to user's email
        subject = "Password Reset OTP"
        # message = f"{firstName} {lastName}Your OTP code is: {otp}. Please enter it within 05 minutes. Do not share this code with anyone. "
        message = f"""Dear {firstName} {lastName},

Your One-Time Password (OTP) for verification is: {otp}

Please use this OTP to complete your verification process. This code is valid for the next 05 Minute. Do not share it with anyone for security reasons.

If you did not request this OTP, please ignore this message or contact our support team immediately.

Thank you,
Digital Employee 
Management Portal"""
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)
    
    def post(self, request):
        username = request.data.get('username')

        if not username:
            return Response(
                {"error": "username is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Check if the email exists in the database
            user = RegisterUser.objects.get(username=username)
            email = user.email
            firstName = user.first_name
            lastName = user.last_name

            # Generate a random OTP (6 digits)
            otp = random.randint(100000, 999999)

            # Store OTP in cache with a timeout (e.g., 5 minutes)
            cache.set(f"otp_{username}", otp, timeout=300)  # Cache for 5 minutes
            
            # Run the email sending function in a separate thread
            email_thread = threading.Thread(target=self.send_otp_email, args=(email, firstName, lastName, otp))
            email_thread.start()

            return Response(
                {"message": "OTP sent successfully to your email."},
                status=status.HTTP_200_OK
            )

        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "username not found."},
                status=status.HTTP_404_NOT_FOUND
            )

            
# Verify OTP
class VerifyForgotPassOTPView(APIView):
    def post(self, request):
        username = request.data.get('username')
        otp = request.data.get('otp')

        if not username or not otp:
            return Response(
                {"error": "Username and OTP are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Check if the user exists
            user = RegisterUser.objects.get(username=username)

            # Retrieve OTP from cache
            cached_otp = cache.get(f"otp_{username}")

            if cached_otp is None:
                return Response(
                    {"error": "OTP has expired or was not generated."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Compare the OTPs
            if otp == str(cached_otp):
                return Response(
                    {"message": "OTP is valid. You can now reset your password."},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"error": "Invalid OTP."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "Username not found."},
                status=status.HTTP_404_NOT_FOUND
            )

# Update Password

# Update Pass Without OTP

class ResetPasswordView(APIView):
    def post(self, request):
        username = request.data.get('username')
        new_password = request.data.get('new_password')
        confirm_new_password = request.data.get('confirm_new_password')

        # Validate required fields
        if not username or not new_password or not confirm_new_password:
            return Response(
                {"error": "Username, new password, and confirm new password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if the passwords match
        if new_password != confirm_new_password:
            return Response(
                {"error": "New password and confirm new password do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Check if the user exists
            user = RegisterUser.objects.get(username=username)

            # Update the password
            user.set_password(new_password)
            user.save()

            return Response(
                {"message": "Password updated successfully."},
                status=status.HTTP_200_OK
            )

        except RegisterUser.DoesNotExist:
            return Response(
                {"error": "Username not found."},
                status=status.HTTP_404_NOT_FOUND
            )


# BlockUser

class BlockUserView(APIView):
    def post(self, request):
        username = request.data.get('username')

        if not username:
            return Response({"error": "Username is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = RegisterUser.objects.get(username=username)
            if not user.is_active:
                return Response({"message": "User is already blocked."}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = False
            user.save()
            return Response({"message": f"User {username} has been blocked successfully."}, status=status.HTTP_200_OK)

        except RegisterUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

# UnblockUser
class UnblockUserView(APIView):
    def post(self, request):
        username = request.data.get('username')

        if not username:
            return Response({"error": "Username is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = RegisterUser.objects.get(username=username)
            if user.is_active:
                return Response({"message": "User is already active."}, status=status.HTTP_400_BAD_REQUEST)

            user.is_active = True
            user.save()
            return Response({"message": f"User {username} has been unblocked successfully."}, status=status.HTTP_200_OK)

        except RegisterUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


# Mark Attendance


class UserCheckInView(APIView):
    # Remove authentication and permissions
    authentication_classes = []  # Disable authentication
    permission_classes = [AllowAny]  # Allow public access

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        status = request.data.get("status")
        action = request.data.get("action")

        if not username or not status or not action:
            return Response({"error": "Missing required fields."}, status=400)

        # Get the current user
        user = RegisterUser.objects.filter(email=username).first()
        if not user:
            return Response({"error": "User not found."}, status=404)

        today = date.today()

        if action == "check-in":
            check_in_time = datetime.now().time()  # Capture the current time
            attendance, created = Attendance.objects.get_or_create(user=user, date=today)

            if attendance.check_in_time:
                return Response({"message": "User already checked in for today."}, status=400)

            attendance.status = status
            attendance.check_in_time = check_in_time
            attendance.save()

            return Response(
                {
                    "message": "Check-in successful.",
                    "username": username,
                    "date": today,
                    "check_in_time": check_in_time,
                    "status": status,
                },
                status=200,
            )

        return Response({"error": "Invalid action."}, status=400)

class UserCheckOutView(APIView):
    authentication_classes = []  # Disable authentication
    permission_classes = [AllowAny]  # Allow public access

    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        action = request.data.get("action")

        if not username or not action:
            return Response({"error": "Missing required fields."}, status=400)

        # Get the user
        user = RegisterUser.objects.filter(email=username).first()
        if not user:
            return Response({"error": "User not found."}, status=404)

        today = date.today()

        if action == "check-out":
            check_out_time = datetime.now().time()  # Capture the current time
            try:
                attendance = Attendance.objects.get(user=user, date=today)
            except Attendance.DoesNotExist:
                return Response({"error": "No check-in record found for today."}, status=404)

            if attendance.check_out_time:
                return Response({"message": "User already checked out for today."}, status=400)

            attendance.check_out_time = check_out_time
            attendance.save()

            return Response(
                {
                    "message": "Check-out successful.",
                    "username": username,
                    "date": today,
                    "check_out_time": check_out_time,
                    "status": attendance.status,
                },
                status=200,
            )

        return Response({"error": "Invalid action."}, status=400)

class AllAttendanceView(APIView):
    permission_classes = [AllowAny]  # You can change this to authentication-based access

    def get(self, request, *args, **kwargs):
        # Fetch all attendance records
        attendances = Attendance.objects.all().select_related('user')

        # Use the serializer to convert data to JSON format
        attendance_data = AttendanceSerializer(attendances, many=True)

        return Response(attendance_data.data, status=200)


class UserAttendanceView(APIView):
    permission_classes = [AllowAny]  # Adjust permissions as needed

    def get(self, request, *args, **kwargs):
        # Fetch query parameters
        username = request.query_params.get('username')
        department = request.query_params.get('department')

        if not username or not department:
            return Response({"error": "Please provide both 'username' and 'department'."}, status=400)

        # Filter attendance records based on the username and department
        attendances = Attendance.objects.filter(user__username=username, user__department=department)

        if not attendances.exists():
            return Response({"message": "No attendance records found for the given user and department."}, status=404)

        # Serialize and return the data
        attendance_data = AttendanceSerializer(attendances, many=True)
        return Response(attendance_data.data, status=200)

# Feedback API
class FeedbackView(APIView):
    authentication_classes = []  # Disable authentication
    permission_classes = [AllowAny]  # Allow public access

        # Get All Feedback
    def get(self, request, *args, **kwargs):
        feedbacks = UserFeedback.objects.all()
        serializer = FeedBackSerializer(feedbacks, many=True)
        return Response(serializer.data, status=200)
    
        #Post All Feedback
    def post(self, request, *args, **kwargs):
        username = request.data.get("username")
        feedback = request.data.get("feedback")
        department = request.data.get("department")

        # Check for missing fields
        if not username or not department or not feedback:
            return Response({"error": "Missing required fields."}, status=400)

        user = RegisterUser.objects.filter(username=username).first()
        if not user:
            return Response({"error": "User not found."}, status=404)

        # Create and save feedback
        user_feedback = UserFeedback.objects.create(
            user=user,
            feedback=feedback,
            department=department,
            date=now().date()
        )

        # Serialize the created feedback
        serializer = FeedBackSerializer(user_feedback)
        
        return Response(serializer.data, status=201)

