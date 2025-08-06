
from django.contrib import admin
from django.urls import path, include
from myapp.views import UserLogoutView, UserLoginView, RegisterUserView, AllUsersDataView, SU_AllUsersDataView, UserProfileView, UserChangePassView, ForgotPasswordView,VerifyForgotPassOTPView, BlockUserView, UnblockUserView, ResetPasswordView
from myapp.views import UserCheckInView, UserCheckOutView, AllAttendanceView, UserAttendanceView, FeedbackView
urlpatterns = [
    path('admin/', admin.site.urls),
    # path('', include('myapp.urls')),
    path('Registrations/', RegisterUserView.as_view(), name='registrtions-users'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', UserLogoutView.as_view(), name='log-out'),
    path('allusers/', AllUsersDataView.as_view(), name='all-user'),
    path('AllUsersDataView/', SU_AllUsersDataView.as_view(), name='Su-allusers-data'),
    path('ProfileView/', UserProfileView.as_view(), name='profile-view'),
    path('ChangePassword/', UserChangePassView.as_view(), name='change-pass'),
    path('ForgotPassword/', ForgotPasswordView.as_view(), name='forget-pass'),
    path('VerifyForgotPassOTP/', VerifyForgotPassOTPView.as_view(), name='verify-otp'),
    path('BlockUser/', BlockUserView.as_view(),name='block-users'),
    path('UnblockUser/', UnblockUserView.as_view(),name='unblock-user'),
    path('ResetPassword/', ResetPasswordView.as_view(), name='reset-pass'),

    path('attendance/check-in/', UserCheckInView.as_view(), name='check_in'),
    path('attendance/check-out/', UserCheckOutView.as_view(), name='check_out'),
    path('attendance/report/', AllAttendanceView.as_view(), name='attendance_report'),
    path('attendance/user/', UserAttendanceView.as_view(), name='attendance_user'),
     path('feedback/', FeedbackView.as_view(), name='feedback'),
]




