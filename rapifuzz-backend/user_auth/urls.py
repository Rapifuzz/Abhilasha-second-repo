from django.urls import path
from user_auth.views import (
                                CreateUser,
                                UserRetrieveUpdateView,
                                ResetPassword,
                                PermissionsView,
                                UserListAPIView,
                                UserVerificationView,
                                VerifyUserView,
                                ResendOtp,
                                ProfileUpdateView
                            )

urlpatterns = [
    path('users',CreateUser.as_view()),
    path('users-list',UserListAPIView.as_view()),
    path('users/<int:pk>',UserRetrieveUpdateView.as_view()),
    path('users/reset-password',ResetPassword.as_view()),
    path('permissions',PermissionsView.as_view()),
    path('create',UserVerificationView.as_view()),
    path('verify-user',VerifyUserView.as_view()),
    path('resend-otp',ResendOtp.as_view()),
    path("profile",ProfileUpdateView.as_view())
]
