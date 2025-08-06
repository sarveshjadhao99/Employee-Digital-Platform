from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
import secrets
import string
from django.db import transaction
from myapp.models import RegisterUser


class Command(BaseCommand):
    help = 'Create a superuser and send credentials via email.'

    def generate_random_password(self):
        """Generate a strong random password."""
        password_length = 8
        password_chars = string.ascii_letters + string.digits + "@&-_%$#"
        return ''.join(secrets.choice(password_chars) for _ in range(password_length))

    def email_validation(self):
        """Prompt for email input and validate."""
        while True:
            email = input('Please enter an email address for the SuperUser: ').lower()
            if not RegisterUser.objects.filter(email=email).exists():
                return email
            print(f'Error: The email "{email}" is already in use. Please try another.')

    def handle(self, *args, **kwargs):
        # Check if a superuser already exists
        if RegisterUser.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.WARNING('A superuser already exists. Skipping creation.'))
            return

        self.stdout.write(self.style.WARNING('No superuser found. Creating one.'))

        # Get email address
        email = self.email_validation()

        # Generate random password
        password = self.generate_random_password()

        try:
            # Use a transaction to ensure atomicity
            with transaction.atomic():
                # Create superuser
                user = RegisterUser.objects.create_superuser(
                    username=email,
                    email=email,
                    password=password,
                    is_active=True,
                    is_superuser=True,
                    is_staff=True,
                    role="SU",
                    position="SU"
                )

                # Attempt to send the credentials email
                self.send_credentials_email(user, password)

                self.stdout.write(self.style.SUCCESS(f'Superuser created and credentials sent to {email}.'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))
            self.stdout.write(self.style.ERROR('Superuser creation aborted.'))

    def send_credentials_email(self, user, password):
        """Send superuser credentials via email."""
        try:
            subject = 'Your Superuser Credentials'
            message = f"""Dear {user.username},
        
We are pleased to inform you that your Super Admin account has been successfully created. 
Below are your account details:

◉ Username: {user.username}
◉ Password: {password}
◉ Position: Superuser

Please ensure you keep your login credentials secure and confidential. 
You may change your password after your first login for enhanced security.

If you have any questions or need assistance, feel free to reach out to the department.

Welcome, and we wish you all the best in your new role!

Best regards,  
Digital Employee  
Management Portal
"""
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
            self.stdout.write(self.style.SUCCESS(f'Credentials sent to {user.email}.'))
        except Exception as e:
            # Raise an exception to trigger a rollback
            raise RuntimeError(f"Error sending email: {str(e)}")
